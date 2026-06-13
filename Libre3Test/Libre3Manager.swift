// Libre3Manager.swift
// CBCentralManager + CBPeripheralDelegate
// Handshake-Flow identisch zu Juggluco's Libre3GattCallback.java:
// - State machine läuft über didWriteValueFor (wie Android's onCharacteristicWrite)
// - Daten werden in 20-Byte-Chunks übertragen (2B Offset + 18B Payload)
// - Sensor-Daten werden via sequence-numbered notifications empfangen

import CoreBluetooth
import Combine
import Foundation

// MARK: - BLE Zustand

enum ConnectionState: String {
    case idle          = "Bereit"
    case scanning      = "Suche Sensor…"
    case connecting    = "Verbinde…"
    case discovering   = "Dienste erkunden…"
    case handshake     = "Handshake läuft…"
    case authenticated = "Authentifiziert ✓"
    case readingData   = "Lese Daten…"
    case failed        = "Fehler"
}

// MARK: - Libre3Manager

@MainActor
class Libre3Manager: NSObject, ObservableObject {

    @Published var state: ConnectionState = .idle
    @Published var log: [String] = []
    @Published var kdfResults: [Libre3Crypto.ChallengeResult] = []
    @Published var glucoseReading: GlucoseReading?

    private var central: CBCentralManager!
    private var peripheral: CBPeripheral?
    let crypto = Libre3Crypto()

    // Characteristics
    private var cmdResponse: CBCharacteristic?
    private var challengeData: CBCharacteristic?
    private var certData: CBCharacteristic?
    private var patchStatus: CBCharacteristic?
    private var oneMinute: CBCharacteristic?
    private var historic: CBCharacteristic?
    private var clinical: CBCharacteristic?

    // Juggluco-style commandphase (driven by write callbacks)
    private var commandPhase = 0
    private var notificationsReady = 0
    private var subscriptionStarted = false

    // Write chunking (20-byte packets: 2B offset + 18B payload)
    private var wrtData: [UInt8]?
    private var wrtOffset = 0

    // Incoming data assembly (sequence-numbered chunks)
    private var rdtData = [UInt8](repeating: 0, count: 512)
    private var rdtLength = 0
    private var rdtBytes = 0
    private var rxPayloadLen = 19      // Payload-Größe, gelernt aus Paket 1
    private var receivedSeqs: Set<Int> = []
    private var totalPackets = 0

    // Timing
    private var scanStart: Date?
    private var connectStart: Date?
    private var handshakeStart: Date?

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: nil)
    }

    // MARK: - Public API

    func startScan() {
        log.append("══════════════════════════════════")
        kdfResults.removeAll()
        glucoseReading = nil
        crypto.resetEphemeral()
        crypto.nonceBackVariant = KDFVariant.allCases[0]
        crypto.nonceVariant = NonceVariant.allCases[0]
        startScanInternal()
    }

    private func startScanInternal() {
        commandPhase = 0
        notificationsReady = 0
        subscriptionStarted = false
        peripheral = nil
        scanStart = Date()
        connectStart = nil
        handshakeStart = nil

        guard central.state == .poweredOn else {
            add("⚠️ Bluetooth nicht eingeschaltet")
            state = .idle
            return
        }
        state = .scanning
        add("🔍 \(crypto.nonceBackVariant.rawValue) | \(crypto.nonceVariant.rawValue)")
        central.scanForPeripherals(
            withServices: [CBUUID(string: Libre3Keys.serviceData),
                           CBUUID(string: Libre3Keys.serviceSecurity)],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    func stopScan() {
        central.stopScan()
        if let p = peripheral { central.cancelPeripheralConnection(p) }
        state = .idle
        add("⏹ Getrennt")
    }

    func add(_ msg: String) {
        let ts = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        log.append("[\(ts)] \(msg)")
        print(msg)
    }

    // MARK: - Timing Helper

    private func elapsed(since start: Date?) -> String {
        guard let s = start else { return "?" }
        return String(format: "%.1fs", Date().timeIntervalSince(s))
    }

    // MARK: - Command Sending

    private func sendRawCommand(_ byte: UInt8) {
        guard let char = cmdResponse, let p = peripheral else { return }
        add("→ CMD: 0x\(String(format:"%02X", byte))")
        p.writeValue(Data([byte]), for: char, type: .withResponse)
    }

    // MARK: - Write Chunking (20-byte format: 2B little-endian offset + 18B payload)

    private func writeNextCertChunk() {
        guard let data = wrtData, let char = certData, let p = peripheral else { return }
        let remaining = data.count - wrtOffset
        guard remaining > 0 else { return }
        let chunkLen = min(remaining, 18)
        var packet = [UInt8](repeating: 0, count: 20)
        packet[0] = UInt8(wrtOffset & 0xFF)
        packet[1] = UInt8((wrtOffset >> 8) & 0xFF)
        for i in 0..<chunkLen { packet[2 + i] = data[wrtOffset + i] }
        wrtOffset += chunkLen
        p.writeValue(Data(packet), for: char, type: .withResponse)
    }

    private func writeNextChallengeChunk() {
        guard let data = wrtData, let char = challengeData, let p = peripheral else { return }
        let remaining = data.count - wrtOffset
        guard remaining > 0 else { return }
        let chunkLen = min(remaining, 18)
        var packet = [UInt8](repeating: 0, count: 20)
        packet[0] = UInt8(wrtOffset & 0xFF)
        packet[1] = UInt8((wrtOffset >> 8) & 0xFF)
        for i in 0..<chunkLen { packet[2 + i] = data[wrtOffset + i] }
        wrtOffset += chunkLen
        p.writeValue(Data(packet), for: char, type: .withResponse)
    }

    // MARK: - Incoming Data Assembly (offset-based, tolerant gegenüber Lücken und Duplikaten)

    // Returns bytes remaining (≤0 = complete)
    private func getsecdata(_ value: [UInt8]) -> Int {
        guard value.count >= 2 else { return rdtLength }
        let seq = Int(value[0] & 0xFF)
        let payload = Array(value.dropFirst())

        if receivedSeqs.contains(seq) { return totalPackets > 0 ? totalPackets - receivedSeqs.count : 1 }
        receivedSeqs.insert(seq)

        if rxPayloadLen == 0 {
            rxPayloadLen = payload.count
            totalPackets = Int(ceil(Double(rdtLength) / Double(max(rxPayloadLen, 1))))
        }

        let pos = seq * rxPayloadLen
        let copyLen = min(payload.count, max(0, rdtData.count - pos))
        if pos >= 0 && copyLen > 0 {
            for i in 0..<copyLen { rdtData[pos + i] = payload[i] }
        }

        rdtBytes = receivedSeqs.reduce(0) { acc, s in
            acc + min(rxPayloadLen, max(0, rdtLength - s * rxPayloadLen))
        }

        if totalPackets > 0 && receivedSeqs.count >= totalPackets { return 0 }
        return rdtLength - rdtBytes
    }

    // MARK: - Handshake Start

    private func startHandshake() {
        commandPhase = 1
        state = .handshake
        handshakeStart = Date()
        add("🔐 Handshake — \(crypto.nonceBackVariant.rawValue)")
        sendRawCommand(0x01)
    }

    // MARK: - preparedata (Juggluco equivalent)
    // Called when cmdResponse notification arrives — signals incoming data or state changes

    private func preparedata(_ value: [UInt8]) {
        let sig = Int(value[0] & 0xFF)

        if value.count == 1 {
            if sig == 4 { sendRawCommand(0x09) }
            else { add("⚠️ preparedata sig=0x\(String(format:"%02X",sig)) unbekannt") }
            return
        }

        let len = Int(value[1] & 0xFF)
        rdtLength = len
        rdtData = [UInt8](repeating: 0, count: max(len, 512))
        rdtBytes = 0; receivedSeqs = []; rxPayloadLen = 0; totalPackets = 0

        switch sig {
        case 8:  add("← Challenge bereit (\(len)B)")
        case 10: add("← Sensor-Cert kommt (\(len)B)…")
        case 15: add("← Sensor-Ephemeral kommt (\(len)B)…")
        default: add("⚠️ preparedata sig=\(sig) len=\(len)")
        }
    }

    // MARK: - Received assembled cert/ephemeral data

    private func receivedCertData() {
        let payload = Data(rdtData.prefix(rdtLength))
        switch rdtLength {
        case 140:
            if crypto.processSensorCertificate(payload) {
                add("✅ Sensor-Cert OK → KeyAgreement")
                commandPhase = 4
                sendRawCommand(0x0D)
            } else {
                add("❌ Sensor-Cert ungültig"); state = .failed
            }
        case 65:
            if crypto.processSensorEphemeral(payload) {
                add("✅ Sensor-Ephemeral OK → AuthorizeSymmetric")
                sendRawCommand(0x11)
            } else {
                add("❌ Sensor-Ephemeral ungültig"); state = .failed
            }
        default:
            add("⚠️ Unbekannte Länge: \(rdtLength)B")
        }
    }

    // MARK: - Challenge Data (23B oder 67B)

    private func receivedChallengeData() {
        let payload = Data(rdtData.prefix(rdtLength))
        add("← Challenge (\(rdtLength)B): \(hexShort([UInt8](payload)))")

        switch rdtLength {
        case 23:
            add("📋 23-Byte Challenge — Variante: \(crypto.nonceBackVariant.rawValue)")
            if let result = crypto.processChallenge23(payload) {
                add("🔑 kInit = \(result.kInitHex)")
                add("→ Nonce-Back senden (\(result.nonceBack.count)B)")
                wrtData = [UInt8](result.nonceBack)
                wrtOffset = 0
                writeNextChallengeChunk()
            } else {
                add("❌ Konnte Nonce-Back nicht berechnen")
            }

        case 67:
            add("🔑 67-Byte Challenge — teste \(KDFVariant.allCases.count) KDF-Varianten…")
            let results = crypto.processChallenge67(payload)
            kdfResults = results
            for r in results {
                let kInitHex = hexShort([UInt8](r.kInit))
                if let dec = r.decrypted {
                    let kEncHex = hexShort([UInt8](dec.subdata(in: 32..<48)))
                    let ivHex   = hexShort([UInt8](dec.subdata(in: 48..<56)))
                    add("✅ \(r.variant.rawValue)\n   kInit:\(kInitHex)\n   kEnc:\(kEncHex) ivEnc:\(ivHex)\n   r2:\(r.r2Matches ? "✅":"❌") r1:\(r.r1Matches ? "✅":"❌")")
                    if r.r2Matches && r.r1Matches {
                        crypto.activateSession(with: r)
                        state = .authenticated
                        add("🎉 HANDSHAKE ERFOLGREICH mit \(r.variant.rawValue)!")
                        enableDataNotifications()
                    }
                } else {
                    add("❌ \(r.variant.rawValue): Tag-Mismatch (kInit:\(kInitHex))")
                }
            }
            if !results.contains(where: { $0.r2Matches && $0.r1Matches }) {
                add("⚠️ Keine KDF korrekt. RAW: \(hex([UInt8](payload)))")
            }

        default:
            add("⚠️ Unbekannte Challenge-Länge: \(rdtLength)")
        }
    }

    // MARK: - Data Notifications aktivieren (nach Handshake)

    private func enableDataNotifications() {
        guard let p = peripheral else { return }
        state = .readingData
        [oneMinute, patchStatus, historic, clinical].compactMap { $0 }.forEach {
            p.setNotifyValue(true, for: $0)
        }
    }

    // MARK: - Glucose

    private func receivedOneMinuteReading(_ data: Data) {
        guard let raw = crypto.decryptPacket(kind: 3, data: data) else {
            add("❌ Glucose: Entschlüsselung fehlgeschlagen")
            return
        }
        if let reading = parseOneMinuteReading(data: raw, activationTime: 0) {
            glucoseReading = reading
            add("🩸 Glucose: \(reading.glucoseMgDl) mg/dL \(reading.trendArrow)")
        }
    }

    // MARK: - Helfer

    func hexShort(_ bytes: [UInt8]) -> String {
        let h = bytes.prefix(16).map { String(format: "%02X", $0) }.joined(separator: " ")
        return bytes.count > 16 ? "\(h)…" : h
    }

    func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: " ")
    }
}

// MARK: - CBCentralManagerDelegate

extension Libre3Manager: CBCentralManagerDelegate {
    nonisolated func centralManagerDidUpdateState(_ central: CBCentralManager) {
        Task { @MainActor in
            switch central.state {
            case .poweredOn:  add("📶 Bluetooth eingeschaltet")
            case .poweredOff: add("📴 Bluetooth ausgeschaltet")
            default: add("⚠️ BT Status: \(central.state.rawValue)")
            }
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                         advertisementData: [String: Any], rssi RSSI: NSNumber) {
        Task { @MainActor in
            guard self.peripheral == nil else { return }
            let name = peripheral.name ?? peripheral.identifier.uuidString.prefix(8).description
            add("📡 Sensor gefunden: \(name) (RSSI: \(RSSI), Scan dauerte \(elapsed(since: scanStart)))")
            connectStart = Date()
            central.stopScan()
            self.peripheral = peripheral
            state = .connecting
            central.connect(peripheral, options: nil)
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        Task { @MainActor in
            add("🔗 Verbunden mit: \(peripheral.name ?? "Sensor") (Connect dauerte \(elapsed(since: connectStart)))")
            state = .discovering
            peripheral.delegate = self
            peripheral.discoverServices([
                CBUUID(string: Libre3Keys.serviceData),
                CBUUID(string: Libre3Keys.serviceSecurity)
            ])
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        Task { @MainActor in
            let dur = handshakeStart != nil ? " (Handshake lief \(elapsed(since: handshakeStart)))"
                    : connectStart  != nil ? " (nach Connect \(elapsed(since: connectStart)))" : ""
            add("🔌 Getrennt\(dur)\(error != nil ? ": \(error!.localizedDescription)" : "")")
            // Nächste KDF-Variante für den nächsten Versuch
            if state != .authenticated {
                let kdfs = KDFVariant.allCases
                let nonces = NonceVariant.allCases
                if let kIdx = kdfs.firstIndex(of: crypto.nonceBackVariant) {
                    let nextKIdx = (kIdx + 1) % kdfs.count
                    if nextKIdx == 0 {
                        // Alle KDF-Varianten durch → Nonce-Variante wechseln
                        let nIdx = nonces.firstIndex(of: crypto.nonceVariant) ?? 0
                        crypto.nonceVariant = nonces[(nIdx + 1) % nonces.count]
                    }
                    crypto.nonceBackVariant = kdfs[nextKIdx]
                    add("🔄 \(crypto.nonceBackVariant.rawValue) | \(crypto.nonceVariant.rawValue)")
                }
            }
            commandPhase = 0
            notificationsReady = 0
            subscriptionStarted = false
            self.peripheral = nil

            if state != .authenticated {
                // Auto-Reconnect: nächste Variante nach kurzer Pause
                state = .scanning
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                startScanInternal()
            } else {
                state = .idle
            }
        }
    }
}

// MARK: - CBPeripheralDelegate

extension Libre3Manager: CBPeripheralDelegate {
    nonisolated func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        Task { @MainActor in
            guard error == nil else { add("❌ Services: \(error!.localizedDescription)"); return }
            for service in peripheral.services ?? [] {
                peripheral.discoverCharacteristics(nil, for: service)
            }
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        Task { @MainActor in
            guard error == nil else { return }
            for char in service.characteristics ?? [] {
                switch char.uuid.uuidString.uppercased() {
                case Libre3Keys.charCommandResponse.uppercased():  cmdResponse   = char
                case Libre3Keys.charChallengeData.uppercased():    challengeData = char
                case Libre3Keys.charCertificateData.uppercased():  certData      = char
                case Libre3Keys.charPatchStatus.uppercased():      patchStatus   = char
                case Libre3Keys.charOneMinuteReading.uppercased(): oneMinute     = char
                case Libre3Keys.charHistoricalData.uppercased():   historic      = char
                case Libre3Keys.charClinicalData.uppercased():     clinical      = char
                default: break
                }
            }

            if cmdResponse != nil && challengeData != nil && certData != nil && !subscriptionStarted {
                subscriptionStarted = true
                add("✅ Security-Characteristics gefunden — aktiviere Notifications…")
                [cmdResponse, challengeData, certData].compactMap { $0 }.forEach {
                    peripheral.setNotifyValue(true, for: $0)
                }
            }
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        Task { @MainActor in
            if let err = error {
                add("⚠️ Notification \(characteristic.uuid.uuidString.prefix(8)): \(err.localizedDescription)")
                return
            }
            let securityUUIDs = [Libre3Keys.charCommandResponse, Libre3Keys.charChallengeData, Libre3Keys.charCertificateData]
                .map { $0.uppercased() }
            if securityUUIDs.contains(characteristic.uuid.uuidString.uppercased()) && characteristic.isNotifying {
                notificationsReady += 1
                add("🔔 Notification aktiv (\(notificationsReady)/3): \(characteristic.uuid.uuidString.prefix(8))")
                if notificationsReady == 3 {
                    add("⏱ Notifications bereit nach \(elapsed(since: connectStart))")
                    startHandshake()
                }
            }
        }
    }

    // MARK: - Write Callbacks (treiben den Handshake-Flow)

    nonisolated func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        Task { @MainActor in
            if let err = error {
                add("❌ Write \(characteristic.uuid.uuidString.prefix(8)): \(err.localizedDescription)")
                return
            }

            let uuid = characteristic.uuid.uuidString.uppercased()

            switch uuid {

            // CMD-Response Write-Callback → Handshake State Machine
            case Libre3Keys.charCommandResponse.uppercased():
                switch commandPhase {
                case 1:
                    commandPhase = 2; sendRawCommand(0x02)
                case 2:
                    commandPhase = 3
                    wrtData = crypto.appCertificate; wrtOffset = 0
                    writeNextCertChunk()
                case 3:
                    break
                case 4:
                    commandPhase = 5
                    wrtData = crypto.appEphemeralPubKeyBytes; wrtOffset = 0
                    writeNextCertChunk()
                case 5:
                    break
                default: break
                }

            case Libre3Keys.charCertificateData.uppercased():
                guard let data = wrtData else { return }
                if wrtOffset < data.count {
                    writeNextCertChunk()
                } else {
                    wrtData = nil
                    sendRawCommand(commandPhase == 5 ? 0x0E : 0x03)
                }

            case Libre3Keys.charChallengeData.uppercased():
                guard let data = wrtData else { return }
                if wrtOffset < data.count {
                    writeNextChallengeChunk()
                } else {
                    wrtData = nil
                    add("→ ChallengeLoadDone (0x08)")
                    sendRawCommand(0x08)
                }

            default: break
            }
        }
    }

    // MARK: - Notification Callbacks

    nonisolated func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        // WICHTIG: characteristic.value sofort capturen (synchron), bevor iOS es für das
        // nächste Paket überschreibt. Erst DANN zum MainActor dispatchen.
        guard error == nil, let value = characteristic.value, !value.isEmpty else { return }
        let bytes = [UInt8](value)
        let uuid = characteristic.uuid.uuidString.uppercased()
        Task { @MainActor [bytes, uuid] in

            switch uuid {

            // CMD Response Notification → preparedata (Ereignis-Signal vom Sensor)
            case Libre3Keys.charCommandResponse.uppercased():
                preparedata(bytes)

            // Cert Data Notification → Sensor-Cert oder Sensor-Ephemeral empfangen
            case Libre3Keys.charCertificateData.uppercased():
                if getsecdata(bytes) <= 0 {
                    receivedCertData()
                    rdtBytes = 0; receivedSeqs = []; totalPackets = 0
                }

            // Challenge Data Notification → 23B oder 67B Challenge
            case Libre3Keys.charChallengeData.uppercased():
                if getsecdata(bytes) <= 0 {
                    receivedChallengeData()
                    rdtBytes = 0; receivedSeqs = []; totalPackets = 0
                }

            case Libre3Keys.charOneMinuteReading.uppercased():
                receivedOneMinuteReading(value)

            case Libre3Keys.charPatchStatus.uppercased():
                add("← patchStatus (\(bytes.count)B): \(hex(bytes))")

            default:
                add("← \(uuid.prefix(8)): \(hex(bytes).prefix(48))")
            }
        }
    }
}

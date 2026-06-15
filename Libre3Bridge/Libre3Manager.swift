/*  Libre3Manager.swift
 *  Part of Libre3Bridge – FreeStyle Libre 3 direct BLE connection for iOS
 *
 *  Copyright (C) 2026 Lars & Lars
 *
 *  Based on Juggluco by Jaap Korthals Altes (GPL-3.0)
 *  <https://github.com/maheitsec/juggluco>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 *  ─────────────────────────────────────────────────────────────────────────
 *  Core Bluetooth layer that drives the Libre 3 security handshake.
 *
 *  The handshake state machine is driven by write-acknowledge callbacks
 *  (didWriteValueFor), mirroring Juggluco's Libre3GattCallback.java which is
 *  driven by onCharacteristicWrite.
 *
 *  Data transfer uses 20-byte GATT packets: 2-byte little-endian offset ‖ 18-byte payload.
 *  Incoming notifications are sequence-numbered (1-byte seq ‖ N-byte payload) and
 *  reassembled before being processed.
 *
 *  When the sensor rejects a nonce-back (disconnects without sending the 67-byte challenge),
 *  the manager automatically cycles to the next KDF × nonce variant and reconnects.
 */

import CoreBluetooth
import Combine
import Foundation

// MARK: - Connection State

/// Observable BLE connection state.
enum ConnectionState: String {
    case idle          = "Ready"
    case scanning      = "Scanning…"
    case connecting    = "Connecting…"
    case discovering   = "Discovering services…"
    case handshake     = "Handshake in progress…"
    case authenticated = "Authenticated"
    case readingData   = "Reading data…"
    case failed        = "Error"
}

// MARK: - Libre3Manager

/// Manages the BLE connection and security handshake with a FreeStyle Libre 3 sensor.
///
/// Create one instance (e.g. as a `@StateObject`) and call ``startScan()`` to begin.
/// The manager publishes ``state``, ``log``, ``kdfResults``, and ``glucoseReading``.
@MainActor
class Libre3Manager: NSObject, ObservableObject {

    @Published var state: ConnectionState = .idle
    @Published var log: [String] = []
    @Published var kdfResults: [Libre3Crypto.ChallengeResult] = []
    @Published var glucoseReading: GlucoseReading?

    private var central: CBCentralManager!
    private var peripheral: CBPeripheral?

    /// Crypto engine instance — accessible from the UI to display the active KDF variant.
    let crypto = Libre3Crypto()

    // Discovered characteristics
    private var cmdResponse: CBCharacteristic?
    private var challengeData: CBCharacteristic?
    private var certData: CBCharacteristic?
    private var patchStatus: CBCharacteristic?
    private var oneMinute: CBCharacteristic?
    private var historic: CBCharacteristic?
    private var clinical: CBCharacteristic?

    // Handshake phase counter driven by write-acknowledge callbacks
    private var commandPhase = 0
    private var notificationsReady = 0
    private var subscriptionStarted = false

    // Outgoing data chunking state (20-byte GATT packets)
    private var wrtData: [UInt8]?
    private var wrtOffset = 0

    // Incoming data reassembly state
    private var rdtData = [UInt8](repeating: 0, count: 512)
    private var rdtLength = 0
    private var rdtBytes = 0
    private var rxPayloadLen = 19
    private var receivedSeqs: Set<Int> = []
    private var totalPackets = 0

    // Timing for logging
    private var scanStart: Date?
    private var connectStart: Date?
    private var handshakeStart: Date?

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: nil)
    }

    // MARK: - Public API

    /// Starts a new scan-connect-handshake cycle.
    ///
    /// Resets the crypto session, clears previous results, and begins scanning for
    /// the Libre 3 GATT service UUIDs.  When the sensor disconnects without completing
    /// the handshake, the manager automatically cycles to the next KDF variant and
    /// calls this method internally.
    func startScan() {
        log.append("══════════════════════════════════")
        kdfResults.removeAll()
        glucoseReading = nil
        crypto.resetEphemeral()
        crypto.nonceBackVariant = KDFVariant.allCases[0]
        crypto.nonceVariant = .raw7
        startScanInternal()
    }

    /// Stops scanning and disconnects the current peripheral.
    func stopScan() {
        central.stopScan()
        if let p = peripheral { central.cancelPeripheralConnection(p) }
        state = .idle
        add("Disconnected by user")
    }

    /// Appends a timestamped message to ``log`` and prints it to the console.
    func add(_ msg: String) {
        let ts = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        log.append("[\(ts)] \(msg)")
        print(msg)
    }

    // MARK: - Internal Helpers

    private func startScanInternal() {
        crypto.resetEphemeral()
        commandPhase = 0
        notificationsReady = 0
        subscriptionStarted = false
        peripheral = nil
        scanStart = Date()
        connectStart = nil
        handshakeStart = nil
        guard central.state == .poweredOn else {
            add("Bluetooth not powered on")
            state = .idle
            return
        }
        state = .scanning
        add("Trying: \(crypto.nonceBackVariant.rawValue) | \(crypto.nonceVariant.rawValue)")
        central.scanForPeripherals(
            withServices: [CBUUID(string: Libre3Keys.serviceData),
                           CBUUID(string: Libre3Keys.serviceSecurity)],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    private func elapsed(since start: Date?) -> String {
        guard let s = start else { return "?" }
        return String(format: "%.1fs", Date().timeIntervalSince(s))
    }

    // MARK: - Command Sending

    private func sendRawCommand(_ byte: UInt8) {
        guard let char = cmdResponse, let p = peripheral else { return }
        if byte == 0x08 || byte == 0x11 { add("→ CMD: 0x\(String(format:"%02X", byte))") }
        p.writeValue(Data([byte]), for: char, type: .withResponse)
    }

    // MARK: - Write Chunking

    // Sends the next 18-byte payload chunk to gattCharCertificateData.
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

    // Sends the next 18-byte payload chunk to gattCharChallengeData.
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

    // MARK: - Incoming Data Reassembly

    // Accumulates sequence-numbered notification chunks; returns bytes still missing (0 = complete).
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

    // MARK: - Handshake State Machine

    private func startHandshake() {
        commandPhase = 1
        state = .handshake
        handshakeStart = Date()
        sendRawCommand(0x01)
    }

    // Handles cmdResponse notifications: incoming length/type signals from the sensor.
    private func preparedata(_ value: [UInt8]) {
        let sig = Int(value[0] & 0xFF)
        if value.count == 1 {
            if sig == 4 { sendRawCommand(0x09) }
            else { add("preparedata sig=0x\(String(format:"%02X",sig)) unknown") }
            return
        }
        let len = Int(value[1] & 0xFF)
        rdtLength = len
        rdtData = [UInt8](repeating: 0, count: max(len, 512))
        rdtBytes = 0; receivedSeqs = []; rxPayloadLen = 0; totalPackets = 0
        if sig != 8 && sig != 10 && sig != 15 {
            add("preparedata sig=\(sig) len=\(len)")
        }
    }

    // Called when gattCharCertificateData is fully reassembled.
    private func receivedCertData() {
        let payload = Data(rdtData.prefix(rdtLength))
        switch rdtLength {
        case 140:
            if crypto.processSensorCertificate(payload) {
                commandPhase = 4
                sendRawCommand(0x0D)
            } else {
                add("Sensor cert invalid"); state = .failed
            }
        case 65:
            if crypto.processSensorEphemeral(payload) {
                sendRawCommand(0x11)
            } else {
                add("Sensor ephemeral key invalid"); state = .failed
            }
        default:
            add("Unexpected cert data length: \(rdtLength) bytes")
        }
    }

    // Called when gattCharChallengeData is fully reassembled (23 or 67 bytes).
    private func receivedChallengeData() {
        let payload = Data(rdtData.prefix(rdtLength))
        add("← Challenge (\(rdtLength)B): \(hexShort([UInt8](payload)))")

        switch rdtLength {
        case 23:
            if let result = crypto.processChallenge23(payload) {
                add("kInit: \(result.kInitHex)")
                wrtData = [UInt8](result.nonceBack)
                wrtOffset = 0
                writeNextChallengeChunk()
            } else {
                add("Failed to build nonce-back")
            }

        case 67:
            let total = KDFVariant.allCases.count * NonceVariant.allCases.count
            add("67-byte challenge — testing \(total) combinations…")
            let results = crypto.processChallenge67(payload)
            kdfResults = results
            let hits    = results.filter { $0.r2Matches && $0.r1Matches }
            let tagOKs  = results.filter { $0.tagOK && !($0.r2Matches && $0.r1Matches) }
            let missCnt = results.filter { !$0.tagOK }.count
            add("Tag OK: \(results.filter{$0.tagOK}.count) | r1+r2 match: \(hits.count) | Tag fail: \(missCnt)")
            for r in tagOKs {
                add("Tag-OK (no r1/r2 match): \(r.label)  raw:\(hexShort([UInt8](r.rawDecrypted)))")
            }
            for r in hits {
                let dec = r.decrypted!
                let kEncHex = hexShort([UInt8](dec.subdata(in: 32..<48)))
                let ivHex   = hexShort([UInt8](dec.subdata(in: 48..<56)))
                add("MATCH: \(r.label)\n   kInit:\(hexShort([UInt8](r.kInit)))\n   kEnc:\(kEncHex) ivEnc:\(ivHex)")
                if state != .authenticated {
                    crypto.activateSession(with: r)
                    state = .authenticated
                    add("HANDSHAKE COMPLETE")
                    enableDataNotifications()
                }
            }
            if hits.isEmpty {
                add("No match. Raw 67B: \(hex([UInt8](payload)))")
            }

        default:
            add("Unexpected challenge length: \(rdtLength) bytes")
        }
    }

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
            add("Glucose decrypt failed")
            return
        }
        if let reading = parseOneMinuteReading(data: raw, activationTime: 0) {
            glucoseReading = reading
            add("Glucose: \(reading.glucoseMgDl) mg/dL \(reading.trendArrow)")
        }
    }

    // MARK: - Formatting

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
            case .poweredOn:  add("Bluetooth powered on")
            case .poweredOff: add("Bluetooth powered off")
            default:          add("Bluetooth state: \(central.state.rawValue)")
            }
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                                    advertisementData: [String: Any], rssi RSSI: NSNumber) {
        Task { @MainActor in
            guard self.peripheral == nil else { return }
            let name = peripheral.name ?? peripheral.identifier.uuidString.prefix(8).description
            add("Sensor found: \(name)  RSSI:\(RSSI)  scan:\(elapsed(since: scanStart))")
            connectStart = Date()
            central.stopScan()
            self.peripheral = peripheral
            state = .connecting
            central.connect(peripheral, options: nil)
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        Task { @MainActor in
            state = .discovering
            peripheral.delegate = self
            peripheral.discoverServices([
                CBUUID(string: Libre3Keys.serviceData),
                CBUUID(string: Libre3Keys.serviceSecurity)
            ])
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager,
                                    didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        Task { @MainActor in
            let dur = handshakeStart != nil ? " (handshake ran \(elapsed(since: handshakeStart)))"
                    : connectStart  != nil ? " (after connect \(elapsed(since: connectStart)))" : ""
            add("Disconnected\(dur)\(error != nil ? ": \(error!.localizedDescription)" : "")")

            if state != .authenticated {
                // Cycle to the next KDF variant and auto-reconnect
                let kdfs = KDFVariant.allCases
                let nonces = NonceVariant.allCases
                if let kIdx = kdfs.firstIndex(of: crypto.nonceBackVariant) {
                    let nextKIdx = (kIdx + 1) % kdfs.count
                    if nextKIdx == 0 {
                        let nIdx = nonces.firstIndex(of: crypto.nonceVariant) ?? 0
                        crypto.nonceVariant = nonces[(nIdx + 1) % nonces.count]
                    }
                    crypto.nonceBackVariant = kdfs[nextKIdx]
                    add("Next: \(crypto.nonceBackVariant.rawValue) | \(crypto.nonceVariant.rawValue)")
                }
            }

            commandPhase = 0; notificationsReady = 0; subscriptionStarted = false
            self.peripheral = nil

            if state != .authenticated {
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
            guard error == nil else { add("Service discovery error: \(error!.localizedDescription)"); return }
            for service in peripheral.services ?? [] {
                peripheral.discoverCharacteristics(nil, for: service)
            }
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral,
                                didDiscoverCharacteristicsFor service: CBService, error: Error?) {
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
                [cmdResponse, challengeData, certData].compactMap { $0 }.forEach {
                    peripheral.setNotifyValue(true, for: $0)
                }
            }
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral,
                                didUpdateNotificationStateFor characteristic: CBCharacteristic,
                                error: Error?) {
        Task { @MainActor in
            if let err = error {
                add("Notification error \(characteristic.uuid.uuidString.prefix(8)): \(err.localizedDescription)")
                return
            }
            let secUUIDs = [Libre3Keys.charCommandResponse, Libre3Keys.charChallengeData,
                            Libre3Keys.charCertificateData].map { $0.uppercased() }
            if secUUIDs.contains(characteristic.uuid.uuidString.uppercased()) && characteristic.isNotifying {
                notificationsReady += 1
                if notificationsReady == 3 {
                    add("All notifications ready (\(elapsed(since: connectStart)))")
                    startHandshake()
                }
            }
        }
    }

    // MARK: - Write Callbacks (drive the handshake state machine)

    nonisolated func peripheral(_ peripheral: CBPeripheral,
                                didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        Task { @MainActor in
            if let err = error {
                add("Write error \(characteristic.uuid.uuidString.prefix(8)): \(err.localizedDescription)")
                return
            }
            let uuid = characteristic.uuid.uuidString.uppercased()
            switch uuid {

            case Libre3Keys.charCommandResponse.uppercased():
                switch commandPhase {
                case 1: commandPhase = 2; sendRawCommand(0x02)
                case 2:
                    commandPhase = 3
                    wrtData = crypto.appCertificate; wrtOffset = 0
                    writeNextCertChunk()
                case 3: break
                case 4:
                    commandPhase = 5
                    wrtData = crypto.appEphemeralPubKeyBytes; wrtOffset = 0
                    writeNextCertChunk()
                case 5: break
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
                    sendRawCommand(0x08)
                }

            default: break
            }
        }
    }

    // MARK: - Notification Callbacks

    nonisolated func peripheral(_ peripheral: CBPeripheral,
                                didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        // Capture value synchronously before iOS overwrites the buffer for the next packet.
        guard error == nil, let value = characteristic.value, !value.isEmpty else { return }
        let bytes = [UInt8](value)
        let uuid = characteristic.uuid.uuidString.uppercased()
        Task { @MainActor [bytes, uuid] in
            switch uuid {
            case Libre3Keys.charCommandResponse.uppercased():
                preparedata(bytes)
            case Libre3Keys.charCertificateData.uppercased():
                if getsecdata(bytes) <= 0 {
                    receivedCertData()
                    rdtBytes = 0; receivedSeqs = []; totalPackets = 0
                }
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

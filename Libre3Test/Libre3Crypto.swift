// Libre3Crypto.swift
// ECDH + KDF + AES-CCM für Libre 3
// Testet 4 KDF-Varianten parallel gegen den echten Sensor.

import CryptoKit
import CommonCrypto
import Foundation

// MARK: - KDF Varianten (das ist was wir testen wollen)

enum KDFVariant: String, CaseIterable {
    // Ze=ECDH(appEph,sensorEph), Zs=ECDH(appStat,sensorStat)
    case zeAndZs       = "V1: SHA256(1‖Ze‖Zs)"
    case zeOnly        = "V2: SHA256(1‖Ze)"
    case zeRaw         = "V3: Ze[:16]"
    case zeSHA256      = "V4: SHA256(Ze)[:16]"
    // Ze_c=ECDH(appEph,sensorStat), Zs_c=ECDH(appStat,sensorEph)
    case crossAndZs    = "V5: SHA256(1‖Ze_c‖Zs_c)"
    case crossOnly     = "V6: SHA256(1‖Ze_c)"
    case crossRaw      = "V7: Ze_c[:16]"
    // Ze_se=ECDH(appStat,sensorEph)
    case statEphOnly   = "V8: SHA256(1‖Ze_se)"
}

// Nonce-Konstruktion: 7-Byte Sensor-Nonce → 13-Byte CCM-Nonce
enum NonceVariant: String, CaseIterable {
    case rightPad = "Nonce-R: nonce7 + 000000"  // aktuell
    case leftPad  = "Nonce-L: 000000 + nonce7"  // Alternative
}

// MARK: - Crypto State

class Libre3Crypto {

    private(set) var appEphemeralPrivKey = P256.KeyAgreement.PrivateKey()
    private var appStaticPrivKey: P256.KeyAgreement.PrivateKey = {
        let raw = Data(Libre3Keys.appStaticPrivKeyLevel1)
        return (try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw))
            ?? P256.KeyAgreement.PrivateKey()
    }()
    private var sensorStaticPubKey: P256.KeyAgreement.PublicKey?
    private var sensorEphemeralPubKey: P256.KeyAgreement.PublicKey?

    // Aktive Session-Keys nach erfolgreichem Handshake
    private(set) var kEnc: Data?
    private(set) var ivEnc: Data?
    private(set) var kAuth: Data?

    // Laufender CCM-Sequence-Counter
    private var outCryptoSequence: UInt16 = 1

    // r1 aus dem 23-Byte-Challenge (zum Verifizieren der kInit-Richtigkeit)
    private(set) var r1: Data?
    private(set) var r2: Data?

    var securityVersion: Int = 1  // 1 für neuere Libre 3 Sensoren (Level 0 hat nicht geantwortet)

    // Neu generiert pro Session
    func resetEphemeral() {
        appEphemeralPrivKey = P256.KeyAgreement.PrivateKey()
        outCryptoSequence = 1
        kEnc = nil; ivEnc = nil; kAuth = nil
        r1 = nil; r2 = nil
    }

    // App Ephemeral Public Key (65 Bytes, x9.63 uncompressed) → an Sensor senden
    var appEphemeralPubKeyBytes: [UInt8] {
        [UInt8](appEphemeralPrivKey.publicKey.x963Representation)
    }

    // App-Zertifikat (140 Bytes) → an Sensor senden
    var appCertificate: [UInt8] {
        securityVersion == 0 ? Libre3Keys.appCertLevel0 : Libre3Keys.appCertLevel1
    }

    // MARK: - Sensor-Cert verarbeiten (140 Bytes vom Sensor)

    func processSensorCertificate(_ data: Data) -> Bool {
        guard data.count == 140 else { return false }
        let pubKeyBytes = Data(data[11...75])  // Sensor Static Pub Key bei Offset 11
        do {
            sensorStaticPubKey = try P256.KeyAgreement.PublicKey(x963Representation: pubKeyBytes)
            return true
        } catch {
            return false
        }
    }

    // MARK: - Sensor Ephemeral Key verarbeiten (65 Bytes vom Sensor)

    func processSensorEphemeral(_ data: Data) -> Bool {
        guard data.count == 65 else { return false }
        do {
            sensorEphemeralPubKey = try P256.KeyAgreement.PublicKey(x963Representation: data)
            return true
        } catch {
            return false
        }
    }

    // MARK: - 23-Byte Challenge (r1 + nonce1)

    // Welche KDF-Variante beim Nonce-Back versucht wird (zyklisch über Sessions)
    var nonceBackVariant: KDFVariant = .zeAndZs
    var nonceVariant: NonceVariant = .rightPad

    func processChallenge23(_ data: Data) -> (nonceBack: Data, kInitHex: String)? {
        guard data.count == 23 else { return nil }
        r1 = data.subdata(in: 0..<16)
        let nonce1 = data.subdata(in: 16..<23)
        var r2bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &r2bytes)
        r2 = Data(r2bytes)
        return buildNonceBack(nonce1: nonce1)
    }

    private func buildNonceBack(nonce1: Data) -> (nonceBack: Data, kInitHex: String)? {
        guard let r2, let r1 else { return nil }
        // Juggluco Libre3GattCallback.java mknonceback(): r1 || r2 || pin (36 Bytes)
        // pin = 0x00000000 für BLE-only (kein NFC-Scan)
        let pin = Data(repeating: 0, count: 4)
        let plaintext = r1 + r2 + pin  // 36 Bytes
        let nonce13 = buildChallengeNonce(nonce7: [UInt8](nonce1))
        guard let kInit = deriveKInit(variant: nonceBackVariant) else { return nil }
        let kInitHex = kInit.map { String(format: "%02X", $0) }.joined(separator: " ")
        guard let encrypted = try? aesCCMEncrypt(key: kInit, nonce: nonce13, plaintext: [UInt8](plaintext)) else { return nil }
        return (encrypted, kInitHex)
    }

    // MARK: - 67-Byte Challenge — der kritische Test

    struct ChallengeResult {
        let variant: KDFVariant
        let kInit: Data
        let decrypted: Data?
        let r2Matches: Bool
        let r1Matches: Bool
        var kEnc: Data? { decrypted.map { $0.subdata(in: 32..<48) } }
        var ivEncResult: Data? { decrypted.map { $0.subdata(in: 48..<56) } }
    }

    func processChallenge67(_ data: Data) -> [ChallengeResult] {
        guard data.count == 67 else { return [] }
        let ciphertext = data.subdata(in: 0..<60)  // erste 60 Bytes
        let nonce7 = [UInt8](data.subdata(in: 60..<67))  // letzte 7 Bytes = Nonce
        let nonce13 = buildChallengeNonce(nonce7: nonce7)

        return KDFVariant.allCases.compactMap { variant -> ChallengeResult? in
            guard let kInit = deriveKInit(variant: variant) else { return nil }
            let decrypted = try? aesCCMDecrypt(key: [UInt8](kInit), nonce: nonce13, ciphertext: [UInt8](ciphertext))
            var r2Matches = false
            var r1Matches = false
            if let dec = decrypted, dec.count >= 32 {
                let decData = Data(dec)
                r2Matches = r2.map { decData.subdata(in: 0..<16) == $0 } ?? false
                r1Matches = r1.map { decData.subdata(in: 16..<32) == $0 } ?? false
            }
            return ChallengeResult(
                variant: variant,
                kInit: kInit,
                decrypted: decrypted.map { Data($0) },
                r2Matches: r2Matches,
                r1Matches: r1Matches
            )
        }
    }

    // MARK: - Session Key aktivieren (nach erfolgreichem 67-Byte-Challenge)

    func activateSession(with result: ChallengeResult) {
        guard let dec = result.decrypted, dec.count >= 56 else { return }
        kEnc = dec.subdata(in: 32..<48)
        ivEnc = dec.subdata(in: 48..<56)
        outCryptoSequence = 1
    }

    // MARK: - Datenpakete entschlüsseln (nach aktivierter Session)

    func decryptPacket(kind: Int, data: Data) -> Data? {
        guard let kEnc, let ivEnc else { return nil }
        guard data.count > 6 else { return nil }
        let cipherLen = data.count - 2
        let seqBytes = [UInt8](data.suffix(2))
        let seq = UInt16(seqBytes[0]) | (UInt16(seqBytes[1]) << 8)
        let nonce = buildDataNonce(sequence: seq, kind: kind, ivEnc: [UInt8](ivEnc))
        guard let bytes = try? aesCCMDecrypt(key: [UInt8](kEnc), nonce: nonce, ciphertext: [UInt8](data.prefix(cipherLen))) else { return nil }
        return Data(bytes)
    }

    // MARK: - KDF Implementierungen

    private func deriveKInit(variant: KDFVariant) -> Data? {
        guard let sensorEphKey = sensorEphemeralPubKey,
              let sensorStatKey = sensorStaticPubKey else { return nil }

        // Ze = ECDH(appEphemeral, sensorEphemeral)
        guard let Ze: Data = {
            guard let s = try? appEphemeralPrivKey.sharedSecretFromKeyAgreement(with: sensorEphKey)
            else { return nil }
            return s.withUnsafeBytes { Data($0) }
        }() else { return nil }

        // Ze_c = ECDH(appEphemeral, sensorStatic) — cross
        guard let Ze_c: Data = {
            guard let s = try? appEphemeralPrivKey.sharedSecretFromKeyAgreement(with: sensorStatKey)
            else { return nil }
            return s.withUnsafeBytes { Data($0) }
        }() else { return nil }

        // Zs = ECDH(appStatic, sensorStatic)
        guard let Zs: Data = {
            guard let s = try? appStaticPrivKey.sharedSecretFromKeyAgreement(with: sensorStatKey)
            else { return nil }
            return s.withUnsafeBytes { Data($0) }
        }() else { return nil }

        // Zs_c = ECDH(appStatic, sensorEphemeral) — cross
        guard let Zs_c: Data = {
            guard let s = try? appStaticPrivKey.sharedSecretFromKeyAgreement(with: sensorEphKey)
            else { return nil }
            return s.withUnsafeBytes { Data($0) }
        }() else { return nil }

        switch variant {
        case .zeAndZs:       return sha256kdf(Ze: Ze, Zs: Zs)
        case .zeOnly:        return sha256kdf(Ze: Ze, Zs: nil)
        case .zeRaw:         return Ze.prefix(16).count == 16 ? Data(Ze.prefix(16)) : nil
        case .zeSHA256:      return Data(SHA256.hash(data: Ze).prefix(16))
        case .crossAndZs:    return sha256kdf(Ze: Ze_c, Zs: Zs_c)
        case .crossOnly:     return sha256kdf(Ze: Ze_c, Zs: nil)
        case .crossRaw:      return Ze_c.prefix(16).count == 16 ? Data(Ze_c.prefix(16)) : nil
        case .statEphOnly:   return sha256kdf(Ze: Zs_c, Zs: nil)
        }
    }

    private func sha256kdf(Ze: Data, Zs: Data?) -> Data {
        var counter = UInt32(1).bigEndian
        var input = Data(bytes: &counter, count: 4) + Ze
        if let Zs { input += Zs }
        return Data(SHA256.hash(data: input).prefix(16))
    }

    // MARK: - Nonce Konstruktion

    // 7-Byte-Challenge-Nonce → 13-Byte-AES-CCM-Nonce
    func buildChallengeNonce(nonce7: [UInt8], variant: NonceVariant? = nil) -> [UInt8] {
        switch variant ?? nonceVariant {
        case .rightPad: return nonce7 + [UInt8](repeating: 0, count: 6)
        case .leftPad:  return [UInt8](repeating: 0, count: 6) + nonce7
        }
    }

    // Datenpaket-Nonce (Juggluco bcrypt.cpp kompatibel)
    private func buildDataNonce(sequence: UInt16, kind: Int, ivEnc: [UInt8]) -> [UInt8] {
        var nonce = [UInt8](repeating: 0, count: 13)
        nonce[0] = UInt8(sequence & 0xFF)
        nonce[1] = UInt8((sequence >> 8) & 0xFF)
        nonce[2] = Libre3Keys.packetDescriptors[kind][0]
        nonce[3] = Libre3Keys.packetDescriptors[kind][1]
        nonce[4] = Libre3Keys.packetDescriptors[kind][2]
        nonce[5...12] = ivEnc[0...7]
        return nonce
    }

    // MARK: - AES-CCM (CommonCrypto basiert, 4-Byte-Tag)

    private let tagLen = 4

    func aesCCMEncrypt(key: Data, nonce: [UInt8], plaintext: [UInt8]) throws -> Data {
        try aesCCMEncrypt(key: [UInt8](key), nonce: nonce, plaintext: plaintext)
    }

    func aesCCMEncrypt(key: [UInt8], nonce: [UInt8], plaintext: [UInt8]) throws -> Data {
        guard key.count == 16, nonce.count == 13 else { throw CryptoError.invalidInput }
        // CCM: data uses S_1,S_2,... (counter increments before first block, like tinycrypt)
        // tag uses S_0[0..t-1]; keystream = [S_0(16B) | S_1(16B) | ...]
        let tag = try cbcMac(key: key, nonce: nonce, plaintext: plaintext, tagLen: tagLen)
        let keystream = try ctrKeystream(key: key, nonce: nonce, length: 16 + plaintext.count)
        var result = [UInt8](repeating: 0, count: plaintext.count + tagLen)
        for i in 0..<plaintext.count {
            result[i] = plaintext[i] ^ keystream[16 + i]  // S_1[0], S_1[1], ...
        }
        for i in 0..<tagLen {
            result[plaintext.count + i] = tag[i] ^ keystream[i]  // S_0[0..t-1]
        }
        return Data(result)
    }

    func aesCCMDecrypt(key: [UInt8], nonce: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        guard key.count == 16, nonce.count == 13, ciphertext.count >= tagLen else {
            throw CryptoError.invalidInput
        }
        let plainLen = ciphertext.count - tagLen
        let keystream = try ctrKeystream(key: key, nonce: nonce, length: 16 + plainLen)
        var plain = [UInt8](repeating: 0, count: plainLen)
        for i in 0..<plainLen {
            plain[i] = ciphertext[i] ^ keystream[16 + i]  // S_1[0], S_1[1], ...
        }
        // Tag verifizieren
        let expectedTag = try cbcMac(key: key, nonce: nonce, plaintext: plain, tagLen: tagLen)
        var receivedTag = [UInt8](repeating: 0, count: tagLen)
        for i in 0..<tagLen {
            receivedTag[i] = ciphertext[plainLen + i] ^ keystream[i]  // S_0[0..t-1]
        }
        guard receivedTag == Array(expectedTag.prefix(tagLen)) else {
            throw CryptoError.tagMismatch
        }
        return plain
    }

    // CBC-MAC (für CCM-Tag)
    private func cbcMac(key: [UInt8], nonce: [UInt8], plaintext: [UInt8], tagLen: Int) throws -> [UInt8] {
        let q = 15 - nonce.count  // 2 für nonce.count=13
        var b0 = [UInt8](repeating: 0, count: 16)
        b0[0] = UInt8((tagLen - 2) / 2) << 3 | UInt8(q - 1)  // flags
        b0[1...13] = nonce[0...12]
        // Länge kodieren (q=2 Bytes)
        let msgLen = plaintext.count
        b0[14] = UInt8((msgLen >> 8) & 0xFF)
        b0[15] = UInt8(msgLen & 0xFF)

        var mac = [UInt8](repeating: 0, count: 16)
        mac = try aesBlock(key: key, input: xor(mac, b0))

        var padded = plaintext
        let rem = plaintext.count % 16
        if rem != 0 { padded += [UInt8](repeating: 0, count: 16 - rem) }

        for blockStart in stride(from: 0, to: padded.count, by: 16) {
            let block = Array(padded[blockStart..<blockStart + 16])
            mac = try aesBlock(key: key, input: xor(mac, block))
        }
        return mac
    }

    // AES-CTR Keystream (für CCM-Verschlüsselung)
    private func ctrKeystream(key: [UInt8], nonce: [UInt8], length: Int) throws -> [UInt8] {
        let q = 15 - nonce.count
        var result = [UInt8]()
        var counter: UInt32 = 0
        while result.count < length {
            var a = [UInt8](repeating: 0, count: 16)
            a[0] = UInt8(q - 1)  // flags
            a[1...13] = nonce[0...12]
            // Counter (big-endian, q=2 Bytes)
            a[14] = UInt8((counter >> 8) & 0xFF)
            a[15] = UInt8(counter & 0xFF)
            result += try aesBlock(key: key, input: a)
            counter += 1
        }
        return Array(result.prefix(length))
    }

    private func xor(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        zip(a, b).map { $0 ^ $1 }
    }

    // AES-128-ECB Block (über CommonCrypto)
    private func aesBlock(key: [UInt8], input: [UInt8]) throws -> [UInt8] {
        guard key.count == 16, input.count == 16 else { throw CryptoError.invalidInput }
        var output = [UInt8](repeating: 0, count: 16)
        var outLen = 0
        let status = CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            key, kCCKeySizeAES128,
            nil,
            input, 16,
            &output, 16,
            &outLen
        )
        guard status == kCCSuccess else { throw CryptoError.aesFailed }
        return output
    }

    enum CryptoError: Error {
        case invalidInput, tagMismatch, aesFailed
    }
}

// MARK: - Glucose Parsing (aus parseOneMinuteReading in DiaBLE)

struct GlucoseReading {
    let lifeCount: UInt16
    let glucoseMgDl: Int
    let rateOfChange: Double
    let trendArrow: String
}

func parseOneMinuteReading(data: Data, activationTime: UInt32) -> GlucoseReading? {
    guard data.count >= 14 else { return nil }
    let lifeCount = UInt16(data[0]) | (UInt16(data[1]) << 8)
    let rawReading = UInt16(data[2]) | (UInt16(data[3]) << 8)
    let glucose = Int(rawReading & 0x1fff)
    let roc = Double(Int16(bitPattern: UInt16(data[4]) | (UInt16(data[5]) << 8))) / 100.0
    let bitfields = data[14]
    let trend = bitfields & 0x07
    let arrows = ["→", "↗", "↑", "↑↑", "↓↓", "↓", "↘", "→"]
    let arrow = Int(trend) < arrows.count ? arrows[Int(trend)] : "?"
    return GlucoseReading(lifeCount: lifeCount, glucoseMgDl: glucose, rateOfChange: roc, trendArrow: arrow)
}

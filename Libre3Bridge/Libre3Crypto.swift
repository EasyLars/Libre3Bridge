/*  Libre3Crypto.swift
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
 *  Implements the Libre 3 BLE security handshake:
 *
 *  Handshake sequence (mirrors Juggluco Libre3GattCallback.java):
 *    1. App → Sensor : app static certificate   (gattCharCertificateData)
 *    2. App → Sensor : app ephemeral public key (gattCharCertificateData)
 *    3. Sensor → App : sensor static cert (140 B) then sensor ephemeral key (65 B)
 *    4. Sensor → App : 23-byte challenge  = r1(16) ‖ nonce1(7)
 *    5. App → Sensor : 40-byte nonce-back = AES-CCM(kInit, nonce1, r1‖r2‖pin)
 *    6. Sensor → App : 67-byte challenge  = nonce(7) ‖ AES-CCM(kInit, nonce, r2‖r1‖kEnc‖ivEnc)
 *    7. App activates session using kEnc (16 B) and ivEnc (8 B).
 *
 *  P-256 ECDH terms used:
 *    Ze   = ECDH(appEphPriv,  sensorEphPub)  — symmetric, both sides computable
 *    Ze_c = ECDH(appEphPriv,  sensorStatPub) — symmetric, both sides computable
 *    Zs   = ECDH(appStatPriv, sensorStatPub) — symmetric IF appStatPriv is known (see Libre3Keys)
 *    Zs_c = ECDH(appStatPriv, sensorEphPub)  — symmetric IF appStatPriv is known
 *
 *  AES-CCM parameters: 128-bit key, 4-byte tag, 7-byte or 13-byte nonce.
 *
 *  Current status: the exact KDF formula used by the sensor to derive kInit is unknown.
 *  This file tests 14 KDF variants × 5 nonce constructions = 70 combinations per session.
 *  All 70 failed in live sensor tests (Build 26).  See README for details and hypotheses.
 */

import CryptoKit
import CommonCrypto
import Foundation

// MARK: - KDF Variants

/// Enumeration of candidate kInit derivation formulas.
///
/// All variants use only Ze and Ze_c because both are symmetric (computable independently
/// by app and sensor).  Zs and Zs_c depend on the app static private key whose raw scalar
/// is not yet extractable from the Juggluco key blob.
enum KDFVariant: String, CaseIterable {
    case zeRaw          = "V1:  Ze[:16]"
    case zeHash         = "V2:  SHA256(Ze)"
    case zeNist         = "V3:  SHA256(1‖Ze)"
    case zeX963         = "V4:  SHA256(Ze‖1)"
    case zecRaw         = "V5:  Ze_c[:16]"
    case zecHash        = "V6:  SHA256(Ze_c)"
    case zecNist        = "V7:  SHA256(1‖Ze_c)"
    case zecX963        = "V8:  SHA256(Ze_c‖1)"
    case zeZecNist      = "V9:  SHA256(1‖Ze‖Ze_c)"
    case zecZeNist      = "V10: SHA256(1‖Ze_c‖Ze)"
    case zeZecCat       = "V11: SHA256(Ze‖Ze_c)"
    case zecZeCat       = "V12: SHA256(Ze_c‖Ze)"
    case hmacZeKeyZec   = "V13: HMAC256(key=Ze,Ze_c)"
    case hmacZecKeyZe   = "V14: HMAC256(key=Ze_c,Ze)"
}

/// How the 7-byte sensor nonce is padded to the CCM nonce length.
enum NonceVariant: String, CaseIterable {
    case rightPad  = "Nonce-R: nonce7+zeros6"
    case leftPad   = "Nonce-L: zeros6+nonce7"
    case dataNonce = "Nonce-D: seq+desc7+zeros8"
    case seqOnly   = "Nonce-S: seq+zeros11"
    /// 7-byte nonce used directly with CCM q=8 (8-byte counter field). Most likely variant.
    case raw7      = "Nonce-7: 7B raw (q=8 CCM)"
}

// MARK: - Crypto State

/// Manages all cryptographic state for one Libre 3 BLE session.
///
/// Create one instance per app lifetime; call ``resetEphemeral()`` before each
/// connection attempt to generate a fresh ephemeral key pair.
class Libre3Crypto {

    // Fresh ephemeral key pair generated per session
    private(set) var appEphemeralPrivKey = P256.KeyAgreement.PrivateKey()

    // Candidate app static key — does NOT match cert pubkey (blob format unknown)
    private var appStaticPrivKey: P256.KeyAgreement.PrivateKey = {
        let raw = Data(Libre3Keys.appStaticPrivKeyLevel1)
        return (try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw))
            ?? P256.KeyAgreement.PrivateKey()
    }()

    private var sensorStaticPubKey: P256.KeyAgreement.PublicKey?
    private var sensorEphemeralPubKey: P256.KeyAgreement.PublicKey?

    /// Session encryption key activated after a successful 67-byte challenge.
    private(set) var kEnc: Data?
    /// Session IV activated after a successful 67-byte challenge.
    private(set) var ivEnc: Data?
    /// Authorization key returned by the sensor (step 9 equivalent).
    private(set) var kAuth: Data?

    private var outCryptoSequence: UInt16 = 1

    /// r1 from the 23-byte challenge (used to verify 67-byte challenge decryption).
    private(set) var r1: Data?
    /// r2 generated by the app and echoed back by the sensor inside the 67-byte challenge.
    private(set) var r2: Data?

    /// Security level: 0 for older sensors, 1 for current generation.
    var securityVersion: Int = 1

    /// KDF variant to use for the next nonce-back (cycles across sessions).
    var nonceBackVariant: KDFVariant = .zeRaw
    /// Nonce padding variant to use for the next nonce-back.
    var nonceVariant: NonceVariant = .raw7

    // MARK: - Session Lifecycle

    /// Generates a new ephemeral key pair and clears all session state.
    ///
    /// Must be called before each connection attempt.
    func resetEphemeral() {
        appEphemeralPrivKey = P256.KeyAgreement.PrivateKey()
        outCryptoSequence = 1
        kEnc = nil; ivEnc = nil; kAuth = nil
        r1 = nil; r2 = nil
    }

    /// Uncompressed P-256 ephemeral public key (65 bytes, x9.63 format) to send to the sensor.
    var appEphemeralPubKeyBytes: [UInt8] {
        [UInt8](appEphemeralPrivKey.publicKey.x963Representation)
    }

    /// App certificate to send to the sensor during handshake phase 2.
    var appCertificate: [UInt8] {
        securityVersion == 0 ? Libre3Keys.appCertLevel0 : Libre3Keys.appCertLevel1
    }

    // MARK: - Sensor Certificate / Ephemeral Key

    /// Parses the 140-byte sensor static certificate and extracts the sensor static public key.
    ///
    /// - Parameter data: Raw bytes received on `gattCharCertificateData` (must be 140 bytes).
    /// - Returns: `true` if the key was extracted successfully.
    func processSensorCertificate(_ data: Data) -> Bool {
        guard data.count == 140 else { return false }
        let pubKeyBytes = Data(data[11...75])  // sensor static public key at offset 11
        do {
            sensorStaticPubKey = try P256.KeyAgreement.PublicKey(x963Representation: pubKeyBytes)
            return true
        } catch {
            return false
        }
    }

    /// Stores the 65-byte sensor ephemeral public key received after the static certificate.
    ///
    /// - Parameter data: Uncompressed P-256 point (65 bytes, 0x04 prefix).
    /// - Returns: `true` if the key was parsed successfully.
    func processSensorEphemeral(_ data: Data) -> Bool {
        guard data.count == 65 else { return false }
        do {
            sensorEphemeralPubKey = try P256.KeyAgreement.PublicKey(x963Representation: data)
            return true
        } catch {
            return false
        }
    }

    // MARK: - 23-Byte Challenge

    /// Processes the 23-byte sensor challenge and builds the 40-byte nonce-back reply.
    ///
    /// Challenge layout: `r1(16) ‖ nonce1(7)`
    /// Nonce-back layout: `AES-CCM(kInit, nonce1, r1‖r2‖pin)` → 36 bytes ciphertext + 4 bytes tag
    ///
    /// - Parameter data: Raw challenge bytes (must be 23 bytes).
    /// - Returns: Tuple of the encrypted nonce-back payload and the kInit hex string for logging,
    ///   or `nil` if ECDH or encryption failed.
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
        // Plaintext: r1(16) ‖ r2(16) ‖ pin(4=0x00000000 for BLE-only, no NFC pairing)
        let plaintext = r1 + r2 + Data(repeating: 0, count: 4)
        let nonce = buildChallengeNonce(nonce7: [UInt8](nonce1))
        guard let kInit = deriveKInit(variant: nonceBackVariant) else { return nil }
        let kInitHex = kInit.map { String(format: "%02X", $0) }.joined(separator: " ")
        guard let encrypted = try? aesCCMEncrypt(key: kInit, nonce: nonce, plaintext: [UInt8](plaintext)) else { return nil }
        return (encrypted, kInitHex)
    }

    // MARK: - 67-Byte Challenge

    /// Result of one KDF + nonce variant combination tested against the 67-byte challenge.
    struct ChallengeResult {
        let variant: KDFVariant
        let nonceVariant: NonceVariant
        let kInit: Data
        /// `true` if the CCM authentication tag verified correctly.
        let tagOK: Bool
        /// Decrypted plaintext — non-nil only when `tagOK` is true.
        let decrypted: Data?
        /// Raw CTR-mode output regardless of tag (for diagnostic logging when all tags fail).
        let rawDecrypted: Data
        let r2Matches: Bool
        let r1Matches: Bool
        var kEnc: Data?       { decrypted.map { $0.subdata(in: 32..<48) } }
        var ivEncResult: Data? { decrypted.map { $0.subdata(in: 48..<56) } }
        var label: String     { "\(variant.rawValue) \(nonceVariant.rawValue)" }
    }

    /// Tests all 14 KDF × 5 nonce = 70 combinations against the 67-byte sensor challenge.
    ///
    /// The sensor challenge layout: `nonce(7) ‖ AES-CCM-ciphertext(60)`.
    /// Expected decrypted plaintext: `r2(16) ‖ r1(16) ‖ kEnc(16) ‖ ivEnc(8)` = 56 bytes.
    ///
    /// A result with `tagOK && r2Matches && r1Matches` means the correct kInit was found.
    ///
    /// - Parameter data: 67-byte challenge received on `gattCharChallengeData`.
    /// - Returns: Array of 70 results, one per combination.
    func processChallenge67(_ data: Data) -> [ChallengeResult] {
        guard data.count == 67 else { return [] }
        let ciphertext = [UInt8](data.subdata(in: 0..<60))
        let nonce7 = [UInt8](data.subdata(in: 60..<67))

        var results: [ChallengeResult] = []
        for nv in NonceVariant.allCases {
            let nonce13 = buildChallengeNonce(nonce7: nonce7, variant: nv)
            for kv in KDFVariant.allCases {
                guard let kInit = deriveKInit(variant: kv) else { continue }
                let raw = aesCCMDecryptRaw(key: [UInt8](kInit), nonce: nonce13, ciphertext: ciphertext)
                let decrypted = try? aesCCMDecrypt(key: [UInt8](kInit), nonce: nonce13, ciphertext: ciphertext)
                let tagOK = decrypted != nil
                var r2Matches = false, r1Matches = false
                if let dec = decrypted, dec.count >= 32 {
                    let decData = Data(dec)
                    r2Matches = r2.map { decData.subdata(in: 0..<16) == $0 } ?? false
                    r1Matches = r1.map { decData.subdata(in: 16..<32) == $0 } ?? false
                }
                results.append(ChallengeResult(
                    variant: kv,
                    nonceVariant: nv,
                    kInit: kInit,
                    tagOK: tagOK,
                    decrypted: decrypted.map { Data($0) },
                    rawDecrypted: Data(raw ?? [UInt8](repeating: 0, count: 56)),
                    r2Matches: r2Matches,
                    r1Matches: r1Matches
                ))
            }
        }
        return results
    }

    // MARK: - Session Activation

    /// Activates the session encryption keys from a successful 67-byte challenge result.
    ///
    /// - Parameter result: A ``ChallengeResult`` with `tagOK == true` and matching r1/r2.
    func activateSession(with result: ChallengeResult) {
        guard let dec = result.decrypted, dec.count >= 56 else { return }
        kEnc = dec.subdata(in: 32..<48)
        ivEnc = dec.subdata(in: 48..<56)
        outCryptoSequence = 1
    }

    // MARK: - Data Decryption

    /// Decrypts an incoming encrypted data notification.
    ///
    /// Uses the session keys activated by ``activateSession(with:)``.
    /// Nonce = seq_LE16(2) ‖ packetDescriptor(3) ‖ ivEnc(8) as per Juggluco bcrypt.cpp.
    ///
    /// - Parameters:
    ///   - kind: Packet type index into ``Libre3Keys/packetDescriptors`` (e.g. 3 for glucose).
    ///   - data: Raw notification bytes; the last 2 bytes are the sequence number (LE).
    /// - Returns: Decrypted payload, or `nil` if keys are not set or decryption fails.
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

    // MARK: - ECDH Diagnostics

    /// Returns a multi-line string with all four ECDH shared secrets for offline analysis.
    ///
    /// Ze and Ze_c are symmetric; Zs and Zs_c use the candidate static key
    /// (which is likely wrong — see ``Libre3Keys/appStaticPrivKeyLevel1``).
    func ecdhDiagnosticsString() -> String {
        guard let sensorEph = sensorEphemeralPubKey,
              let sensorStat = sensorStaticPubKey else { return "Keys not set" }
        let hex: ([UInt8]) -> String = { $0.map { String(format: "%02X", $0) }.joined() }
        var lines: [String] = []
        lines.append("AppEph:  \(hex([UInt8](appEphemeralPrivKey.publicKey.x963Representation)))")
        if let ze  = ecdhRaw(appEphemeralPrivKey, sensorEph)  { lines.append("Ze:      \(hex([UInt8](ze)))") }
        if let zs  = ecdhRaw(appStaticPrivKey,    sensorStat) { lines.append("Zs:      \(hex([UInt8](zs))) (CANDIDATE — likely wrong)") }
        if let zec = ecdhRaw(appEphemeralPrivKey, sensorStat) { lines.append("Ze_c:    \(hex([UInt8](zec)))") }
        if let zsc = ecdhRaw(appStaticPrivKey,    sensorEph)  { lines.append("Zs_c:    \(hex([UInt8](zsc))) (CANDIDATE — likely wrong)") }
        return lines.joined(separator: "\n")
    }

    private func ecdhRaw(_ priv: P256.KeyAgreement.PrivateKey, _ pub: P256.KeyAgreement.PublicKey) -> Data? {
        guard let s = try? priv.sharedSecretFromKeyAgreement(with: pub) else { return nil }
        return s.withUnsafeBytes { Data($0) }
    }

    // MARK: - KDF Implementations

    private func deriveKInit(variant: KDFVariant) -> Data? {
        guard let sensorEphKey = sensorEphemeralPubKey,
              let sensorStatKey = sensorStaticPubKey else { return nil }

        guard let Ze: Data = ecdhRaw(appEphemeralPrivKey, sensorEphKey) else { return nil }
        guard let Ze_c: Data = ecdhRaw(appEphemeralPrivKey, sensorStatKey) else { return nil }

        switch variant {
        case .zeRaw:        return Ze.count >= 16 ? Data(Ze.prefix(16)) : nil
        case .zeHash:       return Data(SHA256.hash(data: Ze).prefix(16))
        case .zeNist:       return sha256kdf(pre: Ze, Zs: nil)
        case .zeX963:       return sha256x963(Z: Ze, extra: nil)
        case .zecRaw:       return Ze_c.count >= 16 ? Data(Ze_c.prefix(16)) : nil
        case .zecHash:      return Data(SHA256.hash(data: Ze_c).prefix(16))
        case .zecNist:      return sha256kdf(pre: Ze_c, Zs: nil)
        case .zecX963:      return sha256x963(Z: Ze_c, extra: nil)
        case .zeZecNist:    return sha256kdf(pre: Ze, Zs: Ze_c)
        case .zecZeNist:    return sha256kdf(pre: Ze_c, Zs: Ze)
        case .zeZecCat:     return Data(SHA256.hash(data: Ze + Ze_c).prefix(16))
        case .zecZeCat:     return Data(SHA256.hash(data: Ze_c + Ze).prefix(16))
        case .hmacZeKeyZec: return Data(hmacSHA256(key: [UInt8](Ze), data: [UInt8](Ze_c)).prefix(16))
        case .hmacZecKeyZe: return Data(hmacSHA256(key: [UInt8](Ze_c), data: [UInt8](Ze)).prefix(16))
        }
    }

    // NIST SP 800-56A single-step KDF: SHA256(0x00000001 ‖ Z ‖ extra?)
    private func sha256kdf(pre Ze: Data, Zs: Data?) -> Data {
        var counter = UInt32(1).bigEndian
        var input = Data(bytes: &counter, count: 4) + Ze
        if let Zs { input += Zs }
        return Data(SHA256.hash(data: input).prefix(16))
    }

    // ANSI X9.63 KDF: SHA256(Z ‖ 0x00000001 ‖ extra?)
    private func sha256x963(Z: Data, extra: Data?) -> Data {
        var counter = UInt32(1).bigEndian
        var input = Z + Data(bytes: &counter, count: 4)
        if let extra { input += extra }
        return Data(SHA256.hash(data: input).prefix(16))
    }

    private func hmacSHA256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var mac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key, key.count, data, data.count, &mac)
        return mac
    }

    // MARK: - Nonce Construction

    /// Converts a 7-byte sensor nonce to the CCM nonce required for a given variant.
    ///
    /// - Parameters:
    ///   - nonce7: 7 bytes as received in the sensor challenge packet.
    ///   - variant: Padding strategy; defaults to ``nonceVariant`` when `nil`.
    /// - Returns: 7-byte (raw7) or 13-byte CCM nonce.
    func buildChallengeNonce(nonce7: [UInt8], variant: NonceVariant? = nil) -> [UInt8] {
        switch variant ?? nonceVariant {
        case .rightPad:  return nonce7 + [UInt8](repeating: 0, count: 6)
        case .leftPad:   return [UInt8](repeating: 0, count: 6) + nonce7
        case .dataNonce:
            var n = [UInt8](repeating: 0, count: 13)
            n[0] = nonce7[0]; n[1] = nonce7[1]
            n[2] = Libre3Keys.packetDescriptors[7][0]
            n[3] = Libre3Keys.packetDescriptors[7][1]
            n[4] = Libre3Keys.packetDescriptors[7][2]
            return n
        case .seqOnly:
            var n = [UInt8](repeating: 0, count: 13)
            n[0] = nonce7[0]; n[1] = nonce7[1]
            return n
        case .raw7:
            return nonce7  // 7 bytes → q=8 CCM (8-byte counter field, flags=0x0F)
        }
    }

    // Nonce for post-handshake data packets: seq_LE16 ‖ descriptor(3) ‖ ivEnc(8)
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

    // MARK: - AES-CCM

    private let tagLen = 4

    /// Encrypts `plaintext` with AES-CCM using `key` and `nonce`.
    ///
    /// Supports 7-byte nonces (q=8) and 13-byte nonces (q=2). Tag length is always 4 bytes.
    ///
    /// - Parameters:
    ///   - key: 16-byte AES-128 key.
    ///   - nonce: 7 or 13 bytes.
    ///   - plaintext: Arbitrary-length input.
    /// - Returns: `plaintext.count + 4` bytes (ciphertext ‖ tag).
    func aesCCMEncrypt(key: Data, nonce: [UInt8], plaintext: [UInt8]) throws -> Data {
        try aesCCMEncrypt(key: [UInt8](key), nonce: nonce, plaintext: plaintext)
    }

    func aesCCMEncrypt(key: [UInt8], nonce: [UInt8], plaintext: [UInt8]) throws -> Data {
        guard key.count == 16, nonce.count == 7 || nonce.count == 13 else { throw CryptoError.invalidInput }
        let tag = try cbcMac(key: key, nonce: nonce, plaintext: plaintext, tagLen: tagLen)
        let keystream = try ctrKeystream(key: key, nonce: nonce, length: 16 + plaintext.count)
        var result = [UInt8](repeating: 0, count: plaintext.count + tagLen)
        for i in 0..<plaintext.count { result[i] = plaintext[i] ^ keystream[16 + i] }
        for i in 0..<tagLen          { result[plaintext.count + i] = tag[i] ^ keystream[i] }
        return Data(result)
    }

    /// Decrypts and verifies `ciphertext` with AES-CCM.
    ///
    /// - Parameters:
    ///   - key: 16-byte AES-128 key.
    ///   - nonce: 7 or 13 bytes.
    ///   - ciphertext: `plaintext.count + 4` bytes (ciphertext ‖ tag).
    /// - Returns: Decrypted plaintext.
    /// - Throws: ``CryptoError/tagMismatch`` if the authentication tag is wrong.
    func aesCCMDecrypt(key: [UInt8], nonce: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        guard key.count == 16, (nonce.count == 7 || nonce.count == 13), ciphertext.count >= tagLen else {
            throw CryptoError.invalidInput
        }
        let plainLen = ciphertext.count - tagLen
        let keystream = try ctrKeystream(key: key, nonce: nonce, length: 16 + plainLen)
        var plain = [UInt8](repeating: 0, count: plainLen)
        for i in 0..<plainLen { plain[i] = ciphertext[i] ^ keystream[16 + i] }
        let expectedTag = try cbcMac(key: key, nonce: nonce, plaintext: plain, tagLen: tagLen)
        var receivedTag = [UInt8](repeating: 0, count: tagLen)
        for i in 0..<tagLen { receivedTag[i] = ciphertext[plainLen + i] ^ keystream[i] }
        guard receivedTag == Array(expectedTag.prefix(tagLen)) else { throw CryptoError.tagMismatch }
        return plain
    }

    /// CTR-mode decryption without tag verification — used for diagnostic logging when all tags fail.
    func aesCCMDecryptRaw(key: [UInt8], nonce: [UInt8], ciphertext: [UInt8]) -> [UInt8]? {
        guard key.count == 16, (nonce.count == 7 || nonce.count == 13), ciphertext.count >= tagLen else { return nil }
        let plainLen = ciphertext.count - tagLen
        guard let keystream = try? ctrKeystream(key: key, nonce: nonce, length: 16 + plainLen) else { return nil }
        var plain = [UInt8](repeating: 0, count: plainLen)
        for i in 0..<plainLen { plain[i] = ciphertext[i] ^ keystream[16 + i] }
        return plain
    }

    // CBC-MAC for AES-CCM; q = 15 - nonce.count (q=2 for 13B nonce, q=8 for 7B nonce)
    private func cbcMac(key: [UInt8], nonce: [UInt8], plaintext: [UInt8], tagLen: Int) throws -> [UInt8] {
        let q = 15 - nonce.count
        var b0 = [UInt8](repeating: 0, count: 16)
        b0[0] = UInt8((tagLen - 2) / 2) << 3 | UInt8(q - 1)
        for i in 0..<nonce.count { b0[1 + i] = nonce[i] }
        let msgLen = plaintext.count
        for i in 0..<q { b0[15 - i] = UInt8((msgLen >> (i * 8)) & 0xFF) }
        var mac = [UInt8](repeating: 0, count: 16)
        mac = try aesBlock(key: key, input: xor(mac, b0))
        var padded = plaintext
        let rem = plaintext.count % 16
        if rem != 0 { padded += [UInt8](repeating: 0, count: 16 - rem) }
        for blockStart in stride(from: 0, to: padded.count, by: 16) {
            mac = try aesBlock(key: key, input: xor(mac, Array(padded[blockStart..<blockStart + 16])))
        }
        return mac
    }

    // AES-CTR keystream; counter starts at 0 (S_0 = tag-mask block, S_1 onwards = plaintext XOR)
    private func ctrKeystream(key: [UInt8], nonce: [UInt8], length: Int) throws -> [UInt8] {
        let q = 15 - nonce.count
        var result = [UInt8]()
        var counter: UInt64 = 0
        while result.count < length {
            var a = [UInt8](repeating: 0, count: 16)
            a[0] = UInt8(q - 1)
            for i in 0..<nonce.count { a[1 + i] = nonce[i] }
            for i in 0..<q { a[15 - i] = UInt8((counter >> (UInt64(i) * 8)) & 0xFF) }
            result += try aesBlock(key: key, input: a)
            counter += 1
        }
        return Array(result.prefix(length))
    }

    private func xor(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] { zip(a, b).map { $0 ^ $1 } }

    private func aesBlock(key: [UInt8], input: [UInt8]) throws -> [UInt8] {
        guard key.count == 16, input.count == 16 else { throw CryptoError.invalidInput }
        var output = [UInt8](repeating: 0, count: 16)
        var outLen = 0
        let status = CCCrypt(
            CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
            key, kCCKeySizeAES128, nil, input, 16, &output, 16, &outLen
        )
        guard status == kCCSuccess else { throw CryptoError.aesFailed }
        return output
    }

    enum CryptoError: Error { case invalidInput, tagMismatch, aesFailed }
}

// MARK: - Glucose Parsing

/// A single one-minute glucose reading received from the sensor.
struct GlucoseReading {
    let lifeCount: UInt16
    let glucoseMgDl: Int
    let rateOfChange: Double
    let trendArrow: String
}

/// Parses a decrypted one-minute reading notification.
///
/// Layout (from DiaBLE, confirmed against sensor data):
/// - bytes 0–1: life count (LE16)
/// - bytes 2–3: raw reading (LE16, 13-bit glucose value in bits 0–12, mg/dL)
/// - bytes 4–5: rate of change (LE16 signed, units: mg/dL/min × 100)
/// - byte 14: bitfield; bits 0–2 = trend index
///
/// - Parameters:
///   - data: Decrypted payload (minimum 15 bytes).
///   - activationTime: Sensor activation timestamp (unused, reserved for future use).
/// - Returns: Parsed reading, or `nil` if `data` is too short.
func parseOneMinuteReading(data: Data, activationTime: UInt32) -> GlucoseReading? {
    guard data.count >= 15 else { return nil }
    let lifeCount  = UInt16(data[0]) | (UInt16(data[1]) << 8)
    let rawReading = UInt16(data[2]) | (UInt16(data[3]) << 8)
    let glucose    = Int(rawReading & 0x1fff)
    let roc        = Double(Int16(bitPattern: UInt16(data[4]) | (UInt16(data[5]) << 8))) / 100.0
    let trend      = data[14] & 0x07
    let arrows     = ["→", "↗", "↑", "↑↑", "↓↓", "↓", "↘", "→"]
    let arrow      = Int(trend) < arrows.count ? arrows[Int(trend)] : "?"
    return GlucoseReading(lifeCount: lifeCount, glucoseMgDl: glucose, rateOfChange: roc, trendArrow: arrow)
}

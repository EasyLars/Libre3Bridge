# Libre3Bridge

An iOS proof-of-concept for reading FreeStyle Libre 3 glucose sensors directly via Bluetooth Low Energy, without the Abbott LibreLink app.

**Authors:** Lars & Lars  
**Based on:** [Juggluco](https://www.juggluco.nl/) by Jaap Korthals Altes  
**License:** GPL-3.0 (see below)

---

## What it does

Libre3Bridge implements the full Libre 3 BLE security handshake as a native iOS app:

1. Scans for the Libre 3 GATT services
2. Sends the app static certificate (140–162 bytes) and ephemeral P-256 public key to the sensor
3. Receives the sensor static certificate and ephemeral key
4. Answers the 23-byte challenge with a 40-byte **nonce-back** encrypted with AES-CCM
5. Decrypts the 67-byte challenge response to extract `kEnc` and `ivEnc`
6. Decrypts live glucose notifications using the session keys

The BLE protocol, packet framing, GATT UUIDs, and AES-CCM implementation are all derived from reverse-engineering Juggluco's `Libre3GattCallback.java` and `bcrypt.cpp`.

---

## Current Status

| Step | Status | Notes |
|------|--------|-------|
| BLE connection & service discovery | ✅ Working | Sensor found and connected reliably |
| App cert + ephemeral key exchange | ✅ Working | Chunked 20-byte GATT writes |
| Sensor cert + ephemeral key receive | ✅ Working | 140-byte and 65-byte payloads parsed correctly |
| 23-byte challenge received | ✅ Working | r1 and nonce1 extracted |
| Nonce-back sent | ✅ Working | AES-CCM implementation is correct |
| Sensor accepts nonce-back | ❌ **Blocked** | Sensor disconnects — KDF formula unknown |
| 67-byte challenge received | ❌ Not reached | Blocked by nonce-back rejection |
| Glucose reading | ❌ Not reached | Blocked by handshake failure |

### The Blocker: Unknown KDF

The sensor verifies the nonce-back by decrypting it with its own copy of `kInit`.  We do not yet know the exact formula the sensor uses to derive `kInit` from the ECDH shared secrets.

We have tested **70 combinations** (14 KDF formulas × 5 nonce constructions) per session across multiple builds, all rejected.

**What we know:**

- The nonce-back plaintext is `r1(16) ‖ r2(16) ‖ pin(4)` where pin = `0x00000000` for BLE-only  
  (confirmed from `Libre3GattCallback.java::mknonceback()`)
- AES-CCM parameters: 128-bit key, 4-byte tag, 7-byte nonce with `q=8` (most likely)
- Four P-256 ECDH terms exist:
  - `Ze   = ECDH(appEphPriv,  sensorEphPub)`  — symmetric ✅
  - `Ze_c = ECDH(appEphPriv,  sensorStatPub)` — symmetric ✅
  - `Zs   = ECDH(appStatPriv, sensorStatPub)` — symmetric IF app static private key is known
  - `Zs_c = ECDH(appStatPriv, sensorEphPub)`  — symmetric IF app static private key is known
- All 14 Ze/Ze_c-only variants (V1–V14) failed in live sensor tests
- The app static private key blob (`LIBRE3_APP_PRIVATE_KEYS` in Juggluco's `ECDHCrypto.java`) does **not** contain the raw P-256 scalar at the expected offset — the blob format is either a proprietary Abbott format or a TEE-wrapped key

**Likely hypotheses (untested):**

1. The KDF includes session-specific data: `kInit = f(Ze_c, r1)` or `f(Ze_c, nonce1)`
2. The app static private key blob decrypts to the correct scalar inside Abbott's native library (`liblibre3extension.so`), which we cannot run on non-Android hardware
3. There is an intermediate key derivation step inside `liblibre3extension.so` not visible in the Java source

**Known test vector** (from `Juggluco/libre3init.java`, security level 1, no PIN):

```
sensorStatPub (offset 11 of rdtData):  04 88 1A CC 74 EE C1 D7 ...
sensorEphPub  (data6):                  04 F3 9D 2D F9 DA B5 78 ...
r1:  C6 57 A6 92 E5 7C 63 F2 C9 A1 99 22 BE DD 9E F4
r2:  21 24 27 C0 C9 74 EC A3 70 91 77 59 14 F9 BC 3D
nonce1 (for nonce-back):  A5 01 00 00 92 D0 44
nonce  (for challenge67): A6 01 00 00 12 C2 C3
pin:   F4 89 54 99  (NFC session; BLE-only would be 00 00 00 00)
bytes60 (challenge67 ciphertext):
  4A F5 6F A6 46 70 F9 0D 7F 37 54 18 4B 45 7B F4
  43 8C 2F EF CA ED 32 CE E3 1F 95 49 FD 42 34 B0
  3F 65 9C 8C CE 49 5B A5 E7 A7 23 CC D3 B3 89 4F
  C7 6E B1 0E 87 1A F4 86 E4 63 15 3C

AES oracle (from bytes60 XOR known plaintext):
  AES_kInit(A1) = 6B D1 48 66 8F 04 15 AE 0F A6 23 41 5F BC C7 C9
  where A1 = 07 A6 01 00 00 12 C2 C3 00 00 00 00 00 00 00 01
```

Any candidate `kInit` can be verified offline against this oracle without a live sensor.  
The app ephemeral key for this test vector is unknown (generated inside `liblibre3extension.so`).

---

## Project Structure

```
Libre3Bridge.xcodeproj/
├── README.md                    ← this file
└── Libre3Bridge/
    ├── Libre3BridgeApp.swift    ← App entry point
    ├── ContentView.swift        ← UI (glucose, status, KDF results, log)
    ├── Libre3Manager.swift      ← CoreBluetooth layer, handshake state machine
    ├── Libre3Crypto.swift       ← ECDH, KDF variants, AES-CCM, glucose parsing
    └── Libre3Keys.swift         ← Certificates, keys, UUIDs, packet descriptors
```

---

## How to Build

### Requirements

- macOS with Xcode 15+
- iOS 16.0+ device (Bluetooth required — simulator will not work)
- Apple Developer account (free tier is sufficient for device testing)

### Steps

1. Open `Libre3Bridge.xcodeproj` in Xcode
2. Set your Team in **Signing & Capabilities**
3. Add `NSBluetoothAlwaysUsageDescription` to `Info.plist`:  
   `"Required to communicate with FreeStyle Libre 3 sensor"`
4. Select your iPhone as the run destination and press **Run**

### Distribution for Field Testing

Use **Product → Archive → Distribute → TestFlight** to distribute to testers.  
Do not use `xcodebuild archive` from the command line (manual archive only).

---

## How to Use

1. Tap **Connect**
2. Hold the sensor near the phone
3. The app cycles through KDF variants automatically (one attempt per minute — the sensor wakes BLE only once per minute to conserve battery over its 14-day lifetime)
4. If a match is found, glucose readings appear automatically
5. Tap the copy icon to export the full log for analysis

The log shows each KDF variant attempted and the raw bytes of any challenge received.

---

## Contributing / Contact

We are stuck on identifying the correct KDF formula.  If you have insights into:

- The format of `LIBRE3_APP_PRIVATE_KEYS` blobs in Juggluco's `ECDHCrypto.java`
- The KDF used inside `liblibre3extension.so` (Abbott's native Android library)
- Any dynamic analysis of the `processbar(7)` / `processbar(8)` calls with known inputs

please open an issue or contact us directly.

This project derives from Juggluco.  Contributions are welcome under GPL-3.0.

---

## License

```
Copyright (C) 2024 Lars & Lars

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

This project is based on Juggluco, Copyright (C) 2021 Jaap Korthals Altes, also licensed under GPL-3.0.

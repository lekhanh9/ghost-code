# GhostCode 👻

A zero-dependency, pure Swift code signing engine and Mach-O manipulation toolkit designed for iOS (iOS 13 through iOS 16+) and macOS. 

GhostCode provides complete, cross-platform Apple code signing capabilities—including **ASN.1 DER Entitlements (Slot -7)** for iOS 16+, **2-pass Page 0 hash recalculation**, **Bundle Sealing (`CodeResources`)**, **embedded provisioning profile handling**, and **full `.ipa` packaging**—running seamlessly on Linux and macOS without requiring Xcode or macOS-only proprietary binaries.

---

## ⚡ Highlights & Key Features

- **Zero External Dependencies**: Implemented in 100% pure Swift, including native SHA-1 / SHA-256 engines and ASN.1 DER encoders.
- **iOS 16+ Ready (DER Entitlements)**: Built-in ASN.1 DER encoder targeting Special Slot `-7` (`CSSLOT_DER_ENTITLEMENTS`), ensuring compatibility with iOS 16 kernel trust policies and CoreTrust.
- **Novel 2-Pass Page 0 Hashing**: Solves the classic Mach-O load command injection paradox by pre-injecting `LC_CODE_SIGNATURE`, recalculating Page 0 byte hashes over updated load commands, and rewriting the SuperBlob in-place.
- **Complete Bundle Sealer (`CodeResources`)**: Generates Apple-compliant XML plists with both SHA-1 and SHA-256 resource digests, recursive nested bundle/framework sealing, and symlink cycle protection.
- **MobileProvision Integration**: Extracts entitlement dictionaries directly from CMS-wrapped `.mobileprovision` files using safe reverse tag scanning, embedding profiles into `embedded.mobileprovision`.
- **Flexible Signing Modes**: Supports Ad-Hoc signing (`--adhoc`, flag `0x20002`), PKCS#12 bundles (`--p12`), and raw PEM/DER keypairs (`--cert cert.pem --key key.pem`).
- **Universal CLI & Cross-Platform Engine**: Runs on Linux and macOS; handles raw Mach-O binaries, `.app` directory bundles, and `.ipa` archives.
- **Rigorously Tested**: 68 comprehensive unit and adversarial test suites + automated 10-step signature diagnostic verifier (`verify.sh`).

---

## 📐 Architecture & Module Structure

```
GhostCode/
├── Sources/
│   ├── GhostCode/
│   │   ├── API/
│   │   │   └── GhostSigner.swift         # Unified high-level signing orchestrator
│   │   ├── MachO/
│   │   │   ├── MachOStructures.swift     # Header, segment & load command struct layouts
│   │   │   ├── MachOReader.swift         # Mach-O parser (32-bit & 64-bit slices, LC scanner)
│   │   │   └── MachOWriter.swift         # LC_CODE_SIGNATURE injector, header & __LINKEDIT updater
│   │   └── CodeSigning/
│   │       ├── CodeDirectory.swift       # CSMAGIC_CODEDIRECTORY builder, page & special slots
│   │       ├── SuperBlobBuilder.swift    # SuperBlob (0xfade0cc0) indexer and slot packer
│   │       ├── DEREncoder.swift          # Pure Swift ASN.1 DER encoder for iOS 16+ Slot -7
│   │       ├── BundleSealer.swift        # _CodeSignature/CodeResources generator (SHA-1/SHA-256)
│   │       ├── CMSSigner.swift           # Detached PKCS#7 CMS signature generator (Slot 0x10000)
│   │       └── CryptoHelpers.swift       # Zero-dependency SHA-1 & SHA-256 cryptographic fallbacks
│   └── GhostCLI/
│       └── main.swift                    # CLI tool for .ipa / .app / Mach-O signing
└── Tests/
    └── GhostCodeTests/
        ├── MachOTests/                   # MachOReader & MachOWriter unit tests
        └── CodeSigningTests/             # DER, CodeDirectory, Sealer, CMS & Signer tests
```

---

## 🛠 Installation & Building

### Prerequisites
- **Swift 5.9+** (Linux or macOS)
- Standard tools: `zip`, `unzip` (for `.ipa` handling), `openssl` (for PKCS#12 credentials)

### Build GhostCode Library & CLI
```bash
# Clone the repository
git clone https://github.com/lekhanh9/ghost-code.git
cd ghost-code

# Build release configuration
swift build -c release

# The executable will be available at:
# .build/release/GhostCLI
```

### Run Test Suite
```bash
swift test
```
All 68 unit tests execute in under 3 seconds with 0 warnings or failures.

---

## 🚀 CLI Usage (`GhostCLI`)

`GhostCLI` can sign raw Mach-O executables, `.app` application bundles, and zipped `.ipa` archives.

```bash
GhostCLI <target.app or .ipa or binary> [OPTIONS]
```

### Options:
| Flag | Description |
|---|---|
| `--adhoc` | Perform Ad-Hoc code signing (no certificate required, sets flag `0x20002`). |
| `--p12 <path>` | Path to PKCS#12 (`.p12`) certificate and private key file. |
| `--cert <path>` | Path to certificate file in PEM (`cert.pem`) or DER format. |
| `--key <path>` | Path to private key file in PEM (`key.pem`) or DER format. |
| `--password <pass>` | Password for the PKCS#12 file. |
| `--provision <path>` | Path to `.mobileprovision` provisioning profile. Embedded into bundle and used to extract entitlements. |
| `--entitlements <path>` | Path to custom XML entitlements `.plist`. |
| `-o`, `--output <path>` | Destination path for the signed binary, `.app`, or `.ipa`. |

---

### Examples

#### 1. Sign an `.ipa` with MobileProvision & P12 Identity
```bash
./.build/release/GhostCLI my_app.ipa \
  --p12 cert.p12 \
  --password secret \
  --provision embedded.mobileprovision \
  --output signed_app.ipa
```

#### 2. Sign an `.ipa` with PEM Certificate & Private Key (`cert.pem` & `key.pem`)
```bash
./.build/release/GhostCLI my_app.ipa \
  --cert cert.pem \
  --key key.pem \
  --provision embedded.mobileprovision \
  --output signed_app.ipa
```

#### 3. Ad-Hoc Sign an `.app` Bundle
```bash
./.build/release/GhostCLI Payload/Test.app --adhoc
```

#### 4. Sign a Raw Mach-O Binary with Custom Entitlements
```bash
./.build/release/GhostCLI my_binary \
  --entitlements entitlements.plist \
  --output my_binary_signed
```

---

## 💻 Swift API Usage

You can embed `GhostCode` directly into your Swift projects as a Swift Package Manager (SPM) dependency.

### `Package.swift`
```swift
dependencies: [
    .package(url: "https://github.com/lekhanh9/ghost-code.git", branch: "main")
]
```

### Code Example: Signing a Bundle

```swift
import Foundation
import GhostCode

let signer = GhostSigner()

let appURL = URL(fileURLWithPath: "/path/to/Payload/App.app")
let provisionURL = URL(fileURLWithPath: "/path/to/embedded.mobileprovision")

// Signs nested frameworks, seals CodeResources, extracts entitlements from profile,
// and signs main executable with 2-pass Page 0 hash alignment:
try signer.signBundle(
    appURL: appURL,
    provisioningProfileURL: provisionURL
)

print("Successfully signed bundle!")
```

### Code Example: Direct Mach-O Binary Signing

```swift
import Foundation
import GhostCode

var binaryData = try Data(contentsOf: URL(fileURLWithPath: "my_macho_binary"))

let customEntitlements: [String: Any] = [
    "get-task-allow": true,
    "application-identifier": "TEAMID123.com.example.app"
]

try GhostSigner().sign(
    binaryData: &binaryData,
    identifier: "com.example.app",
    entitlements: customEntitlements,
    isAdHoc: true
)

try binaryData.write(to: URL(fileURLWithPath: "my_macho_binary_signed"))
```

---

## 🔍 Verification & Diagnostics

`GhostCode` includes an automated 10-step diagnostic verification suite located in `test_env/verify.sh`.

```bash
bash test_env/verify.sh test_env/signed.ipa
```

### Verification Checks:
1. **Archive Integrity**: Checks archive non-emptiness and file structure.
2. **Bundle Unpacking**: Validates `Payload/<App>.app` hierarchy.
3. **Info.plist**: Extracts and verifies `CFBundleIdentifier`, `CFBundleExecutable`, and main binary existence.
4. **CodeResources XML**: Verifies rules, rules2, files dictionaries, exclusions, and SHA-1/SHA-256 hashes.
5. **Mach-O Headers**: Verifies ARM64 64-bit header, `__LINKEDIT` segment size, and 16-byte aligned `LC_CODE_SIGNATURE`.
6. **SuperBlob Layout**: Validates `0xfade0cc0` magic, blob length, and slot count.
7. **CodeDirectory Page Hashes**: Re-computes SHA-256 for all 4096-byte pages and checks byte-for-byte identity (including post-injection Page 0).
8. **Special Slots**:
   - Slot -1 (`CSSLOT_INFOSLOT`): Info.plist SHA-256 hash.
   - Slot -3 (`CSSLOT_RESOURCEDIR`): `CodeResources` SHA-256 hash.
   - Slot -7 (`CSSLOT_DER_ENTITLEMENTS`): Valid ASN.1 DER entitlement byte stream.
9. **Signature Slot**: Verifies `0x10000` (`CSSLOT_SIGNATURESLOT`) CMS container or Ad-Hoc omission.
10. **Result Summary**: Exits with code `0` on 100% compliance.

---

## 🛡 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

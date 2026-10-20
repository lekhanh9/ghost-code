# Project: GhostCode Bundle Signing & CMS Signer

## Architecture
- `Sources/GhostCode/CodeSigning/BundleSealer.swift`: Generates `_CodeSignature/CodeResources` XML plist with SHA-1 and SHA-256 hashes, rules, files, files2, handling symlinks, nested frameworks, and excluding `_CodeSignature/` and `Info.plist`.
- `Sources/GhostCode/CodeSigning/CMSSigner.swift`: Uses native `Security.framework` (`CMSEncoder`) on Darwin to generate detached PKCS#7 CMS signature over `CodeDirectory` data with `BlobWrapper` (0xfade0b01); provides Linux mock/stub types for cross-platform compatibility.
- `Sources/GhostCode/CodeSigning/CryptoHelpers.swift`: Zero-dependency SHA-1 and SHA-256 implementations for cross-platform Linux/Darwin execution.
- `Sources/GhostCode/CodeSigning/CodeDirectory.swift`: Populates Special Slot -1 (`CSSLOT_INFOPLIST`) and Special Slot -3 (`CSSLOT_RESOURCEDIR`).
- `Sources/GhostCode/CodeSigning/SuperBlobBuilder.swift`: Embeds CMS signature in `CSSLOT_SIGNATURESLOT` (0x10000) wrapped in `CSMAGIC_BLOBWRAPPER`.
- `Sources/GhostCode/API/GhostSigner.swift`: Orchestrates full signing pipeline (nested frameworks/plugins bottom-up, CodeResources sealing, executable signing with DER entitlements, CMS blob insertion into slot 0x10000).
- `Sources/GhostCLI/main.swift`: Zero-dependency CLI entrypoint accepting `--p12`, `--password`, `--provision` flags.
- `Tests/`: Comprehensive unit and integration test suites with dummy `.app` bundles.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Research & Spec Mining | Detailed analysis of CodeResources plist format, SHA-1/256, symlinks, CMS PKCS#7 signing | Phase 1 | ORIGINAL_REQUEST |
| 2 | Native SHA-1 & Constants | Add NativeSHA1 to CryptoHelpers and CSMAGIC_BLOBWRAPPER (0xfade0b01) to MachOStructures | Phase 2 | Research |
| 3 | BundleSealer | `generateCodeResources(for appURL: URL) throws -> Data` with XML plist, rules, files, files2, SHA-1/SHA-256, symlink handling, nested frameworks, exclusions | Phase 2 | ORIGINAL_REQUEST |
| 4 | CMSSigner | `signCodeDirectory(codeDirectoryData: Data, cert: SecCertificate, key: SecKey) throws -> Data` with detached PKCS#7 signature via CMSEncoder (Darwin) and mock/stub (Linux) | Phase 3 | ORIGINAL_REQUEST |
| 5 | CodeDirectory & SuperBlob Extension | Support Slot -1, Slot -3, and Slot 0x10000 BlobWrapper | Phase 4 | Research |
| 6 | GhostSigner Pipeline | Orchestrate signing nested frameworks/plugins first, generate CodeResources, sign main executable, embed CMS blob in slot 0x10000 | Phase 4 | ORIGINAL_REQUEST |
| 7 | GhostCLI & Package.swift | Add GhostCLI executable target in Package.swift, CLI flags `--p12`, `--password`, `--provision` invoking the full signing pipeline | Phase 4 | ORIGINAL_REQUEST |
| 8 | Dummy .app Test Infrastructure | Dummy app structure with mock resources to test sealing and signing | Phase 5 | ORIGINAL_REQUEST |
| 9 | Full Verification & Remote Push | `swift build`, `swift test` 100% pass, commit `[skip ci] feat: implement bundle sealer and CMS signer`, push to `origin main` | Phase 5 | ORIGINAL_REQUEST |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Phase 1: Research | Survey CodeSignKit & Security.framework, summarize specifications | none | DONE |
| 2 | Phase 2: Bundle Sealer | `BundleSealer.swift`, `NativeSHA1`, `CSMAGIC_BLOBWRAPPER`, and unit tests | Phase 1 | DONE |
| 3 | Phase 3: CMS Signer | `CMSSigner.swift` implementation and unit tests | Phase 1 | DONE |
| 4 | Phase 4: Integration & CLI | `GhostSigner.swift`, `Package.swift`, and `Sources/GhostCLI/main.swift` | Phase 2, Phase 3 | DONE |
| 5 | Phase 5: Verification & Push | E2E tests, `swift build`, `swift test`, git commit & push | Phase 4 | DONE |

## Code Layout
- `Sources/GhostCode/CodeSigning/`: Core code signing library components (`BundleSealer.swift`, `CMSSigner.swift`, `CryptoHelpers.swift`, `CodeDirectory.swift`, `SuperBlobBuilder.swift`)
- `Sources/GhostCode/API/`: Public API (`GhostSigner.swift`)
- `Sources/GhostCode/MachO/`: Low-level Mach-O structures and reader/writer
- `Sources/GhostCLI/`: Command line interface (`main.swift`)
- `Tests/GhostCodeTests/`: Unit and integration tests

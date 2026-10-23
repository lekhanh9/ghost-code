# zsign signing architecture → ghost-code

Analysis of `zhlynn/zsign` @ `9299685` (read from source, not from docs), and a gap
analysis against `Sources/GhostCode`. No code was changed.

Severity scale used throughout:

- **S1** — Apple's verifier rejects the signature / install fails on device.
- **S2** — fails on some inputs (fat binaries, specific bundle IDs, distribution profiles).
- **S3** — fidelity/determinism only; installs work.

---

## 1. Where the logic actually lives

The brief named `zsign.cpp`, `bundle.cpp`, `macho.cpp`. Only one of those holds signing
logic:

| File | Role |
|---|---|
| `src/zsign.cpp` (517 L) | CLI: arg parsing, `.ipa` unzip/rezip, drives `ZBundle`. **No signing logic.** |
| `src/bundle.cpp` (910 L) | Bundle discovery, traversal order, `CodeResources`, Info.plist mutation, profile injection. |
| `src/macho.cpp` (280 L) | Fat/thin container wrapper; per-arch dispatch; signature-space realloc + fat rebuild. |
| `src/archo.cpp` (763 L) | **Per-arch Mach-O**: load-command scan, `BuildCodeSignature`, slot order, `LC_CODE_SIGNATURE`, dylib injection. |
| `src/signing.cpp` (860 L) | **Blob builders**: CodeDirectory, entitlements (XML + DER), requirements, CMS slot, slot parsers. |
| `src/openssl.cpp` (965 L) | **CMS/PKCS#7 via OpenSSL**, cert/profile loading, WWDR chain, `GetCMSContent`. |
| `src/metadata.cpp`, `src/certcheck.cpp` | mtime metadata; certificate inspection. Not on the signing path. |

So Phase 1 item 4 ("does it use OpenSSL, how does it align `LC_CODE_SIGNATURE`") is answered
by `openssl.cpp:361-521` and `archo.cpp:565-664` — neither file was in the brief.

---

## 2. End-to-end algorithm (`ZBundle::SignFolder`, bundle.cpp:780)

1. **Locate the app root** — `FindAppFolder` (bundle.cpp:21): accepts a path ending `.app`/`.appex`,
   else recursive scan for the first such folder, skipping `__MACOSX`.
2. **Mutate Info.plist before anything is sealed** — `ApplyAppModifications` (bundle.cpp:721):
   `UISupportsDocumentBrowser`/`UIFileSharingEnabled`, `MinimumOSVersion`, delete `PlugIns`/`Extensions`,
   delete `Watch`/`WatchKit`/`com.apple.WatchPlaceholder`, delete `UISupportedDevices`. Each sets `m_bForceSign`.
   Then `ChangeAppIcon` (545) and `ModifyBundleInfo` (656). All plist edits happen **pre-seal** — any edit
   after sealing leaves the seal stale.
3. **Root profile write** — delete then write `<app>/embedded.mobileprovision` (bundle.cpp:829-835).
   Only the root bundle here; nested bundles get theirs in step 8.
4. **Copy injected dylibs** into the app root (bundle.cpp:837-846).
5. **Cache check** — `./.zsign_cache/<sha1(appFolderPath)>.json`; if absent → force sign (848-852).
   `bEnableCache` writes the tree descriptor back after success (886-889).
6. **Build the work descriptor** — `GetSignFolderInfo` + `GetObjectsToSign` + `GetNodeChangedFiles` (854-868).
7. **`SignNode(jvRoot)`** (885) — the recursive worker, described next.

### `SignNode` order (bundle.cpp:312-477)

For each node: (a) sign its loose Mach-O files, (b) recurse into child bundle nodes,
(c) then seal *this* bundle: generate/patch `CodeResources`, write it, sign this bundle's
executable. Because children are fully processed before the parent's seal is generated,
the parent's seal hashes the children's **already re-signed** bytes. That ordering is the
whole point of the design.

---

## 3. Nested bundle handling

### Discovery (`GetObjectsToSign`, bundle.cpp:86-153)

- Recursive scan collects directories ending `.app`, `.appex`, `.framework`, `.xctest`
  (91-105). It recurses into bundles *and* non-bundle dirs, so appex-inside-watchapp and
  framework-inside-appex are found. `.framework` versions layout (`Versions/A`) is **not**
  special-cased — fine for iOS, wrong for macOS.
- Results are sorted by **slash count, deepest first** (109-114). Consequence: `Payload.app/Watch.app/PlugIns.ext.appex`
  is sealed before `Watch.app`, which is sealed before the root. Note `std::sort` is **not stable**
  → same-depth siblings get an arbitrary order. Signatures are still valid (sibling order is
  irrelevant to the seal) but byte-for-byte reproducibility across runs is not guaranteed.
- Each discovered bundle becomes a node with `bundle_id`, `bundle_version`,
  `bundle_executable`, `sha1`/`sha256` of the raw `Info.plist` bytes (base64), and a
  root-relative `path` (47-84). The `folders` array is **flat**, not nested (119) — the
  "tree" is really a depth-ordered list plus the root.
- Separately, a full recursive **file** scan (123-150) sniffs each file's first 4 bytes for
  `MH_MAGIC`/`MH_CIGAM`/`MH_MAGIC_64`/`MH_CIGAM_64`/`FAT_MAGIC`/`FAT_CIGAM` and pushes every
  Mach-O into `jvInfo["files"]`, skipping dirs, `*.dSYM` and `* _WatchKitStub*`.

### The double-sign quirk

A framework binary (`Frameworks/Foo.framework/Foo`) matches **both** scans: it is a Mach-O file
(147) and its containing `.framework` is a bundle node (95). So it is signed once generically via
the files list — `macho.Sign(..., "", "", "", "")` (320) with empty bundle ID and empty Info.plist
hashes, which `MachO::Sign` (macho.cpp:132-148) back-fills from the binary's own `__TEXT,__info_plist`
section (`archo.cpp:61`, `81`) or **zeroes** if absent (143-144) — and again properly when the
`.framework` node is processed. The second pass overwrites the first. It works, but it doubles the
work and, for binaries lacking an embedded `__info_plist`, produces an intermediate signature whose
slot -1 is 32 zero bytes. Worth not copying: see §11.

### Parent re-seal after nested signing

`GetNodeChangedFiles`/`GetChangedFiles` (260-296) compute, for the root node, the list of
every descendant's `<path>/_CodeSignature/CodeResources` and `<path>/<executable>`, plus
`embedded.mobileprovision` at the root. In the non-force path those "changed" files are
patched into the *existing* parent `CodeResources` (440-463) instead of a full re-seal.

Note a bug in that patch path: it writes `files[key] = "data:<sha1>"` and
`files2[key] = {hash, hash2}` **without** re-applying the omit/optional rules (§4). So a changed
`*.lproj/locversion.plist` re-enters both dicts, and a changed `Info.plist`/`PkgInfo`/`.DS_Store`
re-enters `files2` even though `rules2` marks them `omit`. Apple tolerates extra entries in
`files2` (the rule says omit, so the verifier ignores them), which is why this survives. Don't
port it.

---

## 4. `CodeResources` generation (`GenerateCodeResources`, bundle.cpp:155-258)

Recursively collect all **files** under the bundle, root-relative, `\`→`/`, into a sorted `set<string>`
(157-165). Erase `_CodeSignature/CodeResources` and the bundle executable (176-177). Optionally erase
and delete `embedded.mobileprovision` (184-189). For each remaining file, stream SHA-1 **and** SHA-256,
base64 both (194).

Emitted shape — note the asymmetry, which is exactly Apple's:

| Path | `files` (v1) | `files2` (v2) |
|---|---|---|
| normal file | `"data:<sha1b64>"` (scalar) | `{hash: "data:<sha1b64>", hash2: "data:<sha256b64>"}` |
| under `*.lproj/` | `{hash: "data:<sha1b64>", optional: true}` | `{hash, hash2, optional: true}` |
| `*.lproj/locversion.plist` | **omitted** | **omitted** |
| `.DS_Store` / `Info.plist` / `PkgInfo` | present (SHA-1) | **omitted** |

Two hard-coded rule dicts, both faithful to `codesign`'s standard sets (233-255):

- `rules` (5 keys): `^.*`=true, `^.*\.lproj/`={optional,w1000}, `^.*\.lproj/locversion.plist$`={omit,w1100},
  `^Base\.lproj/`={w1010}, `^version.plist$`=true.
- `rules2` (10 keys): adds `.*\.dSYM($|/)`={w11}, `^(.*/)?\.DS_Store$`={omit,w2000},
  `^Info\.plist$`={omit,w20}, `^PkgInfo$`={omit,w20}, `^embedded\.provisionprofile$`={w20},
  `^version\.plist$`={w20}.

**No negative-lookahead rules** (`^(?!.*\.lproj/).*$`) anywhere — zsign uses the same anchored
forms Apple emits, matched by highest-weight. **No symlink handling**: the enumerator yields files;
a symlink is read through and hashed as its target's content; zsign never emits a `symlinks` key
and never records the link itself. Apple's own seal also largely ignores link identity for resources,
so this is S3, but it means a bundle whose resources are symlinks produces a seal that only matches
as long as those links resolve identically at verify time.

---

## 5. Info.plist, profile and entitlements

- **`GetCMSContent`** (openssl.cpp:523) strips the profile's PKCS#7 to get the inner plist; `ZSignAsset::Init`
  (828-874) then reads `Entitlements.application-identifier` → `m_strApplicationId`, and `TeamIdentifier[0]`
  → `m_strTeamId`. If no `-e` entitlements file was supplied, **the profile's own `Entitlements` dict is
  re-serialized as the entitlements plist** (865-867). An explicit `-e` file wins. Missing TeamId is fatal (871).
- Adhoc mode short-circuits before any profile is read (842-850).
- **Multi-profile mode**: when signing with a list of identities (`SignFolder` overload, bundle.cpp:896),
  `SignNode` walks the list in reverse and writes `embedded.mobileprovision` into each bundle whose
  `CFBundleIdentifier` is a **suffix** of that identity's `application-identifier` (410-425), then forces
  re-sign of that bundle. This is how one app with several appexes, each with its own profile, gets correct profiles.
- **Ordering constraint**, spelled out in the comment at bundle.cpp:406-409: the profile must be written
  **before** `CodeResources` is generated, because the seal hashes every file in the bundle. Writing it
  after produces `a sealed resource is missing or invalid` under `codesign --verify --strict`.
- App-extension dylib injection uses a `../`-prefix back to the app root, and only for top-level
  `PlugIns/`/`Extensions/` appex (298-310, 389-404).
- Bundle-ID rewriting cascades: `ModifyPluginsBundleId` (479-528) rewrites `CFBundleIdentifier`,
  `WKCompanionAppBundleIdentifier`, and `NSExtension.NSExtensionAttributes.WKAppBundleIdentifier` in every
  nested `.app`/`.appex` — required so re-signed appexes still point at the renamed container.

---

## 6. Per-arch Mach-O signing (`archo.cpp`)

### Init scan (archo.cpp:27-114)

Walks load commands once, capturing: `__TEXT` `vmsize` → `s_uExecSegLimit` (static! shared across arches);
first `__text` section → `m_uLoadCommandsFreeSpace` (58-60, 78-80); `__TEXT,__info_plist` → embedded plist
(61, 81); `__LINKEDIT` segment command pointer (65, 85); `LC_ENCRYPTION_INFO` `cryptid>=1` → `m_bEncrypted`
(90-97); `LC_CODE_SIGNATURE` → `m_pCodeSignSegment`, `m_uCodeLength = dataoff`, `m_pSignBase`, `m_uSignLength`
(99-106).

### `BuildCodeSignature` (archo.cpp:327-562) — slot order

| # | Slot (blob index) | Contents | Notes |
|---|---|---|---|
| 1 | `CSSLOT_CODEDIRECTORY` (0) | SHA-1 CD | primary; skipped if `--SHA256only` |
| 2 | `CSSLOT_REQUIREMENTS` (2) | blob `0xfade0c01` | see below |
| 3 | `CSSLOT_ENTITLEMENTS` (5) | `0xfade7171` + XML plist | **non-executables get an empty `<dict/>`** (340-342) |
| 4 | `CSSLOT_DER_ENTITLEMENTS` (7) | `0xfade7172` + DER | executables only |
| 5 | `CSSLOT_ALTERNATE_CODEDIRECTORIES` (0x1000) | SHA-256 CD | always built |
| 6 | `CSSLOT_SIGNATURESLOT` (0x10000) | `0xfade0b01` + DER PKCS#7 | **ad-hoc: the 8-byte empty blobwrapper** (signing.cpp:676-679) |

Offsets are accumulated strictly in that emission order (488-529); blobs are concatenated in the same order
(543-548). Only blobs with non-zero length get an index (472-477), so the count is data-dependent.

**Requirements**: `SlotBuildRequirements` (signing.cpp:141-260) emits the designated requirement
`identifier "<bundleID>" and anchor apple generic and certificate leaf[subject.CN] = "<CN>" and
certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */`, as a real `opIdent/opAnd/opAppleGenericAnchor/
opCertField/opCertGeneric` expression tree. When bundle ID or CN is empty it emits an **empty requirements
vector** (magic, length=12, count=0 — ldid style) instead of omitting the slot (145-154).

**execSegFlags** (archo.cpp:380-403): `CS_EXECSEG_MAIN_BINARY` iff `MH_EXECUTE` — the comment states
without it macOS `codesign --verify` reports "code or signature have been modified".
`CS_EXECSEG_ALLOW_UNSIGNED` is set only when the entitlements plist contains `<key>get-task-allow</key>`
with a `<true/>` occurring before any `<false/>` — a string search on purpose, so distribution profiles
that carry `get-task-allow=false` keep the flag clear.

### CodeDirectory layout (`SlotBuildCodeDirectory`, signing.cpp:449-611)

Always `version = 0x20400`. `hashSize`/`hashType` are 20/1 for the primary and 32/2 for the alternate (485-486).
`pageSize = 12` (4 KiB), `nCodeSlots = codeLength/4096 + (remainder>0 ? 1 : 0)` (520-523).

**Header size is derived from the version, in steps** (525-540):

```
44                                       # base through spare2
+4   sizeof(scatterOffset)               # version >= 0x20100
+4   sizeof(teamOffset)                  # version >= 0x20200
+4   sizeof(spare3)
+8   sizeof(codeLimit64)                 # version >= 0x20300
+8   sizeof(execSegBase)
+8   sizeof(execSegLimit)
+8   sizeof(execSegFlags)                # version >= 0x20400
= 88 bytes at 0x20400
```

`identOffset = 44`? **No** — `identOffset = uHeaderLength` (557), i.e. 88 at this version.
`teamOffset = uHeaderLength + bundleIDLength` and the team string is appended right after the identifier
(567-580). `hashOffset = uHeaderLength + bundleIDLen + (+teamIDLen) + specialSlotsLen` (561-571).

**Special slots** are assembled most-negative-first (498-509), which maps exactly onto Apple's
`CSSLOT_*` numbering (`mach-o.h:468-475`: `INFOSLOT=1`, `REQUIREMENTS=2`, `RESOURCEDIR=3`,
`APPLICATION=4`, `ENTITLEMENTS=5`, `DER_ENTITLEMENTS=7`):

| array position | slot | value |
|---|---|---|
| 0 | -7 | DER entitlements hash |
| 1 | -6 | zero |
| 2 | -5 | XML entitlements hash |
| 3 | -4 | zero (`CSSLOT_APPLICATION`) |
| 4 | -3 | CodeResources hash |
| 5 | -2 | Requirements hash |
| 6 | -1 | Info.plist hash |

Leading all-zero entries are trimmed so `nSpecialSlots` stays minimal and the region remains
contiguous ending at -1 (510-518). Non-executables simply skip pushing slots -7/-6 (500-503).

**Page hashes are reused, not recomputed**, when the input is already signed and not force-signing:
existing SHA-1 and SHA-256 slot arrays are pulled out of the old signature (archo.cpp:372-378) and spliced
in if the slot count is unchanged (signing.cpp:586-587).

---

## 7. CMS construction (`openssl.cpp:361-521`) — yes, OpenSSL

1. **Chain**: prefer CA certs carried in the input p12, but only if that stack actually contains the
   leaf's issuer (`StackContainsIssuerOf`, 375-389); else select the embedded WWDR intermediate PEM by
   `X509_issuer_name_hash(leaf)` (391-401) and **fail hard** if no embedded WWDR matches (394-397).
   Then append the Apple root that issued a chain member (G3 or legacy root), skipping duplicates (403-433).
2. `CMS_sign(NULL, NULL, otherCerts, NULL, CMS_PARTIAL|CMS_DETACHED|CMS_NOSMIMECAP|CMS_BINARY)` (440-441);
   `CMS_add1_signer(..., EVP_sha256(), flags)` (446) — the SHA-1 signer line is commented out (447).
3. **Signed attribute `1.2.840.113635.100.9.1`** = the `cdhashes` XML plist (453-462).
4. **Signed attribute `1.2.840.113635.100.9.2`** = `SEQUENCE { OID sha256, OCTET STRING <32-byte hash> }`,
   hex-uppercased before wrapping (465-494).
5. `CMS_final(cms, in, NULL, flags)` where `in` is the **primary CodeDirectory blob** (435, 496) —
   detached content is the CD, not the file.
6. `i2d_CMS_bio` → DER (506); wrapped by the caller in `CSMAGIC_BLOBWRAPPER` + length (signing.cpp:735-740).

### The dual-hash coupling — read this before porting

`SlotBuildCMSSignature` (signing.cpp:670-742) encodes a rule that is easy to get wrong, and its comment
(682-700) documents a bug they already hit:

- `cdhashes` plist gets **one entry per CodeDirectory that is actually in the signature**, each value
  truncated to 20 bytes: dual mode → `[SHA1(primary), SHA256(alternate)[0..20]]`; SHA-256-only →
  `[SHA256(primary)[0..20]]` (714-722).
- `CDHashes2` gets the full SHA-256 of the alternate in dual mode, and of the **primary** in SHA-256-only
  mode (725-728).
- Emitting an entry for a CodeDirectory that is not present breaks verification with
  `errSecCSSignatureFailed` / "code or signature have been modified".

ghost-code is SHA-256-only single-CD, so if we port zsign's CMS path we must port it in the
`bHasAlternate == false` shape.

### Signature-space management

- Write path: blob is `memcpy`'d to `m_pBase + m_uCodeLength`; free space =
  `m_uLength - m_uCodeLength - blob.size`; negative → `m_bEnoughSpace=false` (archo.cpp:593-600).
  `macho.Sign` then triggers **one** `ReallocCodeSignSpace` and retries the whole sign (macho.cpp:150-158).
- `ReallocCodeSignSpace` (archo.cpp:605-664): new length = `codeLength + align(((codeLength/4096)+1)*(20+32), 4096) + 32768`
  — page-hash room plus a flat 32 KiB head start; grows `__LINKEDIT` `vmsize`/`filesize`; **creates**
  `LC_CODE_SIGNATURE` from `m_uLoadCommandsFreeSpace` if absent, bumping `ncmds`/`sizeofcmds` (636-649);
  sets `datasize = uNewLength - m_uCodeLength`, i.e. **datasize covers the whole padded tail, not the
  superblob length** (650) — so a later bigger signature fits without moving bytes.
- Fat: per-arch files written, then the container is rebuilt with `align = 2^14` and 16 KiB per-arch
  padding (macho.cpp:188-255).

---

## 8. ghost-code today, and where it diverges

Verified against the current files, not against `PROJECT.md`.

| Area | zsign | ghost-code | Sev | Evidence |
|---|---|---|---|---|
| **CD header length** | 88 B at 0x20400, derived from version | **44 B written, version claims 0x20400** | **S1** | `signing.cpp:525-540` vs `CodeDirectory.swift:82,112-125` |
| team ID in CD | `teamOffset` + `TeamIdentifier` string | no field, no offset | **S1** | `signing.cpp:567-580` vs `CodeDirectory.swift:94-109` |
| execSeg base/limit/flags | set (MAIN_BINARY, ALLOW_UNSIGNED) | no fields at all | **S1** | `archo.cpp:380-403` vs `CodeDirectory.swift:94-109` |
| SHA-1 CD + SHA-256 alternate | both, primary=SHA-1 | SHA-256 only, primary only | S2 | `archo.cpp:407-454` vs `CodeDirectory.swift:81,105` |
| Requirements blob | slot 2 emitted, real DR expression | absent; slot -2 zero-filled | S2 | `signing.cpp:141-260` vs `SuperBlobBuilder.swift:14-53` |
| CMS on iOS | OpenSSL, platform-independent | **mock ASCII blob; real path guarded `os(macOS)`** | **S1** | `CMSSigner.swift:29,41-44,73-76` |
| `cdhashes` / `CDHashes2` attrs | both emitted | not emitted at all | **S1** | `openssl.cpp:453-494` vs `CMSSigner.swift:47-77` |
| Cert chain in PKCS#7 | WWDR + root appended | leaf only, `CMSEncoderAddSigners(cert)` | **S1** | `openssl.cpp:370-433` vs `CMSSigner.swift:64` |
| EC signing key | RSA + EC via OpenSSL | `kSecAttrKeyTypeRSA` hard-coded | S2 | `CMSSigner.swift:34-37` |
| p12 input | `-k cert.p12` supported | not present (PKCS#12 parse lives in ghost-sign) | S3 | `CMSSigner.swift` (no p12 path) |
| Fat binaries | full parse + rebuild | `MH_MAGIC_64` only, fat rejected | S2 | `macho.cpp:60-92` vs `MachOWriter.swift:42` |
| Bundle traversal | recursive, deepest-first, `.app/.appex/.framework/.xctest` | one level: `Frameworks/` (`.framework`, `.dylib`) + `PlugIns/` (`.appex`) | S2 | `bundle.cpp:86-121` vs `GhostSigner.swift:227-251` |
| `.watchapp`, XPC, `Helpers/`, nested-in-framework | found | not present | S2 | `GhostSigner.swift` (no references) |
| Entitlements for non-executables | empty `<dict/>` blob | slot omitted entirely | S3 | `archo.cpp:340-342` vs `SuperBlobBuilder.swift:26-32` |
| `nSpecialSlots` when nothing present | trimmed to minimum | falls through to **7** → 224 zero bytes | S3 | `signing.cpp:510-518` vs `CodeDirectory.swift:79` |
| CodeResources rules | 5 + 10 keys, as above | 5 + 10 keys, **byte-equivalent rule sets** | — | `BundleSealer.swift:23-74` == `bundle.cpp:233-255` |
| `files` scalar/dict + omit/optional | as §4 | same (v1 SHA-1, v2 SHA-256, lproj optional, locversion/DS_Store/Info.plist/PkgInfo omitted per table) | — | `BundleSealer.swift:232-255` |
| Signature space | realloc + padded `datasize` | truncate-and-append; `datasize = blob.count` | S3 | `archo.cpp:650` vs `MachOWriter.swift:162` |
| Incremental re-sign cache | `.zsign_cache` | not present | S3 | `bundle.cpp:848-868` |
| Encrypted (`cryptid=1`) binaries | detected (`m_bEncrypted`) | not detected | S2 | `archo.cpp:90-97` |

### Corrected framing on "BlobIndex layout"

The BlobIndex **arithmetic is correct** and I want that on the record rather than implied:
`build(entries:)` uses a 12-byte `CS_SuperBlob` (magic+length+count) and 8-byte
`{type, offset}` indexes, and offsets accumulate correctly with a 4-byte-aligned start
(`SuperBlobBuilder.swift:55-81`). Nothing there is wrong.

What is wrong is **which indexes exist and what the blobs they point at contain**:

1. Only 4 index types are ever emitted (0, 5, 7, 0x10000) — no Requirements (2), no alternate CD
   (0x1000). zsign emits up to 6, chosen by which blobs are non-empty (`archo.cpp:471-477`).
2. The blob the index at slot 0 points to is structurally invalid (§9.1), so correct indexes
   describe a bad blob.
3. `totalLength` (`SuperBlobBuilder.swift:72-76`) is the sum of whatever was appended, so once the CD
   grows (fix 9.1) the indexes still follow correctly — this is not a place the fix has to touch.
4. Because blobs are concatenated with no per-blob 4-byte padding, an unaligned CD length pushes every
   later index onto an unaligned offset. Trigger: `identifier.count % 4 != 3`, since
   `CD_len = 44 + (id+1) + 32*k`. Most Apple signatures pad the identifier so the hash region stays
   aligned; zsign does not either, so this is S3 — but we are rewriting the CD anyway and should fix it
   while there.

---

## 9. Proposed fixes (not applied)

### 9.1 S1: write a real 0x20400 CodeDirectory header

`CodeDirectory.swift` currently serializes 15 fields = 44 bytes and sets `identOffset = 44`
(`:82,84,112-125`). A verifier sizes the header from `version`, so it reads `scatterOffset`,
`teamOffset`, `spare3`, `codeLimit64`, `execSegBase`, `execSegLimit`, `execSegFlags` from bytes 44..87 —
which in our blob are the **bundle-identifier ASCII**. For `com.lekhanh.omnistore` that yields
`teamOffset ≈ 0x63206d6f`, i.e. out-of-range, and the CD's own `length`/`hashOffset` are 44 bytes short
of where the parser expects the hash region. Fix, mirroring `signing.cpp:525-540`:

```swift
// CodeDirectory.swift — inside build(...)
let version: UInt32 = 0x20400
var headerSize = 44
headerSize += 4            // scatterOffset  (>= 0x20100)
headerSize += teamID.isEmpty ? 0 : 4   // teamOffset     (>= 0x20200, only if team present)
headerSize += 4 + 8        // spare3 + codeLimit64 (>= 0x20300)
headerSize += 8 + 8 + 8    // execSegBase/Limit/Flags (>= 0x20400)

let identOffset = headerSize
let teamOffset  = teamID.isEmpty ? 0 : identOffset + identifier.bytes.count + 1
let hashOffset  = identOffset + identifier.bytes.count + 1
                  + (teamID.isEmpty ? 0 : teamID.bytes.count + 1)
                  + Int(nSpecialSlots) * hashSize
```

and append the new fields in Apple's order (`scatterOffset, teamOffset, spare3, codeLimit64,
execSegBase, execSegLimit, execSegFlags`), all big-endian, after `spare2`. `CodeDirectory`
(`CodeDirectory.swift:7-55`) needs those stored properties, `build(...)` gains `teamID: String?`,
`execSegLimit: UInt64`, `execSegFlags: UInt64`, and `signBundle` must supply the team ID from the profile
(already parsed by `GhostSigner.extractEntitlements(fromMobileProvisionData:)`, `:274` — extend it to also
return `TeamIdentifier[0]`, mirroring `openssl.cpp:864`).

`execSegFlags` per `archo.cpp:380-403`: `CS_EXECSEG_MAIN_BINARY` for `MH_EXECUTE` only;
`CS_EXECSEG_ALLOW_UNSIGNED` only when `get-task-allow` is *true* (string-test on the XML plist is
acceptable and matches zsign). `execSegLimit` = `__TEXT` `vmsize` — note zsign stores it in a
**static** (`archo.cpp:6`, `54`) which leaks across arches and files; we must read it per-arch from
`MachOReader`'s segment table instead of copying that detail.

Also: `flags = isAdHoc ? 0x20002 : 0x20000` (`CodeDirectory.swift:98`) sets
`CS_GET_TASK_ALLOW` alongside `CS_ADHOC` for ad-hoc. Keep `0x2` only for debug/entitlement-backed
signing, not merely because it is ad-hoc — the profile's `get-task-allow` should decide, same as
`execSegFlags`.

### 9.2 S1: build the PKCS#7 by hand (there is no CMS encoder on iOS)

`CMSSigner.swift` gates the entire real implementation behind `#if canImport(Security) && os(macOS)`
and returns `mockDetachedCMS` otherwise — `"CMS_DETACHED_SIGNATURE" + SHA-256(data)` (`:79-84`), an
ASCII string, not DER. On iOS that is what every OmniStore signature contains today. Before assuming
`CMSEncoder*` is even linkable in the iOS SDK, note that the guard itself is the answer: it was added
because it is not.

Propose `CodeSigning/PKCS7Builder.swift`, DER-only, using what ghost-code already has (`DEREncoder.swift`,
`CryptoHelpers.swift`) plus swift-crypto for ECDSA/RSA primitives:

- `ContentInfo{ contentType: signedData, [0] EncryptedContent-info{ version, digestAlgorithms{sha256},
  encapContentInfo{ eContent: absent (detached) }, signerInfos:[...] } }`
- `SignerInfo.version = 3`, `sid = issuerAndSerialNumber`, `digestAlgorithm = sha256`,
  `signedAttrs`, `signatureAlgorithm`, `signature`. Oracle-verified quirk: OpenSSL fills
  `signatureAlgorithm` from the certificate's SPKI algorithm, so zsign emits `rsaEncryption` +
  NULL for RSA keys (not `sha256WithRSAEncryption`) and `ecdsa-with-SHA256` with no parameters
  for EC keys; Apple's verifier accepts both, and ghost-code mirrors zsign byte-for-byte.
- **Signed attrs** — the two Apple needs, mirroring `openssl.cpp:453-494`:
  - `1.2.840.113635.100.9.1` SET OF one: the `cdhashes` XML plist.
  - `1.2.840.113635.100.9.2` SET OF one: `SEQUENCE { OID(sha256), OCTET STRING(32) }`.
  - plus `content-type`, `message-digest`, and `signing-time` for Apple fidelity.
- The `signedAttrs` DER must be re-encoded as `SET OF` with tag `0x31` before hashing (the classic
  `CMS_SIGNERINFO` tag-substitution bug: sign over `0x31`, emit as `0xa0`).
- Chain: leaf + WWDR intermediate + Apple root, selected by the leaf's issuer. ghost-code has no
  embedded WWDR; either bundle the PEMs (as zsign does, `openssl.cpp:406`) or take the chain from the
  p12 that ghost-sign fetches — its `PKCS12Parser.extract` (`ghost-sign/Sources/GhostSign/Certificates/PKCS12Parser.swift`)
  already returns cert+key, and we should extend it to return the **additional CA bags** rather than
  discarding them. This mirrors zsign's preference order (`openssl.cpp:375-401`).

Keep the Security.framework path for macOS CLI use, but it must add `CMSEncoderAddCertificates` for the
chain and the two signed attributes; today it adds neither.

### 9.3 S1: `cdhashes` must describe the CDs that actually exist

Per §7's coupling rule. If we stay SHA-256-only (one CD): `cdhashes` has exactly **one** 20-byte entry
(SHA-256 of the CD, truncated) and `CDHashes2` carries SHA-256 of **that same primary** CD
(`signing.cpp:720-728`). If we add the SHA-1 primary + SHA-256 alternate (the Apple-default shape, and what
older iOS verifiers expect): `cdhashes = [SHA1(primary), SHA256(alt)[0..20]]` and `CDHashes2 = SHA256(alt)`,
and `SuperBlobBuilder` gains a slot `0x1000` entry. I recommend dual-hash, because truncating our only CD's
SHA-256 to a 20-byte "cdhash" is the less-tested path on real devices.

### 9.4 S2: traversal parity

Replace the one-level scan in `GhostSigner.signBundle` (`:227-251`) with a zsign-style two-phase design:

- **Discover** all bundle dirs recursively (`.app`, `.appex`, `.framework`, `.xctest`, `.dSYM` skipped)
  using `FileManager.enumerator`, then sort by path depth descending. Use `sorted(by:)` on the array
  (Swift's `sort` is not stable either) — or, better, tie-break on the path string so a re-sign is
  byte-reproducible; zsign's non-stable `std::sort` gives arbitrary sibling order (§3).
- Sign each bundle node bottom-up; each node seals its own `CodeResources` and then signs its own
  executable. Do **not** copy the parallel "all Mach-O files" list that causes the double-sign (§3).
- Write the matching `embedded.mobileprovision` into each bundle **before** sealing it (§5, the
  `bundle.cpp:406-409` constraint). With one profile this is the root only; when we later support
  per-appex profiles, use zsign's `application-identifier` suffix match (`:410-425`).
- Add `Helpers/`, `Watch/`, XPC `.xpc` handling; for macOS-style frameworks either support
  `Versions/A` or fail loudly.

### 9.5 S2: fat binaries

`MachOWriter` refuses anything but `MH_MAGIC_64` (`:42`). Follow `macho.cpp:60-92`: detect
`FAT_MAGIC`/`FAT_CIGAM`, split arches, sign each, and rebuild the container at 16 KiB alignment
(`:188-255`). Since ghost-code always truncates-and-appends rather than reallocating, per-arch
growing means rewriting the fat table — the zsign approach is the reference for that.

### 9.6 S3: small fidelity items

- `nSpecialSlots` fall-through should be `0` when nothing is present, not `7` (`CodeDirectory.swift:79`),
  and the ladder should be built by the most-negative-populated rule from `signing.cpp:510-518`.
- Add slot -2 (Requirements) to the CD only once we emit the Requirements blob (9.7).
- Pad the identifier so the hash region is 4-byte aligned (see §8, "BlobIndex layout" item 4).
- Non-executable Mach-O: emit the empty `<dict/>` entitlements blob like `archo.cpp:340-342`.
- Detect `LC_ENCRYPTION_INFO.cryptid >= 1` and refuse with a clear error (App Store-thinned binaries
  cannot be re-signed this way) rather than producing a broken seal.
- `getBaseBinarySize` (`GhostSigner.swift:290-328`) assumes a 64-bit LE header; add a magic check.
- Force-unwraps to remove (our own rule 3): `MachOWriter.swift:83`, `CMSSigner.swift:59`,
  `DEREncoder.swift:96,98`.

### 9.7 New module: Requirements blob

`SuperBlobBuilder.build(codeDirectory:...)` has no requirements parameter (`:14-19`). Add a
`RequirementsBuilder` emitting `opIdent / opAnd / opAppleGenericAnchor / opCertField(leaf,
"subject.CN", matchEqual, cn) / opCertGeneric(1, 1.2.840.113635.100.6.2.1, exists)` exactly as
`signing.cpp:141-260`, and the empty-vector form (`magic,12,0`) when we have no CN — the
`bundle.cpp` ad-hoc/no-cert paths depend on that branch existing.

---

## 10. What I recommend we do **not** port from zsign

- **`ReallocCodeSignSpace`** (`archo.cpp:605-664`). It exists because zsign writes in-place into an
  `mmap`'d file and must grow `__LINKEDIT` when the signature outgrows the old slot. ghost-code
  rebuilds the tail in memory (`MachOWriter.swift:133-143`), so the whole realloc dance — plus its
  fat-table rewriting — is dead weight. We lose zsign's "leave 32 KiB slack so the next re-sign is cheap"
  optimization; accept that, or emulate it by padding `datasize` to `blob.count` rounded up, without
  touching segment vmsize arithmetic.
- **`.zsign_cache`** (`bundle.cpp:848-889`): keyed on the SHA-1 of the *absolute folder path*, so it is
  per-machine and unsafe to ship inside an app; the incremental patch path is where §3's rule-skipping
  bug lives.
- **App-icon replacement, `ChangeAppIcon`, document-browser / `MinimumOSVersion` /
  `UISupportedDevices` / `--remove-extensions` mutations**: those are re-package features, not signing,
  and each one silently invalidates the seal if done in the wrong order.
- **dylib injection / `RemoveDylibs`** (`archo.cpp:666-760`): out of scope for `ghost-code`'s contract.
- **The static `s_uExecSegLimit`** (`archo.cpp:6`) — a cross-file leak, see 9.1.
- **OpenSSL itself**: obviously not, in a zero-dependency Swift package.

---

## 11. Verification plan (what we cannot do here)

Nothing in this codespace can validate a signature: no `codesign`, no Xcode, no iOS SDK, and
`swift build` only proves it compiles. So "exit code 0" is **not** evidence 9.1/9.2 are right. Proposed:

1. **Golden-blob diffing on a macOS runner**: for a fixed dummy bundle, run Apple `codesign` and zsign,
   dump slots with `zsign -p` / `codesign -d --xml`, and assert our `CodeDirectory` bytes match field for
   field. The one property that catches 9.1 immediately is: parse our own CD back out and require
   `hashOffset == headerSize + identLen + teamLen + nSpecialSlots*32` with `headerSize` derived from
   `version`.
2. **Oracle test against zsign** in this Linux codespace: build zsign here (it vendors OpenSSL
   (`src/third-party/`), so `make` should work), sign `Tests/`'s dummy app with a fixed key, and byte-compare
   our superblob against its `CodeSignature.blob.new` debug output (`archo.cpp:550-560`). This gives real
   differential evidence without a Mac.
3. **Unit tests for the coupling rule in 9.3**: one CD → one `cdhashes` entry; two CDs → two; and
   `CDHashes2` must equal SHA-256 of the alternate when present, of the primary when not.
4. **Device test last**, via OmniStore's minimuxer path, and treat `0xe8008018` / `errSecCSSignatureFailed`
   as the specific signatures of a 9.1/9.2/9.3 regression.

## 12. Open questions for your review

1. Dual-hash (SHA-1 primary + SHA-256 alternate, Apple's default) or stay SHA-256-only? Recommendation:
   dual — 9.3.
2. Where does the WWDR intermediate come from: embed PEMs in `ghost-code` (breaks "zero-dependency" in
   spirit, ~2 KB) or require ghost-sign to hand over the full chain it fetched? Recommendation: the latter.
3. Is the `get-task-allow`/`ALLOW_UNSIGNED` policy "read the profile" (zsign's) or "caller passes a flag"?
   Reading it is safer against `0xe8008018` on distribution profiles.
4. Do we need macOS `Versions/A` framework support, or iOS-only with a loud failure?

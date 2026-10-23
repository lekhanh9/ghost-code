import XCTest
@testable import GhostCode

final class CodeDirectoryTests: XCTestCase {
    func testNativeSHA256StandardVectors() {
        // Test vector: empty string
        let emptyHash = NativeSHA256.hash(Data())
        let emptyHex = emptyHash.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(emptyHex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        // Test vector: "abc"
        let abcHash = NativeSHA256.hash(Data("abc".utf8))
        let abcHex = abcHash.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(abcHex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    func testCodeDirectoryWithSpecialSlotMinus7() throws {
        let dummyBinary = Data(repeating: 0x90, count: 8192) // 2 pages
        let derBlob = CodeSigningSlot.derEntitlements(Data([0x70, 0x03, 0x02, 0x01, 0x01]))
        let xmlBlob = CodeSigningSlot.xmlEntitlements(Data("<plist></plist>".utf8))

        let cdData = CodeDirectoryBuilder.build(
            binaryData: dummyBinary,
            codeLimit: 8192,
            identifier: "com.example.test",
            xmlEntitlementsBlob: xmlBlob,
            derEntitlementsBlob: derBlob
        )

        // Read CodeDirectory header
        let magic = UInt32(bigEndian: cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) })
        let length = UInt32(bigEndian: cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self) })
        let hashOffset = UInt32(bigEndian: cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self) })
        let nSpecialSlots = UInt32(bigEndian: cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 24, as: UInt32.self) })
        let nCodeSlots = UInt32(bigEndian: cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 28, as: UInt32.self) })

        XCTAssertEqual(magic, MachOConstants.CSMAGIC_CODEDIRECTORY)
        XCTAssertEqual(length, UInt32(cdData.count))
        XCTAssertEqual(nSpecialSlots, 7)
        XCTAssertEqual(nCodeSlots, 2)

        // Verify Slot -7 (DER hash)
        // Offset in cdData: hashOffset - (7 * 32)
        let slot7Offset = Int(hashOffset) - (7 * 32)
        let slot7Hash = cdData.subdata(in: slot7Offset..<(slot7Offset + 32))
        XCTAssertEqual(slot7Hash, CodeDirectoryBuilder.sha256(derBlob))

        // Verify Slot -5 (XML hash)
        let slot5Offset = Int(hashOffset) - (5 * 32)
        let slot5Hash = cdData.subdata(in: slot5Offset..<(slot5Offset + 32))
        XCTAssertEqual(slot5Hash, CodeDirectoryBuilder.sha256(xmlBlob))

        // Verify Code Slot 0
        let codeSlot0 = cdData.subdata(in: Int(hashOffset)..<(Int(hashOffset) + 32))
        let expectedPage0Hash = CodeDirectoryBuilder.sha256(dummyBinary.subdata(in: 0..<4096))
        XCTAssertEqual(codeSlot0, expectedPage0Hash)
    }

    func testSpecialSlotsHashTheWholeBlobNotJustThePayload() {
        // Hashing the payload alone is the bug that makes Apple reject the entitlements slot.
        let xmlBlob = CodeSigningSlot.xmlEntitlements(Data("<plist></plist>".utf8))
        let cd = CodeDirectoryBuilder.build(
            binaryData: Data(repeating: 0, count: 4096),
            codeLimit: 4096,
            identifier: "com.example.test",
            xmlEntitlementsBlob: xmlBlob
        )
        let hashOffset = Int(bigEndian32(cd, at: 16))
        // Unused more-negative slots are trimmed, so slot -5 is the first of the kept window.
        let slot5 = cd.subdata(in: (hashOffset - 5 * 32)..<(hashOffset - 4 * 32))
        XCTAssertEqual(slot5, CodeDirectoryBuilder.sha256(xmlBlob))
        XCTAssertNotEqual(slot5, CodeDirectoryBuilder.sha256(Data("<plist></plist>".utf8)))
    }

    func testSHA1DirectoryHashesEverySlotWithSHA1() {
        let binary = Data(repeating: 0x90, count: 8192)
        let xmlBlob = CodeSigningSlot.xmlEntitlements(Data("<plist></plist>".utf8))
        let cd = CodeDirectoryBuilder.build(
            binaryData: binary,
            codeLimit: 8192,
            identifier: "com.example.test",
            xmlEntitlementsBlob: xmlBlob,
            hash: .sha1
        )

        XCTAssertEqual(cd[37], 1, "hashType must be CS_HASHTYPE_SHA1")
        XCTAssertEqual(cd[36], 20, "hashSize must be 20")

        let hashOffset = Int(bigEndian32(cd, at: 16))
        let nSpecialSlots = Int(bigEndian32(cd, at: 24))
        XCTAssertEqual(nSpecialSlots, 5)
        XCTAssertEqual(bigEndian32(cd, at: 28), 2, "nCodeSlots")
        XCTAssertEqual(UInt32(cd.count), UInt32(hashOffset + 2 * 20), "length accounts for 20-byte slots")

        // Unused more-negative slots are trimmed, so slot -5 is the first of the kept window.
        let slot5 = cd.subdata(in: (hashOffset - 5 * 20)..<(hashOffset - 4 * 20))
        XCTAssertEqual(slot5, CryptoHelpers.sha1(xmlBlob))
        XCTAssertEqual(
            cd.subdata(in: hashOffset..<(hashOffset + 20)),
            CryptoHelpers.sha1(binary.subdata(in: 0..<4096))
        )
    }

    func testSHA1AndSHA256DirectoriesDifferOnlyInHashesAndHeader() {
        let binary = Data(repeating: 0x90, count: 8192)
        let sha1CD = CodeDirectoryBuilder.build(
            binaryData: binary, codeLimit: 8192,
            identifier: "com.example.test", teamID: "ABCDE12345", hash: .sha1
        )
        let sha256CD = CodeDirectoryBuilder.build(
            binaryData: binary, codeLimit: 8192,
            identifier: "com.example.test", teamID: "ABCDE12345", hash: .sha256
        )
        XCTAssertEqual(bigEndian32(sha1CD, at: 20), bigEndian32(sha256CD, at: 20), "identOffset")
        XCTAssertEqual(bigEndian32(sha1CD, at: 48), bigEndian32(sha256CD, at: 48), "teamOffset")
        XCTAssertLessThan(sha1CD.count, sha256CD.count)
    }

    // MARK: - 0x20400 header layout

    private func bigEndian32(_ data: Data, at offset: Int) -> UInt32 {
        data.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self)) }
    }

    private func bigEndian64(_ data: Data, at offset: Int) -> UInt64 {
        data.withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self)) }
    }

    private func buildCD(
        identifier: String = "com.example.test",
        teamID: String? = nil,
        xml: Data? = nil,
        der: Data? = nil,
        infoPlist: Data? = nil,
        resourceDir: Data? = nil,
        execSegLimit: UInt64 = 0,
        isExecutableImage: Bool = false,
        getTaskAllow: Bool = false,
        isAdHoc: Bool = true,
        hash: CodeDirectoryHash = .sha256
    ) -> Data {
        CodeDirectoryBuilder.build(
            binaryData: Data(repeating: 0x90, count: 8192),
            codeLimit: 8192,
            identifier: identifier,
            xmlEntitlementsBlob: xml.map { CodeSigningSlot.blob(magic: GhostCodeConstants.CodeSigning.CSMAGIC_EMBEDDED_ENTITLEMENTS, payload: $0) },
            derEntitlementsBlob: der.map { CodeSigningSlot.blob(magic: GhostCodeConstants.CodeSigning.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, payload: $0) },
            infoPlistData: infoPlist,
            resourceDirData: resourceDir,
            teamID: teamID,
            execSegLimit: execSegLimit,
            isExecutableImage: isExecutableImage,
            getTaskAllow: getTaskAllow,
            isAdHoc: isAdHoc,
            hash: hash
        )
    }

    func testHeaderLengthIsVersionGated() {
        XCTAssertEqual(CodeDirectory.headerLength(version: 0x20000), 44)
        XCTAssertEqual(CodeDirectory.headerLength(version: 0x20100), 48)
        XCTAssertEqual(CodeDirectory.headerLength(version: 0x20200), 52)
        XCTAssertEqual(CodeDirectory.headerLength(version: 0x20300), 64)
        XCTAssertEqual(CodeDirectory.headerLength(version: 0x20400), 88)
    }

    func testIdentOffsetFollowsFull88ByteHeader() {
        let cd = buildCD(xml: Data("<plist></plist>".utf8), der: Data([0x30, 0x05, 0x01, 0x01, 0xFF]))

        XCTAssertEqual(bigEndian32(cd, at: 8), 0x20400, "version")
        XCTAssertEqual(bigEndian32(cd, at: 20), 88, "identOffset must sit past every version-gated field")
        XCTAssertEqual(bigEndian32(cd, at: 48), 0, "teamOffset stays zero without a team")
        XCTAssertEqual(bigEndian64(cd, at: 56), 0, "codeLimit64")
        XCTAssertEqual(bigEndian32(cd, at: 52), 0, "spare3")

        // Identifier is the 17 bytes starting at 88 ("com.example.test" + NUL)
        XCTAssertEqual(String(decoding: cd.subdata(in: 88..<104), as: UTF8.self), "com.example.test")
        XCTAssertEqual(cd[104], 0)

        let nSpecialSlots = bigEndian32(cd, at: 24)
        XCTAssertEqual(bigEndian32(cd, at: 16), 88 + 17 + nSpecialSlots * 32, "hashOffset")
        XCTAssertEqual(bigEndian32(cd, at: 4), UInt32(cd.count), "length must cover the whole blob")
    }

    func testTeamStringIsWrittenBetweenIdentifierAndSlots() {
        let cd = buildCD(teamID: "ABCDE12345", xml: Data("<plist></plist>".utf8))

        let identOffset = bigEndian32(cd, at: 20)
        let teamOffset = bigEndian32(cd, at: 48)
        XCTAssertEqual(teamOffset, identOffset + 17, "team string starts right after the NUL-terminated identifier")

        let teamBytes = cd.subdata(in: Int(teamOffset)..<(Int(teamOffset) + 11))
        XCTAssertEqual(String(decoding: teamBytes.prefix(10), as: UTF8.self), "ABCDE12345")
        XCTAssertEqual(teamBytes[10], 0)

        XCTAssertEqual(bigEndian32(cd, at: 16), teamOffset + 11 + bigEndian32(cd, at: 24) * 32, "hashOffset skips the team string")
    }

    func testUnusedSpecialSlotsAreTrimmedFromTheFront() {
        // Only Info.plist (-1): six more-negative slots are unused, so nSpecialSlots collapses to 1.
        let plistOnly = buildCD(infoPlist: Data("plist".utf8))
        XCTAssertEqual(bigEndian32(plistOnly, at: 24), 1)
        let plistSlot = plistOnly.subdata(in: Int(bigEndian32(plistOnly, at: 16) - 32)..<Int(bigEndian32(plistOnly, at: 16)))
        XCTAssertEqual(plistSlot, CodeDirectoryBuilder.sha256(Data("plist".utf8)))

        // XML entitlements (-5) plus the reserved -6/-4 gaps: 5 slots kept.
        let xmlOnly = buildCD(xml: Data("<plist></plist>".utf8))
        XCTAssertEqual(bigEndian32(xmlOnly, at: 24), 5)

        // DER entitlements (-7) pins the full window even though -6..-1 are empty.
        let derOnly = buildCD(der: Data([0x30, 0x05, 0x01, 0x01, 0xFF]))
        XCTAssertEqual(bigEndian32(derOnly, at: 24), 7)

        // Nothing sealed at all: no special slot region.
        let bare = buildCD()
        XCTAssertEqual(bigEndian32(bare, at: 24), 0)
        XCTAssertEqual(bigEndian32(bare, at: 16), 88 + 17)
    }

    func testExecSegFieldsRoundTrip() {
        let cd = buildCD(teamID: "ABCDE12345", execSegLimit: 0x4000, isExecutableImage: true, getTaskAllow: true)

        XCTAssertEqual(bigEndian64(cd, at: 64), 0, "execSegBase")
        XCTAssertEqual(bigEndian64(cd, at: 72), 0x4000, "execSegLimit")
        XCTAssertEqual(
            bigEndian64(cd, at: 80),
            GhostCodeConstants.CodeSigning.CS_EXECSEG_MAIN_BINARY | GhostCodeConstants.CodeSigning.CS_EXECSEG_ALLOW_UNSIGNED
        )
        XCTAssertEqual(
            bigEndian32(cd, at: 12) & GhostCodeConstants.CodeSigning.CS_GET_TASK_ALLOW,
            GhostCodeConstants.CodeSigning.CS_GET_TASK_ALLOW
        )
    }

    func testFlagsOnlyClaimWhatIsActuallySigned() {
        XCTAssertEqual(bigEndian32(buildCD(), at: 12), GhostCodeConstants.CodeSigning.CS_ADHOC)

        let adHocWithEntitlements = buildCD(xml: Data("<plist></plist>".utf8))
        XCTAssertEqual(
            bigEndian32(adHocWithEntitlements, at: 12),
            GhostCodeConstants.CodeSigning.CS_ENTITLEMENTS_VALIDATED | GhostCodeConstants.CodeSigning.CS_ADHOC
        )

        let realSignatureWithTaskAllow = buildCD(xml: Data("<plist></plist>".utf8), getTaskAllow: true, isAdHoc: false)
        XCTAssertEqual(
            bigEndian32(realSignatureWithTaskAllow, at: 12),
            GhostCodeConstants.CodeSigning.CS_ENTITLEMENTS_VALIDATED | GhostCodeConstants.CodeSigning.CS_GET_TASK_ALLOW
        )
    }

    func testDistributionProfileKeepsGetTaskAllowClear() {
        let cd = buildCD(xml: Data("<plist></plist>".utf8), getTaskAllow: false)
        XCTAssertEqual(bigEndian32(cd, at: 12) & GhostCodeConstants.CodeSigning.CS_GET_TASK_ALLOW, 0)
        XCTAssertEqual(bigEndian64(cd, at: 80) & GhostCodeConstants.CodeSigning.CS_EXECSEG_ALLOW_UNSIGNED, 0)
    }

    func testCodeSlotsStartAtDeclaredHashOffset() {
        let binary = Data(repeating: 0x90, count: 8192)
        let cd = CodeDirectoryBuilder.build(
            binaryData: binary,
            codeLimit: 8192,
            identifier: "com.example.a",
            teamID: "TEAM"
        )
        let hashOffset = Int(bigEndian32(cd, at: 16))
        XCTAssertEqual(bigEndian32(cd, at: 28), 2, "nCodeSlots")
        XCTAssertEqual(cd.subdata(in: hashOffset..<(hashOffset + 32)), CodeDirectoryBuilder.sha256(binary.subdata(in: 0..<4096)))
        let lastPage = binary.subdata(in: 4096..<8192)
        XCTAssertEqual(cd.subdata(in: (hashOffset + 32)..<(hashOffset + 64)), CodeDirectoryBuilder.sha256(lastPage))
    }
}

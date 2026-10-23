import XCTest
@testable import GhostCode

private struct MissingCodeDirectoryError: Error {}

final class GhostSignerTests: XCTestCase {
    private func createMockBinary() -> Data {
        var data = Data()
        var header = MachHeader64(
            magic: MachOConstants.MH_MAGIC_64,
            cpuType: 0x0100000c, // ARM64
            cpuSubtype: 0,
            fileType: 2,         // MH_EXECUTE
            ncmds: 2,
            sizeofcmds: 144,
            flags: 0x00200085,
            reserved: 0
        )

        withUnsafeBytes(of: &header.magic) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.cpuType) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.cpuSubtype) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.fileType) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.ncmds) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.sizeofcmds) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.flags) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.reserved) { data.append(contentsOf: $0) }

        // Segment 1: __TEXT
        appendSegment(name: "__TEXT", fileoff: 0, filesize: 4096, vmsize: 4096, to: &data)
        // Segment 2: __LINKEDIT
        appendSegment(name: "__LINKEDIT", fileoff: 4096, filesize: 0, vmsize: 4096, to: &data)

        // Pad up to 4096 bytes
        if data.count < 4096 {
            data.append(Data(repeating: 0, count: 4096 - data.count))
        }

        return data
    }

    private func appendSegment(name: String, fileoff: UInt64, filesize: UInt64, vmsize: UInt64, to data: inout Data) {
        var cmd = MachOConstants.LC_SEGMENT_64
        var cmdsize: UInt32 = 72
        withUnsafeBytes(of: &cmd) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &cmdsize) { data.append(contentsOf: $0) }

        var nameBytes = [UInt8](repeating: 0, count: 16)
        let utf8 = Array(name.utf8.prefix(16))
        for (i, b) in utf8.enumerated() { nameBytes[i] = b }
        data.append(contentsOf: nameBytes)

        var vmaddr: UInt64 = 0x100000000
        var vmSize = vmsize
        var fileOff = fileoff
        var fileSize = filesize
        var maxprot: Int32 = 7
        var initprot: Int32 = 5
        var nsects: UInt32 = 0
        var flags: UInt32 = 0

        withUnsafeBytes(of: &vmaddr) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &vmSize) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &fileOff) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &fileSize) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &maxprot) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &initprot) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &nsects) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &flags) { data.append(contentsOf: $0) }
    }

    func testSignBinaryWithEntitlementsContainsSlotMinus7() throws {
        let binaryData = createMockBinary()
        let tempDir = FileManager.default.temporaryDirectory
        let inputURL = tempDir.appendingPathComponent("unsigned_\(UUID().uuidString).bin")
        let outputURL = tempDir.appendingPathComponent("signed_\(UUID().uuidString).bin")

        try binaryData.write(to: inputURL)
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let entitlements: [String: Any] = [
            "get-task-allow": true,
            "application-identifier": "TEAM123.com.example.app"
        ]

        let signer = GhostSigner()
        try signer.sign(binaryURL: inputURL, entitlements: entitlements, outputURL: outputURL)

        // Read signed binary
        let reader = try MachOReader(contentsOf: outputURL)
        let sigCmd = try XCTUnwrap(reader.codeSignatureCommand)
        XCTAssertEqual(sigCmd.cmd, MachOConstants.LC_CODE_SIGNATURE)
        XCTAssertGreaterThan(sigCmd.datasize, 0)

        // Read SuperBlob
        let signedData = try Data(contentsOf: outputURL)
        let superBlobOffset = Int(sigCmd.dataoff)
        let superBlob = signedData.subdata(in: superBlobOffset..<(superBlobOffset + Int(sigCmd.datasize)))

        // Verify SuperBlob header
        let magic = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) })
        let totalLength = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self) })
        let count = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt32.self) })

        XCTAssertEqual(magic, MachOConstants.CSMAGIC_EMBEDDED_SIGNATURE)
        XCTAssertEqual(totalLength, UInt32(superBlob.count))
        XCTAssertGreaterThanOrEqual(count, 2) // CodeDirectory + DER (and optional XML)

        // Search for Slot 7 (CSSLOT_DER_ENTITLEMENTS)
        var foundSlot7 = false
        var derBlobOffset: Int?

        for i in 0..<Int(count) {
            let entryOffset = 12 + i * 8
            let slotType = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entryOffset, as: UInt32.self) })
            let blobOffset = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entryOffset + 4, as: UInt32.self) })

            if slotType == MachOConstants.CSSLOT_DER_ENTITLEMENTS {
                foundSlot7 = true
                derBlobOffset = Int(blobOffset)
            }
        }

        // Verify Slot 7 was found in SuperBlob
        XCTAssertTrue(foundSlot7, "SuperBlob must contain a BlobIndex for CSSLOT_DER_ENTITLEMENTS (Slot 7)")
        let offset = try XCTUnwrap(derBlobOffset)

        // Check DER Blob Header: magic 0xfade7172
        let derMagic = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) })
        XCTAssertEqual(derMagic, MachOConstants.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS)
    }

    func testSignInPlace() throws {
        let binaryData = createMockBinary()
        let tempDir = FileManager.default.temporaryDirectory
        let fileURL = tempDir.appendingPathComponent("inplace_\(UUID().uuidString).bin")

        try binaryData.write(to: fileURL)
        defer {
            try? FileManager.default.removeItem(at: fileURL)
        }

        try GhostSigner.sign(binaryURL: fileURL, entitlements: ["get-task-allow": false])

        let reader = try MachOReader(contentsOf: fileURL)
        XCTAssertNotNil(reader.codeSignatureCommand)
    }

    func testSignBundleEndToEnd() throws {
        let tempDir = FileManager.default.temporaryDirectory
        let appDir = tempDir.appendingPathComponent("TestApp_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: appDir) }

        // Create Info.plist
        let infoPlist: [String: Any] = [
            "CFBundleExecutable": "TestApp",
            "CFBundleIdentifier": "com.ghostcode.testapp",
            "CFBundleVersion": "1.0"
        ]
        let infoData = try PropertyListSerialization.data(fromPropertyList: infoPlist, format: .xml, options: 0)
        try infoData.write(to: appDir.appendingPathComponent("Info.plist"))

        // Create main executable
        let exeData = createMockBinary()
        try exeData.write(to: appDir.appendingPathComponent("TestApp"))

        // Create dummy resource
        try Data("Hello world".utf8).write(to: appDir.appendingPathComponent("resource.txt"))

        // Sign the bundle with certificate & key (triggers CMS signing)
        let signer = GhostSigner()
        try signer.signBundle(
            appURL: appDir,
            cert: SecCertificate(),
            key: SecKey(),
            entitlements: ["get-task-allow": true]
        )

        // Check _CodeSignature/CodeResources was created
        let codeResourcesURL = appDir.appendingPathComponent("_CodeSignature/CodeResources")
        XCTAssertTrue(FileManager.default.fileExists(atPath: codeResourcesURL.path))

        // Check main executable was signed with signature command and slot 0x10000
        let reader = try MachOReader(contentsOf: appDir.appendingPathComponent("TestApp"))
        let sigCmd = try XCTUnwrap(reader.codeSignatureCommand)
        XCTAssertGreaterThan(sigCmd.datasize, 0)
    }

    func testExtractEntitlementsValidXML() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>AppIDName</key>
            <string>TestApp</string>
            <key>Entitlements</key>
            <dict>
                <key>application-identifier</key>
                <string>TESTTEAM123.com.ghostcode.testapp</string>
                <key>get-task-allow</key>
                <true/>
                <key>com.apple.developer.team-identifier</key>
                <string>TESTTEAM123</string>
            </dict>
        </dict>
        </plist>
        """
        var mockProfileData = Data([0x30, 0x82, 0x05, 0x10, 0x06, 0x09])
        mockProfileData.append(Data(xml.utf8))
        mockProfileData.append(Data([0x00, 0x01, 0x02, 0x03]))

        let entitlements = GhostSigner.extractEntitlements(fromMobileProvisionData: mockProfileData)
        XCTAssertNotNil(entitlements)
        XCTAssertEqual(entitlements?["application-identifier"] as? String, "TESTTEAM123.com.ghostcode.testapp")
        XCTAssertEqual(entitlements?["get-task-allow"] as? Bool, true)
        XCTAssertEqual(entitlements?["com.apple.developer.team-identifier"] as? String, "TESTTEAM123")
    }

    func testExtractEntitlementsMalformedOrReversed() {
        // Reversed tags must cleanly return nil without crash
        let reversedData = Data("</plist> some text <plist>".utf8)
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: reversedData))

        let onlyClosing = Data("</plist>".utf8)
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: onlyClosing))

        let onlyOpening = Data("<plist>".utf8)
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: onlyOpening))

        let emptyData = Data()
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: emptyData))

        let garbageData = Data([0x00, 0xff, 0xee, 0xdd])
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: garbageData))
    }

    func testExtractEntitlementsAdversarialStressFuzzing() {
        // 1. Exact boundary: </plist><plist>
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: Data("</plist><plist>".utf8)))

        // 2. Exact boundary with reversed uppercase/lowercase
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: Data("</PLIST><plist>".utf8)))
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: Data("</plist><PLIST>".utf8)))

        // 3. Nested tags and multiple closing tags
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: Data("<plist><plist></plist></plist>".utf8)))
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: Data("</plist></plist></plist>".utf8)))
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: Data("<plist><plist><plist>".utf8)))
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: Data("<plist></plist></plist>".utf8)))
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: Data("</plist></plist><plist>".utf8)))
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: Data("<plist/>".utf8)))

        // 4. Multiple closing tags around content without Entitlements
        let multiClosing = Data("<plist><dict><key>foo</key><string>bar</string></dict></plist></plist>".utf8)
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: multiClosing))

        // 5. Valid XML plist but Entitlements is non-dict
        let nonDictCases = [
            "<plist><dict><key>Entitlements</key><string>not-a-dict</string></dict></plist>",
            "<plist><dict><key>Entitlements</key><array><string>item</string></array></dict></plist>",
            "<plist><dict><key>Entitlements</key><integer>123</integer></dict></plist>",
            "<plist><dict><key>Entitlements</key><true/></dict></plist>",
            "<plist><dict><key>NoEntitlements</key><dict/></dict></plist>",
            "<plist><dict/></plist>",
            "<plist></plist>"
        ]
        for c in nonDictCases {
            XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: Data(c.utf8)), "Should return nil for: \(c)")
        }

        // 6. Valid XML plist with embedded Entitlements and CDATA in values
        let nestedInValue = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Entitlements</key>
            <dict>
                <key>nested-tags</key>
                <string><![CDATA[</plist><plist>]]></string>
                <key>test-key</key>
                <string>valid-value</string>
            </dict>
        </dict>
        </plist>
        """
        let extracted = GhostSigner.extractEntitlements(fromMobileProvisionData: Data(nestedInValue.utf8))
        XCTAssertNotNil(extracted)
        XCTAssertEqual(extracted?["test-key"] as? String, "valid-value")
        XCTAssertEqual(extracted?["nested-tags"] as? String, "</plist><plist>")

        // 7. Binary garbage with embedded tags placed adversarially
        let binaryPrefix = Data((0..<256).map { UInt8($0) })
        let binarySuffix = Data((0..<256).reversed().map { UInt8($0) })

        var testBuf1 = binaryPrefix
        testBuf1.append(Data("</plist><plist>".utf8))
        testBuf1.append(binarySuffix)
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: testBuf1))

        var testBuf2 = binaryPrefix
        testBuf2.append(Data("</plist>".utf8))
        testBuf2.append(binarySuffix)
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: testBuf2))

        var testBuf3 = binaryPrefix
        testBuf3.append(Data("<plist".utf8))
        testBuf3.append(binarySuffix)
        XCTAssertNil(GhostSigner.extractEntitlements(fromMobileProvisionData: testBuf3))

        // 8. Deterministic pseudo-random fuzzing (5000 randomized iterations)
        var lcg: UInt64 = 0x1234567887654321
        func nextRand() -> UInt32 {
            lcg = lcg &* 6364136223846793005 &+ 1442695040888963407
            return UInt32(truncatingIfNeeded: lcg >> 32)
        }

        let tagFragments = ["<plist", "</plist>", "<plist>", "</plist><plist>", "</plist> </plist>", "<dict>", "</dict>", "<key>", "Entitlements", "\0", "\u{FF}"]

        for _ in 0..<5000 {
            let length = Int(nextRand() % 512)
            var fuzzedData = Data((0..<length).map { _ in UInt8(nextRand() & 0xFF) })

            // Inject random tags into random positions
            let numInjections = Int(nextRand() % 4)
            for _ in 0..<numInjections {
                let tag = tagFragments[Int(nextRand() % UInt32(tagFragments.count))]
                let tagData = Data(tag.utf8)
                let insertPos = fuzzedData.isEmpty ? 0 : Int(nextRand() % UInt32(fuzzedData.count))
                fuzzedData.insert(contentsOf: tagData, at: insertPos)
            }

            // Must execute safely without any fatalError or crash trap
            _ = GhostSigner.extractEntitlements(fromMobileProvisionData: fuzzedData)
        }
    }

    func testSignBundleWithProvisioningProfile() throws {
        let tempDir = FileManager.default.temporaryDirectory
        let appDir = tempDir.appendingPathComponent("TestAppProv_\(UUID().uuidString).app")
        let provURL = tempDir.appendingPathComponent("test_\(UUID().uuidString).mobileprovision")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: appDir)
            try? FileManager.default.removeItem(at: provURL)
        }

        // Create Info.plist
        let infoPlist: [String: Any] = [
            "CFBundleExecutable": "TestApp",
            "CFBundleIdentifier": "com.ghostcode.testapp",
            "CFBundleVersion": "1.0"
        ]
        let infoData = try PropertyListSerialization.data(fromPropertyList: infoPlist, format: .xml, options: 0)
        try infoData.write(to: appDir.appendingPathComponent("Info.plist"))

        // Create main executable
        let exeData = createMockBinary()
        try exeData.write(to: appDir.appendingPathComponent("TestApp"))

        // Create mock mobileprovision with valid plist entitlements
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Entitlements</key>
            <dict>
                <key>application-identifier</key>
                <string>CUSTOMTEAM.com.ghostcode.testapp</string>
                <key>get-task-allow</key>
                <false/>
            </dict>
        </dict>
        </plist>
        """
        var provData = Data([0x30, 0x82, 0x01, 0x00])
        provData.append(Data(xml.utf8))
        provData.append(Data([0x00, 0x01]))
        try provData.write(to: provURL)

        // Sign bundle with provisioning profile (entitlements: nil -> should extract from profile)
        let signer = GhostSigner()
        try signer.signBundle(
            appURL: appDir,
            provisioningProfileURL: provURL,
            cert: SecCertificate(),
            key: SecKey(),
            entitlements: nil
        )

        // 1. Verify embedded.mobileprovision was copied to bundle root
        let embeddedProvURL = appDir.appendingPathComponent("embedded.mobileprovision")
        XCTAssertTrue(FileManager.default.fileExists(atPath: embeddedProvURL.path))
        let embeddedData = try Data(contentsOf: embeddedProvURL)
        XCTAssertEqual(embeddedData, provData)

        // 2. Verify _CodeSignature/CodeResources was created and contains embedded.mobileprovision
        let codeResourcesURL = appDir.appendingPathComponent("_CodeSignature/CodeResources")
        XCTAssertTrue(FileManager.default.fileExists(atPath: codeResourcesURL.path))
        let codeResData = try Data(contentsOf: codeResourcesURL)
        let codeResPlist = try PropertyListSerialization.propertyList(from: codeResData, options: [], format: nil) as? [String: Any]
        let files = codeResPlist?["files"] as? [String: Any]
        XCTAssertNotNil(files?["embedded.mobileprovision"], "embedded.mobileprovision must be sealed in CodeResources files")

        // 3. Verify main executable signature has Slot 7 with extracted entitlement
        let reader = try MachOReader(contentsOf: appDir.appendingPathComponent("TestApp"))
        let sigCmd = try XCTUnwrap(reader.codeSignatureCommand)
        XCTAssertGreaterThan(sigCmd.datasize, 0)

        let signedExeData = try Data(contentsOf: appDir.appendingPathComponent("TestApp"))
        let superBlobOffset = Int(sigCmd.dataoff)
        let superBlob = signedExeData.subdata(in: superBlobOffset..<(superBlobOffset + Int(sigCmd.datasize)))
        let superBlobString = String(decoding: superBlob, as: UTF8.self)
        XCTAssertTrue(superBlobString.contains("CUSTOMTEAM.com.ghostcode.testapp"), "SuperBlob must contain extracted entitlement")
    }

    // MARK: - TeamIdentifier extraction

    private func mockProfile(_ xml: String) -> Data {
        var data = Data([0x30, 0x82, 0x01, 0x00])
        data.append(Data(xml.utf8))
        data.append(Data([0x00, 0x01]))
        return data
    }

    /// Pulls the CSSLOT_CODEDIRECTORY blob out of an embedded superblob.
    private func codeDirectory(from superBlob: Data) throws -> Data {
        let count = Int(UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt32.self) }))
        for index in 0..<count {
            let entry = 12 + index * 8
            let slot = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entry, as: UInt32.self) })
            let offset = Int(UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entry + 4, as: UInt32.self) }))
            guard slot == MachOConstants.CSSLOT_CODEDIRECTORY else { continue }
            let length = Int(UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self) }))
            return superBlob.subdata(in: offset..<min(offset + length, superBlob.count))
        }
        throw MissingCodeDirectoryError()
    }

    func testExtractTeamIdentifierPrefersProfileArray() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
        <dict>
            <key>TeamIdentifier</key>
            <array>
                <string>TEAMFROMPROFILE</string>
                <string>QWERTYUIOP</string>
            </array>
            <key>Entitlements</key>
            <dict>
                <key>com.apple.developer.team-identifier</key>
                <string>TEAMFROMENTITLEMENT</string>
            </dict>
        </dict>
        </plist>
        """
        XCTAssertEqual(
            GhostSigner.extractTeamIdentifier(fromMobileProvisionData: mockProfile(xml)),
            "TEAMFROMPROFILE",
            "TeamIdentifier[0] is authoritative over the mirrored entitlement"
        )
    }

    func testExtractTeamIdentifierFallsBackToEntitlement() {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
        <dict>
            <key>Entitlements</key>
            <dict>
                <key>com.apple.developer.team-identifier</key>
                <string>ENTITLETEAM</string>
            </dict>
        </dict>
        </plist>
        """
        XCTAssertEqual(GhostSigner.extractTeamIdentifier(fromMobileProvisionData: mockProfile(xml)), "ENTITLETEAM")
    }

    func testExtractTeamIdentifierNilWhenAbsent() {
        XCTAssertNil(GhostSigner.extractTeamIdentifier(fromMobileProvisionData: mockProfile("""
        <plist version="1.0"><dict><key>Name</key><string>x</string></dict></plist>
        """)))
        XCTAssertNil(GhostSigner.extractTeamIdentifier(fromMobileProvisionData: Data("not a profile".utf8)))
    }

    func testSignedBinaryWritesTeamInto88ByteHeader() throws {
        let binaryData = createMockBinary()
        let signer = GhostSigner()
        var signed = binaryData
        try signer.sign(
            binaryData: &signed,
            identifier: "com.ghostcode.teamtest",
            entitlements: ["get-task-allow": true],
            teamID: "ABCDE12345"
        )

        let reader = try MachOReader(data: signed)
        let sigCmd = try XCTUnwrap(reader.codeSignatureCommand)
        let superBlobStart = Int(sigCmd.dataoff)
        let superBlob = signed.subdata(in: superBlobStart..<(superBlobStart + Int(sigCmd.datasize)))
        let cd = try codeDirectory(from: superBlob)

        func be32(_ offset: Int) -> UInt32 {
            UInt32(bigEndian: cd.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) })
        }
        func be64(_ offset: Int) -> UInt64 {
            UInt64(bigEndian: cd.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self) })
        }

        XCTAssertEqual(be32(8), 0x20400)
        XCTAssertEqual(be32(20), 88, "identOffset")
        XCTAssertEqual(be32(48), UInt32(88 + "com.ghostcode.teamtest".count + 1), "teamOffset")
        XCTAssertEqual(be64(72), 4096, "execSegLimit is __TEXT vmsize")
        XCTAssertEqual(be64(80), 0x11, "MH_EXECUTE + get-task-allow")
        let teamStart = Int(be32(48))
        XCTAssertEqual(String(decoding: cd.subdata(in: teamStart..<(teamStart + 10)), as: UTF8.self), "ABCDE12345")
    }

    func testSignBundleWritesTeamAndProfileTaskAllowFromProfile() throws {
        let tempDir = FileManager.default.temporaryDirectory
        let appDir = tempDir.appendingPathComponent("TestAppTeam_\(UUID().uuidString).app")
        let provURL = tempDir.appendingPathComponent("team_\(UUID().uuidString).mobileprovision")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: appDir)
            try? FileManager.default.removeItem(at: provURL)
        }

        let infoPlist: [String: Any] = [
            "CFBundleExecutable": "TestApp",
            "CFBundleIdentifier": "com.ghostcode.teamapp",
            "CFBundleVersion": "1.0"
        ]
        let infoData = try PropertyListSerialization.data(fromPropertyList: infoPlist, format: .xml, options: 0)
        try infoData.write(to: appDir.appendingPathComponent("Info.plist"))
        try createMockBinary().write(to: appDir.appendingPathComponent("TestApp"))

        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
        <dict>
            <key>TeamIdentifier</key>
            <array><string>PROFILETEAM</string></array>
            <key>Entitlements</key>
            <dict>
                <key>application-identifier</key>
                <string>PROFILETEAM.com.ghostcode.teamapp</string>
                <key>get-task-allow</key>
                <false/>
            </dict>
        </dict>
        </plist>
        """
        try mockProfile(xml).write(to: provURL)

        let signer = GhostSigner()
        try signer.signBundle(
            appURL: appDir,
            provisioningProfileURL: provURL,
            rawCertificate: SigningFixtures.leafCertificate,
            entitlements: nil,
            contentSigner: { _ in Data(repeating: 0xAB, count: 256) }
        )

        let exeURL = appDir.appendingPathComponent("TestApp")
        let signed = try Data(contentsOf: exeURL)
        let reader = try MachOReader(data: signed)
        let sigCmd = try XCTUnwrap(reader.codeSignatureCommand)
        let superBlobStart = Int(sigCmd.dataoff)
        let superBlob = signed.subdata(in: superBlobStart..<(superBlobStart + Int(sigCmd.datasize)))
        let cd = try codeDirectory(from: superBlob)

        func be32(_ offset: Int) -> UInt32 {
            UInt32(bigEndian: cd.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) })
        }

        XCTAssertEqual(be32(20), 88, "identOffset")
        let teamOffset = Int(be32(48))
        XCTAssertGreaterThan(teamOffset, 0, "distribution profile must yield a teamOffset")
        XCTAssertEqual(String(decoding: cd.subdata(in: teamOffset..<(teamOffset + 11)), as: UTF8.self), "PROFILETEAM")
        XCTAssertEqual(be32(12), GhostCodeConstants.CodeSigning.CS_ENTITLEMENTS_VALIDATED, "profile with get-task-allow false must not set the adhoc or task-allow bits")
    }
}


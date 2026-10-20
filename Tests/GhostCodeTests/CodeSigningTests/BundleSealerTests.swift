import XCTest
@testable import GhostCode

final class BundleSealerTests: XCTestCase {

    func testNativeSHA1StandardVectors() {
        // Test vector 1: empty string ""
        let emptyHash = NativeSHA1.hash(Data())
        let emptyHex = emptyHash.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(emptyHex, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        XCTAssertEqual(emptyHash.count, 20)

        // Verify CryptoHelpers.sha1 matches
        let helperEmptyHash = CryptoHelpers.sha1(Data())
        XCTAssertEqual(helperEmptyHash, emptyHash)

        // Test vector 2: "abc"
        let abcData = Data("abc".utf8)
        let abcHash = NativeSHA1.hash(abcData)
        let abcHex = abcHash.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(abcHex, "a9993e364706816aba3e25717850c26c9cd0d89d")
        XCTAssertEqual(CryptoHelpers.sha1(abcData), abcHash)

        // Test vector 3: 56-byte string
        let longData = Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)
        let longHash = NativeSHA1.hash(longData)
        let longHex = longHash.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(longHex, "84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        XCTAssertEqual(CryptoHelpers.sha1(longData), longHash)
    }

    func testMachOConstants() {
        XCTAssertEqual(MachOConstants.CSMAGIC_BLOBWRAPPER, 0xfade0b01)
        XCTAssertEqual(MachOConstants.CS_HASHTYPE_SHA1, 1)
        XCTAssertEqual(CSMAGIC_BLOBWRAPPER, 0xfade0b01)
        XCTAssertEqual(CS_HASHTYPE_SHA1, 1)
    }

    func testGenerateCodeResourcesDummyApp() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("TestApp_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // 1. Info.plist with CFBundleExecutable = "MyApp"
        let infoPlistContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleExecutable</key>
            <string>MyApp</string>
            <key>CFBundleIdentifier</key>
            <string>com.example.testapp</string>
        </dict>
        </plist>
        """
        let infoPlistData = Data(infoPlistContent.utf8)
        try infoPlistData.write(to: tempDir.appendingPathComponent("Info.plist"))

        // 2. Dummy main executable binary (should be excluded)
        let execData = Data([0xCF, 0xFA, 0xED, 0xFE, 0x01, 0x00, 0x00, 0x00])
        try execData.write(to: tempDir.appendingPathComponent("MyApp"))

        // 3. Resource file (Assets.car)
        let assetsData = Data("Sample Assets.car binary content".utf8)
        try assetsData.write(to: tempDir.appendingPathComponent("Assets.car"))

        // 4. Base localization file (Base.lproj/Main.storyboard)
        let baseDir = tempDir.appendingPathComponent("Base.lproj")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        let storyboardData = Data("<storyboard>dummy content</storyboard>".utf8)
        try storyboardData.write(to: baseDir.appendingPathComponent("Main.storyboard"))

        // 5. Language localization file (fr.lproj/Localizable.strings)
        let frDir = tempDir.appendingPathComponent("fr.lproj")
        try FileManager.default.createDirectory(at: frDir, withIntermediateDirectories: true)
        let stringsData = Data("\"Hello\" = \"Bonjour\";".utf8)
        try stringsData.write(to: frDir.appendingPathComponent("Localizable.strings"))

        // 6. Language metadata file (fr.lproj/locversion.plist) - should be omitted by rule
        let locData = Data("<plist></plist>".utf8)
        try locData.write(to: frDir.appendingPathComponent("locversion.plist"))

        // 7. Nested folder and resource
        let nestedDir = tempDir.appendingPathComponent("nested")
        try FileManager.default.createDirectory(at: nestedDir, withIntermediateDirectories: true)
        let nestedData = Data("nested file content".utf8)
        try nestedData.write(to: nestedDir.appendingPathComponent("sample.txt"))

        // 8. Stale _CodeSignature directory with old CodeResources
        let sigDir = tempDir.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: sigDir, withIntermediateDirectories: true)
        try Data("old signature data".utf8).write(to: sigDir.appendingPathComponent("CodeResources"))

        // 9. Symlink pointing to Assets.car
        let symlinkURL = tempDir.appendingPathComponent("Assets_link.car")
        try FileManager.default.createSymbolicLink(at: symlinkURL, withDestinationURL: tempDir.appendingPathComponent("Assets.car"))

        // Run BundleSealer.generateCodeResources
        let codeResourcesData = try BundleSealer.generateCodeResources(for: tempDir)
        XCTAssertFalse(codeResourcesData.isEmpty)

        // Verify it is a valid XML Property List
        var format: PropertyListSerialization.PropertyListFormat = .binary
        let plistObj = try PropertyListSerialization.propertyList(
            from: codeResourcesData,
            options: [],
            format: &format
        )
        XCTAssertEqual(format, .xml)

        guard let plist = plistObj as? [String: Any] else {
            XCTFail("CodeResources is not a dictionary")
            return
        }

        // Verify root keys
        XCTAssertNotNil(plist["files"])
        XCTAssertNotNil(plist["files2"])
        XCTAssertNotNil(plist["rules"])
        XCTAssertNotNil(plist["rules2"])

        guard let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("files or files2 is not a dictionary")
            return
        }

        // 1. Exclusions
        // _CodeSignature must not appear in files or files2
        XCTAssertNil(files["_CodeSignature"])
        XCTAssertNil(files["_CodeSignature/CodeResources"])
        XCTAssertNil(files2["_CodeSignature"])
        XCTAssertNil(files2["_CodeSignature/CodeResources"])

        // Main executable binary "MyApp" must be excluded
        XCTAssertNil(files["MyApp"])
        XCTAssertNil(files2["MyApp"])

        // locversion.plist must be omitted
        XCTAssertNil(files["fr.lproj/locversion.plist"])
        XCTAssertNil(files2["fr.lproj/locversion.plist"])

        // Directories must not be sealed as entries
        XCTAssertNil(files["Base.lproj"])
        XCTAssertNil(files2["Base.lproj"])
        XCTAssertNil(files["fr.lproj"])
        XCTAssertNil(files2["fr.lproj"])
        XCTAssertNil(files["nested"])
        XCTAssertNil(files2["nested"])

        // 2. Info.plist: present in files (SHA-1), omitted in files2
        XCTAssertNotNil(files["Info.plist"])
        XCTAssertNil(files2["Info.plist"])
        let infoSHA1 = CryptoHelpers.sha1(infoPlistData)
        XCTAssertEqual(files["Info.plist"] as? Data, infoSHA1)

        // 3. Assets.car: present in both files (SHA-1) and files2 (SHA-256)
        let expectedAssetsSHA1 = CryptoHelpers.sha1(assetsData)
        let expectedAssetsSHA256 = CryptoHelpers.sha256(assetsData)
        XCTAssertEqual(files["Assets.car"] as? Data, expectedAssetsSHA1)

        guard let assets2Entry = files2["Assets.car"] as? [String: Any] else {
            XCTFail("Assets.car entry in files2 is not a dictionary")
            return
        }
        XCTAssertEqual(assets2Entry["hash2"] as? Data, expectedAssetsSHA256)
        XCTAssertNil(assets2Entry["optional"])

        // 4. Base localization: Base.lproj/Main.storyboard (not optional)
        let expectedSbSHA1 = CryptoHelpers.sha1(storyboardData)
        let expectedSbSHA256 = CryptoHelpers.sha256(storyboardData)
        XCTAssertEqual(files["Base.lproj/Main.storyboard"] as? Data, expectedSbSHA1)
        guard let sb2Entry = files2["Base.lproj/Main.storyboard"] as? [String: Any] else {
            XCTFail("Main.storyboard entry in files2 is not a dictionary")
            return
        }
        XCTAssertEqual(sb2Entry["hash2"] as? Data, expectedSbSHA256)
        XCTAssertNil(sb2Entry["optional"])

        // 5. Language localization: fr.lproj/Localizable.strings (marked optional)
        guard let frEntry = files["fr.lproj/Localizable.strings"] as? [String: Any] else {
            XCTFail("Localizable.strings entry in files is not a dictionary")
            return
        }
        XCTAssertEqual(frEntry["hash"] as? Data, CryptoHelpers.sha1(stringsData))
        XCTAssertEqual(frEntry["optional"] as? Bool, true)

        guard let fr2Entry = files2["fr.lproj/Localizable.strings"] as? [String: Any] else {
            XCTFail("Localizable.strings entry in files2 is not a dictionary")
            return
        }
        XCTAssertEqual(fr2Entry["hash2"] as? Data, CryptoHelpers.sha256(stringsData))
        XCTAssertEqual(fr2Entry["optional"] as? Bool, true)

        // 6. Nested file: nested/sample.txt
        let expectedNestedSHA1 = CryptoHelpers.sha1(nestedData)
        let expectedNestedSHA256 = CryptoHelpers.sha256(nestedData)
        XCTAssertEqual(files["nested/sample.txt"] as? Data, expectedNestedSHA1)
        guard let nested2Entry = files2["nested/sample.txt"] as? [String: Any] else {
            XCTFail("nested/sample.txt entry in files2 is not a dictionary")
            return
        }
        XCTAssertEqual(nested2Entry["hash2"] as? Data, expectedNestedSHA256)

        // 7. Symlink: Assets_link.car
        XCTAssertNotNil(files["Assets_link.car"])
        XCTAssertNotNil(files2["Assets_link.car"])
        XCTAssertEqual(files["Assets_link.car"] as? Data, expectedAssetsSHA1)
        guard let symlink2Entry = files2["Assets_link.car"] as? [String: Any] else {
            XCTFail("Assets_link.car entry in files2 is not a dictionary")
            return
        }
        XCTAssertEqual(symlink2Entry["hash2"] as? Data, expectedAssetsSHA256)

        // 8. Disk verification: [appURL]/_CodeSignature/CodeResources written
        let writtenURL = tempDir.appendingPathComponent("_CodeSignature/CodeResources")
        XCTAssertTrue(FileManager.default.fileExists(atPath: writtenURL.path))
        let writtenData = try Data(contentsOf: writtenURL)
        XCTAssertEqual(writtenData, codeResourcesData)
    }

    func testSealHelperMethod() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("TestSealApp_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try "Hello World".write(to: tempDir.appendingPathComponent("test.txt"), atomically: true, encoding: .utf8)

        let sealedData = try BundleSealer.seal(appURL: tempDir, executableName: "None")
        XCTAssertFalse(sealedData.isEmpty)

        let writtenURL = tempDir.appendingPathComponent("_CodeSignature/CodeResources")
        XCTAssertTrue(FileManager.default.fileExists(atPath: writtenURL.path))
        let writtenData = try Data(contentsOf: writtenURL)
        XCTAssertEqual(writtenData, sealedData)
    }

    func testExplicitExecutableNameExclusion() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("TestExecApp_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try "Binary Content".write(to: tempDir.appendingPathComponent("CustomBinary"), atomically: true, encoding: .utf8)
        try "Resource Content".write(to: tempDir.appendingPathComponent("resource.json"), atomically: true, encoding: .utf8)

        let data = try BundleSealer.generateCodeResources(for: tempDir, executableName: "CustomBinary", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        XCTAssertNil(files["CustomBinary"])
        XCTAssertNil(files2["CustomBinary"])
        XCTAssertNotNil(files["resource.json"])
        XCTAssertNotNil(files2["resource.json"])

        // Verify writeToBundle = false did not create _CodeSignature
        let sigPath = tempDir.appendingPathComponent("_CodeSignature/CodeResources").path
        XCTAssertFalse(FileManager.default.fileExists(atPath: sigPath))
    }

    func testEnumerationFailedThrows() {
        let nonExistentURL = URL(fileURLWithPath: "/non/existent/path/for/bundle/testing")
        XCTAssertThrowsError(try BundleSealer.generateCodeResources(for: nonExistentURL, writeToBundle: false)) { error in
            guard let sealerError = error as? BundleSealerError else {
                XCTFail("Expected BundleSealerError but got \(error)")
                return
            }
            if case .enumerationFailed = sealerError {
                // Expected
            } else {
                XCTFail("Expected .enumerationFailed but got \(sealerError)")
            }
        }
    }

    func testNestedFrameworkSealing() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("TestNestedApp_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Main app binary
        try "AppBinary".write(to: tempDir.appendingPathComponent("App"), atomically: true, encoding: .utf8)

        // Nested framework
        let frameworkDir = tempDir.appendingPathComponent("Frameworks/MyFramework.framework")
        try FileManager.default.createDirectory(at: frameworkDir, withIntermediateDirectories: true)
        try "FrameworkBinary".write(to: frameworkDir.appendingPathComponent("MyFramework"), atomically: true, encoding: .utf8)
        let fwSigDir = frameworkDir.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: fwSigDir, withIntermediateDirectories: true)
        try "<plist>FWCodeResources</plist>".write(to: fwSigDir.appendingPathComponent("CodeResources"), atomically: true, encoding: .utf8)

        let data = try BundleSealer.generateCodeResources(for: tempDir, executableName: "App")
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to deserialize plist")
            return
        }

        // Main executable excluded
        XCTAssertNil(files["App"])
        XCTAssertNil(files2["App"])

        // Nested framework binary and its nested _CodeSignature/CodeResources must be sealed in parent bundle!
        XCTAssertNotNil(files["Frameworks/MyFramework.framework/MyFramework"])
        XCTAssertNotNil(files2["Frameworks/MyFramework.framework/MyFramework"])
        XCTAssertNotNil(files["Frameworks/MyFramework.framework/_CodeSignature/CodeResources"])
        XCTAssertNotNil(files2["Frameworks/MyFramework.framework/_CodeSignature/CodeResources"])

        // But parent's own _CodeSignature/CodeResources must NOT be in files or files2
        XCTAssertNil(files["_CodeSignature/CodeResources"])
        XCTAssertNil(files2["_CodeSignature/CodeResources"])
    }

    func testRules2Omissions() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("TestRulesApp_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try "ds_store".write(to: tempDir.appendingPathComponent(".DS_Store"), atomically: true, encoding: .utf8)
        try "pkginfo".write(to: tempDir.appendingPathComponent("PkgInfo"), atomically: true, encoding: .utf8)
        try "provision".write(to: tempDir.appendingPathComponent("embedded.provisionprofile"), atomically: true, encoding: .utf8)

        let data = try BundleSealer.generateCodeResources(for: tempDir, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to deserialize plist")
            return
        }

        // .DS_Store and PkgInfo omitted from files2
        XCTAssertNil(files2[".DS_Store"])
        XCTAssertNil(files2["PkgInfo"])

        // embedded.provisionprofile is included in files2
        XCTAssertNotNil(files2["embedded.provisionprofile"])

        // All 3 are present in files (v1)
        XCTAssertNotNil(files[".DS_Store"])
        XCTAssertNotNil(files["PkgInfo"])
        XCTAssertNotNil(files["embedded.provisionprofile"])
    }

    func testIdempotentSealing() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("TestIdempotent_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try "Resource".write(to: tempDir.appendingPathComponent("data.bin"), atomically: true, encoding: .utf8)

        // Seal first time
        let data1 = try BundleSealer.seal(appURL: tempDir)

        // Seal second time on the same directory (now contains _CodeSignature/CodeResources)
        let data2 = try BundleSealer.seal(appURL: tempDir)

        XCTAssertEqual(data1, data2)
    }
}


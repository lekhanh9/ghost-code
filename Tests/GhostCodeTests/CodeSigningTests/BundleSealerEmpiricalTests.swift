import XCTest
import Foundation
@testable import GhostCode

final class BundleSealerEmpiricalTests: XCTestCase {

    // MARK: - 1. NativeSHA1 & CryptoHelpers.sha1 Boundary Stress Testing

    func testNativeSHA1_ComprehensiveBoundarySizes_RepeatingPattern() {
        let referenceVectors: [(size: Int, expectedHex: String)] = [
            (0, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (1, "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"),
            (2, "e0c9035898dd52fc65c41454cec9c4d2611bfb37"),
            (3, "7e240de74fb1ed08fa08d38063f6a6a91462a815"),
            (54, "b05d71c64979cb95fa74a33cdb31a40d258ae02e"),
            (55, "c1c8bbdc22796e28c0e15163d20899b65621d65a"),
            (56, "c2db330f6083854c99d4b5bfb6e8f29f201be699"),
            (57, "f08f24908d682555111be7ff6f004e78283d989a"),
            (63, "03f09f5b158a7a8cdad920bddc29b81c18a551f5"),
            (64, "0098ba824b5c16427bd7a1122a5a442a25ec644d"),
            (65, "11655326c708d70319be2610e8a57d9a5b959d3b"),
            (118, "d0572de8e494e0b7b8e50302003fc4ae0596ef4d"),
            (119, "ee971065aaa017e0632a8ca6c77bb3bf8b1dfc56"),
            (120, "f34c1488385346a55709ba056ddd08280dd4c6d6"),
            (127, "89d95fa32ed44a7c610b7ee38517ddf57e0bb975"),
            (128, "ad5b3fdbcb526778c2839d2f151ea753995e26a0"),
            (129, "d96debf1bdcbc896e6c134ea76e8141f40d78536"),
            (511, "b9370eafb7ac772c6c1dc6b88ac9ad466b880ea1"),
            (512, "164557facb73929875168c1e92caf09bb6064564"),
            (1000, "291e9a6c66994949b57ba5e650361e98fc36b1ba"),
            (1024, "8eca554631df9ead14510e1a70ae48c70f9b9384"),
            (65535, "e1d0a18d43d3a689af088e156bd0434aa0c831fc"),
            (65536, "79db5888b5d38e10afbdbd14a19cd1caa9044c65"),
            (100000, "c4d4b30851182fc4eb8675494d42fd7f17e29c93"),
            (1000000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f")
        ]

        let asciiA: UInt8 = 0x61 // 'a'

        for (size, expectedHex) in referenceVectors {
            let data = Data(repeating: asciiA, count: size)

            // Test NativeSHA1 directly
            let nativeHash = NativeSHA1.hash(data)
            XCTAssertEqual(nativeHash.count, 20, "NativeSHA1 output for size \(size) must be exactly 20 bytes")
            let nativeHex = nativeHash.map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(nativeHex, expectedHex, "NativeSHA1 failed for size \(size)")

            // Test CryptoHelpers.sha1 wrapper
            let helperHash = CryptoHelpers.sha1(data)
            XCTAssertEqual(helperHash, nativeHash, "CryptoHelpers.sha1 does not match NativeSHA1 for size \(size)")
        }
    }

    func testNativeSHA1_SequentialPattern() {
        let referenceVectors: [(size: Int, expectedHex: String)] = [
            (0, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (1, "5ba93c9db0cff93f52b521d7420e43f6eda2784f"),
            (55, "8ae2d46729cfe68ff927af5eec9c7d1b66d65ac2"),
            (56, "636e2ec698dac903498e648bd2f3af641d3c88cb"),
            (64, "c6138d514ffa2135bfce0ed0b8fac65669917ec7"),
            (119, "41c89d06001bab4ab78736b44efe7ce18ce6ae08"),
            (120, "d3dbd653bd8597b7475321b60a36891278e6a04a"),
            (1000, "af0b191c2de46fe13fe0908f5a6a4e90e0cafc46"),
            (100000, "0b2dbe11b251d595b35eb42fe85b3a3e15767aa0")
        ]

        for (size, expectedHex) in referenceVectors {
            var bytes = [UInt8](repeating: 0, count: size)
            for i in 0..<size {
                bytes[i] = UInt8(i % 256)
            }
            let data = Data(bytes)

            let nativeHash = NativeSHA1.hash(data)
            let nativeHex = nativeHash.map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(nativeHex, expectedHex, "NativeSHA1 failed for sequential pattern size \(size)")
            XCTAssertEqual(CryptoHelpers.sha1(data), nativeHash)
        }
    }

    func testNativeSHA1_ZeroAndFFPatterns() {
        let zeroVectors: [(size: Int, expectedHex: String)] = [
            (55, "8e8832c642a6a38c74c17fc92ccedc266c108e6c"),
            (56, "9438e360f578e12c0e0e8ed28e2c125c1cefee16"),
            (64, "c8d7d0ef0eedfa82d2ea1aa592845b9a6d4b02b7"),
            (119, "85634f17f58bda0e4f0515dfb68bc1af922a031f"),
            (120, "b110a88a11436b215220486c1081dec2fb0f389a")
        ]

        for (size, expectedHex) in zeroVectors {
            let data = Data(repeating: 0x00, count: size)
            let nativeHash = NativeSHA1.hash(data)
            let nativeHex = nativeHash.map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(nativeHex, expectedHex, "NativeSHA1 failed for zeros size \(size)")
        }

        let ffVectors: [(size: Int, expectedHex: String)] = [
            (55, "450732ec1ec8fc5594a29700e11c37f09622ed72"),
            (56, "09cade8bfcfc501cb097636504dff46b39270658"),
            (64, "ffc6261e487efa8c7442069f71acfc4aa826993d"),
            (119, "97b433c99a75e69bd8170ef41aacbfb370434b0d"),
            (120, "b099d503d1c2bdf6defb88f6368bde6a6e71c448")
        ]

        for (size, expectedHex) in ffVectors {
            let data = Data(repeating: 0xFF, count: size)
            let nativeHash = NativeSHA1.hash(data)
            let nativeHex = nativeHash.map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(nativeHex, expectedHex, "NativeSHA1 failed for 0xFF size \(size)")
        }
    }

    // MARK: - 2. PropertyListSerialization Validity Stress Testing

    func testPropertyListSerialization_FormatAndRoundtrip() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("PLRoundtrip_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Create sample resources
        try "Content A".write(to: tempDir.appendingPathComponent("fileA.txt"), atomically: true, encoding: .utf8)
        try "Content B".write(to: tempDir.appendingPathComponent("fileB.json"), atomically: true, encoding: .utf8)

        let xmlData = try BundleSealer.generateCodeResources(for: tempDir, executableName: "None", writeToBundle: false)

        // 1. Verify XML header and DOCTYPE
        guard let xmlString = String(data: xmlData, encoding: .utf8) else {
            XCTFail("CodeResources is not valid UTF-8 string")
            return
        }
        XCTAssertTrue(xmlString.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"), "Missing XML declaration")
        XCTAssertTrue(xmlString.contains("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"), "Missing Apple Plist DOCTYPE")
        XCTAssertTrue(xmlString.contains("<plist version=\"1.0\">"), "Missing root plist tag")

        // 2. Roundtrip via PropertyListSerialization
        var format: PropertyListSerialization.PropertyListFormat = .binary
        let obj = try PropertyListSerialization.propertyList(from: xmlData, options: [], format: &format)
        XCTAssertEqual(format, .xml, "Format should be .xml")
        guard let dict = obj as? [String: Any] else {
            XCTFail("Root is not a dictionary")
            return
        }

        XCTAssertNotNil(dict["files"])
        XCTAssertNotNil(dict["files2"])
        XCTAssertNotNil(dict["rules"])
        XCTAssertNotNil(dict["rules2"])

        // 3. Verify files and files2 structure
        guard let files = dict["files"] as? [String: Any],
              let files2 = dict["files2"] as? [String: Any] else {
            XCTFail("files or files2 is not dictionary")
            return
        }

        XCTAssertTrue(files["fileA.txt"] is Data, "fileA.txt in files should be Data")
        guard let fileA2 = files2["fileA.txt"] as? [String: Any] else {
            XCTFail("fileA.txt in files2 should be dictionary")
            return
        }
        XCTAssertTrue(fileA2["hash2"] is Data, "hash2 should be Data")

        // 4. Verify base64 <data> encoding in raw XML
        XCTAssertTrue(xmlString.contains("<data>"), "XML should contain <data> tags for binary hashes")
    }

    // MARK: - 3. Apple Codesign Rules & Rules2 Evaluation Stress Testing

    func testRulesAndRules2EvaluationAppleCodesignExpectations() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("AppleRulesApp_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // 1. Info.plist
        let infoData = Data("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist><dict><key>CFBundleExecutable</key><string>MainApp</string></dict></plist>".utf8)
        try infoData.write(to: tempDir.appendingPathComponent("Info.plist"))

        // 2. Main binary (matching CFBundleExecutable)
        try "MachO binary".write(to: tempDir.appendingPathComponent("MainApp"), atomically: true, encoding: .utf8)

        // 3. PkgInfo
        try "APPL????".write(to: tempDir.appendingPathComponent("PkgInfo"), atomically: true, encoding: .utf8)

        // 4. Root .DS_Store
        try "ds_store_root".write(to: tempDir.appendingPathComponent(".DS_Store"), atomically: true, encoding: .utf8)

        // 5. Nested .DS_Store
        let subDir = tempDir.appendingPathComponent("sub")
        try FileManager.default.createDirectory(at: subDir, withIntermediateDirectories: true)
        try "ds_store_sub".write(to: subDir.appendingPathComponent(".DS_Store"), atomically: true, encoding: .utf8)

        // 6. Deeply nested .DS_Store
        let deepDir = tempDir.appendingPathComponent("a/b/c")
        try FileManager.default.createDirectory(at: deepDir, withIntermediateDirectories: true)
        try "ds_store_deep".write(to: deepDir.appendingPathComponent(".DS_Store"), atomically: true, encoding: .utf8)

        // 7. embedded.provisionprofile
        try "provision_data".write(to: tempDir.appendingPathComponent("embedded.provisionprofile"), atomically: true, encoding: .utf8)

        // 8. version.plist
        try "<plist></plist>".write(to: tempDir.appendingPathComponent("version.plist"), atomically: true, encoding: .utf8)

        // 9. Base.lproj/Main.storyboard (non-optional)
        let baseDir = tempDir.appendingPathComponent("Base.lproj")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        try "<storyboard/>".write(to: baseDir.appendingPathComponent("Main.storyboard"), atomically: true, encoding: .utf8)

        // 10. Base.lproj/locversion.plist (MUST BE OMITTED despite Base.lproj weight!)
        try "<plist/>".write(to: baseDir.appendingPathComponent("locversion.plist"), atomically: true, encoding: .utf8)

        // 11. fr.lproj/Localizable.strings (optional)
        let frDir = tempDir.appendingPathComponent("fr.lproj")
        try FileManager.default.createDirectory(at: frDir, withIntermediateDirectories: true)
        try "\"test\" = \"test\";".write(to: frDir.appendingPathComponent("Localizable.strings"), atomically: true, encoding: .utf8)

        // 12. fr.lproj/locversion.plist (MUST BE OMITTED)
        try "<plist/>".write(to: frDir.appendingPathComponent("locversion.plist"), atomically: true, encoding: .utf8)

        // 13. Nested framework with its own _CodeSignature
        let fwDir = tempDir.appendingPathComponent("Frameworks/Test.framework")
        let fwSigDir = fwDir.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: fwSigDir, withIntermediateDirectories: true)
        try "FWBinary".write(to: fwDir.appendingPathComponent("Test"), atomically: true, encoding: .utf8)
        try "FWInfo".write(to: fwDir.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)
        try "<plist>FWCodeResources</plist>".write(to: fwSigDir.appendingPathComponent("CodeResources"), atomically: true, encoding: .utf8)

        // 14. Nested app extension (PlugIns/Share.appex)
        let appexDir = tempDir.appendingPathComponent("PlugIns/Share.appex")
        let appexSigDir = appexDir.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: appexSigDir, withIntermediateDirectories: true)
        try "AppexBinary".write(to: appexDir.appendingPathComponent("Share"), atomically: true, encoding: .utf8)
        try "<plist>AppexCR</plist>".write(to: appexSigDir.appendingPathComponent("CodeResources"), atomically: true, encoding: .utf8)

        // 15. Stale root _CodeSignature
        let rootSigDir = tempDir.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: rootSigDir, withIntermediateDirectories: true)
        try "stale".write(to: rootSigDir.appendingPathComponent("CodeResources"), atomically: true, encoding: .utf8)

        // Execute Sealer
        let codeResourcesData = try BundleSealer.generateCodeResources(for: tempDir)

        guard let plist = try PropertyListSerialization.propertyList(from: codeResourcesData, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse CodeResources dictionary")
            return
        }

        // --- Verifications ---

        // A. Root _CodeSignature must NEVER appear
        XCTAssertNil(files["_CodeSignature"])
        XCTAssertNil(files["_CodeSignature/CodeResources"])
        XCTAssertNil(files2["_CodeSignature"])
        XCTAssertNil(files2["_CodeSignature/CodeResources"])

        // B. Main binary excluded
        XCTAssertNil(files["MainApp"])
        XCTAssertNil(files2["MainApp"])

        // C. Info.plist: in files (v1), OMITTED in files2 (v2)
        XCTAssertNotNil(files["Info.plist"], "Info.plist must be present in files (v1)")
        XCTAssertNil(files2["Info.plist"], "Info.plist must be omitted from files2 (v2)")

        // D. PkgInfo: in files (v1), OMITTED in files2 (v2)
        XCTAssertNotNil(files["PkgInfo"], "PkgInfo must be present in files (v1)")
        XCTAssertNil(files2["PkgInfo"], "PkgInfo must be omitted from files2 (v2)")

        // E. .DS_Store at all depths: in files (v1), OMITTED in files2 (v2)
        XCTAssertNotNil(files[".DS_Store"])
        XCTAssertNil(files2[".DS_Store"])
        XCTAssertNotNil(files["sub/.DS_Store"])
        XCTAssertNil(files2["sub/.DS_Store"])
        XCTAssertNotNil(files["a/b/c/.DS_Store"])
        XCTAssertNil(files2["a/b/c/.DS_Store"])

        // F. embedded.provisionprofile: in files and files2
        XCTAssertNotNil(files["embedded.provisionprofile"])
        XCTAssertNotNil(files2["embedded.provisionprofile"])

        // G. version.plist: in files and files2
        XCTAssertNotNil(files["version.plist"])
        XCTAssertNotNil(files2["version.plist"])

        // H. Base.lproj/Main.storyboard: NOT optional in either files or files2
        XCTAssertTrue(files["Base.lproj/Main.storyboard"] is Data, "Base storyboard should be plain Data in files")
        if let base2 = files2["Base.lproj/Main.storyboard"] as? [String: Any] {
            XCTAssertNil(base2["optional"], "Base storyboard should not have optional key in files2")
        } else {
            XCTFail("Base storyboard missing from files2")
        }

        // I. Base.lproj/locversion.plist & fr.lproj/locversion.plist: OMITTED from both files and files2
        XCTAssertNil(files["Base.lproj/locversion.plist"], "Base locversion.plist must be omitted from files")
        XCTAssertNil(files2["Base.lproj/locversion.plist"], "Base locversion.plist must be omitted from files2")
        XCTAssertNil(files["fr.lproj/locversion.plist"], "fr locversion.plist must be omitted from files")
        XCTAssertNil(files2["fr.lproj/locversion.plist"], "fr locversion.plist must be omitted from files2")

        // J. fr.lproj/Localizable.strings: optional in both files and files2
        guard let frEntry = files["fr.lproj/Localizable.strings"] as? [String: Any],
              let fr2Entry = files2["fr.lproj/Localizable.strings"] as? [String: Any] else {
            XCTFail("fr localization missing or not dictionary")
            return
        }
        XCTAssertEqual(frEntry["optional"] as? Bool, true)
        XCTAssertEqual(fr2Entry["optional"] as? Bool, true)

        // K. Nested framework preserved
        XCTAssertNotNil(files["Frameworks/Test.framework/Test"])
        XCTAssertNotNil(files2["Frameworks/Test.framework/Test"])
        XCTAssertNotNil(files["Frameworks/Test.framework/Info.plist"])
        XCTAssertNotNil(files2["Frameworks/Test.framework/Info.plist"])
        XCTAssertNotNil(files["Frameworks/Test.framework/_CodeSignature/CodeResources"])
        XCTAssertNotNil(files2["Frameworks/Test.framework/_CodeSignature/CodeResources"])

        // L. Nested app extension preserved
        XCTAssertNotNil(files["PlugIns/Share.appex/Share"])
        XCTAssertNotNil(files2["PlugIns/Share.appex/Share"])
        XCTAssertNotNil(files["PlugIns/Share.appex/_CodeSignature/CodeResources"])
        XCTAssertNotNil(files2["PlugIns/Share.appex/_CodeSignature/CodeResources"])
    }

    // MARK: - 4. Special Characters, Unicode Paths & Binary Plist

    func testSpecialCharactersAndUnicodePaths() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("SpecialChars_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let testFiles = [
            "My Spaced Resource.png": "Spaces content",
            "Café_☕.json": "Unicode content",
            "日本語_ファイル.txt": "Japanese content",
            "foo&bar<baz>.xml": "XML entity chars"
        ]

        for (filename, content) in testFiles {
            try content.write(to: tempDir.appendingPathComponent(filename), atomically: true, encoding: .utf8)
        }

        let data = try BundleSealer.generateCodeResources(for: tempDir, executableName: "None", writeToBundle: false)

        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to deserialize plist")
            return
        }

        for (filename, content) in testFiles {
            let expectedSHA1 = CryptoHelpers.sha1(Data(content.utf8))
            let expectedSHA256 = CryptoHelpers.sha256(Data(content.utf8))

            XCTAssertNotNil(files[filename], "Missing \(filename) in files")
            XCTAssertEqual(files[filename] as? Data, expectedSHA1)

            guard let f2 = files2[filename] as? [String: Any] else {
                XCTFail("Missing or invalid \(filename) in files2")
                continue
            }
            XCTAssertEqual(f2["hash2"] as? Data, expectedSHA256)
        }
    }

    func testBinaryInfoPlistExecutableExtraction() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("BinaryInfo_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Create a binary Info.plist
        let infoDict: [String: Any] = [
            "CFBundleExecutable": "BinaryAppExec",
            "CFBundleIdentifier": "com.test.binary"
        ]
        let binaryData = try PropertyListSerialization.data(fromPropertyList: infoDict, format: .binary, options: 0)
        try binaryData.write(to: tempDir.appendingPathComponent("Info.plist"))

        // Create the executable and a resource
        try "exec data".write(to: tempDir.appendingPathComponent("BinaryAppExec"), atomically: true, encoding: .utf8)
        try "resource data".write(to: tempDir.appendingPathComponent("data.bin"), atomically: true, encoding: .utf8)

        // Run sealer without explicitly passing executableName
        let crData = try BundleSealer.generateCodeResources(for: tempDir, executableName: nil, writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: crData, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        // BinaryAppExec should be detected and excluded
        XCTAssertNil(files["BinaryAppExec"], "BinaryAppExec should be excluded from files")
        XCTAssertNil(files2["BinaryAppExec"], "BinaryAppExec should be excluded from files2")

        // Info.plist should be present in files and omitted in files2
        XCTAssertNotNil(files["Info.plist"])
        XCTAssertNil(files2["Info.plist"])

        // data.bin should be present in both
        XCTAssertNotNil(files["data.bin"])
        XCTAssertNotNil(files2["data.bin"])
    }

    // MARK: - 5. Symlinks & Edge Cases

    func testDirectorySymlinkSkipping() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("SymlinkDir_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let targetDir = tempDir.appendingPathComponent("RealDir")
        try FileManager.default.createDirectory(at: targetDir, withIntermediateDirectories: true)
        try "hello".write(to: targetDir.appendingPathComponent("inside.txt"), atomically: true, encoding: .utf8)

        // Create symlink pointing to RealDir
        let symDirURL = tempDir.appendingPathComponent("SymDir")
        try FileManager.default.createSymbolicLink(at: symDirURL, withDestinationURL: targetDir)

        let crData = try BundleSealer.generateCodeResources(for: tempDir, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: crData, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        // SymDir (directory symlink) must NOT be recorded as a file entry
        XCTAssertNil(files["SymDir"])
        XCTAssertNotNil(files["RealDir/inside.txt"])
    }

    func testBrokenSymlinkThrowsUnreadableFile() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("BrokenSymlink_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Create symlink pointing to non-existent target
        let brokenLinkURL = tempDir.appendingPathComponent("broken.txt")
        let nonExistentTarget = tempDir.appendingPathComponent("does_not_exist.txt")
        try FileManager.default.createSymbolicLink(at: brokenLinkURL, withDestinationURL: nonExistentTarget)

        XCTAssertThrowsError(try BundleSealer.generateCodeResources(for: tempDir, executableName: "None", writeToBundle: false)) { error in
            guard let sealerError = error as? BundleSealerError else {
                XCTFail("Expected BundleSealerError but got \(error)")
                return
            }
            if case .unreadableFile = sealerError {
                // Expected
            } else {
                XCTFail("Expected .unreadableFile but got \(sealerError)")
            }
        }
    }
}

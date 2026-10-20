import XCTest
@testable import GhostCode

final class BundleSealerAdversarialTests: XCTestCase {

    // Helper to create a temporary bundle directory
    private func createTempBundle(prefix: String = "AdvTest") throws -> URL {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)_\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        return tempDir
    }

    private func cleanupBundle(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }

    // MARK: - 1. Empty Files & Zero-Byte Resources

    func testEmptyFilesSealing() throws {
        let bundleURL = try createTempBundle(prefix: "EmptyFile")
        defer { cleanupBundle(bundleURL) }

        // Create empty regular files
        let empty1 = bundleURL.appendingPathComponent("empty_file.txt")
        let empty2 = bundleURL.appendingPathComponent("nested/empty_data.dat")
        try FileManager.default.createDirectory(at: empty2.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data().write(to: empty1)
        try Data().write(to: empty2)

        // Seal bundle
        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to deserialize property list")
            return
        }

        let emptySHA1 = CryptoHelpers.sha1(Data())
        let emptySHA256 = CryptoHelpers.sha256(Data())

        XCTAssertEqual(emptySHA1.map { String(format: "%02x", $0) }.joined(), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        XCTAssertEqual(emptySHA256.map { String(format: "%02x", $0) }.joined(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        XCTAssertEqual(files["empty_file.txt"] as? Data, emptySHA1)
        XCTAssertEqual(files["nested/empty_data.dat"] as? Data, emptySHA1)

        guard let entry2_1 = files2["empty_file.txt"] as? [String: Any],
              let entry2_2 = files2["nested/empty_data.dat"] as? [String: Any] else {
            XCTFail("Missing files2 entries for empty files")
            return
        }
        XCTAssertEqual(entry2_1["hash2"] as? Data, emptySHA256)
        XCTAssertEqual(entry2_2["hash2"] as? Data, emptySHA256)
    }

    // MARK: - 2. Large Files (Multi-Megabyte Buffer Hashing)

    func testLargeFileSealing() throws {
        let bundleURL = try createTempBundle(prefix: "LargeFile")
        defer { cleanupBundle(bundleURL) }

        // 5 MB of repeating non-trivial data
        let pattern = "GhostCode_Large_File_Sealing_Stress_Test_Pattern_1234567890\n"
        let patternData = Data(pattern.utf8)
        let repeatCount = (5 * 1024 * 1024) / patternData.count
        var largeData = Data()
        largeData.reserveCapacity(repeatCount * patternData.count)
        for _ in 0..<repeatCount {
            largeData.append(patternData)
        }

        let largeFileURL = bundleURL.appendingPathComponent("Assets/large_asset.bin")
        try FileManager.default.createDirectory(at: largeFileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try largeData.write(to: largeFileURL)

        let expectedSHA1 = CryptoHelpers.sha1(largeData)
        let expectedSHA256 = CryptoHelpers.sha256(largeData)

        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to deserialize property list")
            return
        }

        XCTAssertEqual(files["Assets/large_asset.bin"] as? Data, expectedSHA1)
        guard let entry2 = files2["Assets/large_asset.bin"] as? [String: Any] else {
            XCTFail("Missing files2 entry for large file")
            return
        }
        XCTAssertEqual(entry2["hash2"] as? Data, expectedSHA256)
    }

    // MARK: - 3. Special Characters in File Names

    func testSpecialCharactersInFilenames() throws {
        let bundleURL = try createTempBundle(prefix: "SpecialChars")
        defer { cleanupBundle(bundleURL) }

        let testCases: [(relativePath: String, content: String)] = [
            // Spaces and punctuation
            ("Folder With Spaces/File With Many Spaces.txt", "content space"),
            ("file-name_v1.0@2x~iphone#hash.png", "content punct"),
            // Plus signs and math
            ("C++_Library+v1.0+alpha.dat", "content plus"),
            ("calc_2+2=4.dat", "content math"),
            // XML special characters (must be safely encoded in plist XML without corruption)
            ("file_&_more<tag>'quote\"amp.dat", "content xml chars"),
            // Emojis
            ("emoji_🚀_app_🎉.json", "content emoji"),
            ("sub_📁/icon_✨_star.png", "content nested emoji"),
            // Non-ASCII and Unicode (accents, Asian characters, Cyrillic, Arabic)
            ("café_résumé_naïve.strings", "content accents"),
            ("日本語_ディレクトリ/ファイル名.txt", "content japanese"),
            ("файл_на_русском.dat", "content cyrillic"),
            ("ملف_عربي.txt", "content arabic"),
            // Brackets and parentheses
            ("items[0](first){v1}.txt", "content brackets")
        ]

        for tc in testCases {
            let fileURL = bundleURL.appendingPathComponent(tc.relativePath)
            try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(tc.content.utf8).write(to: fileURL)
        }

        // Generate CodeResources and write to bundle
        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: true)

        // Verify plist deserialization succeeds and preserves exact strings
        var format: PropertyListSerialization.PropertyListFormat = .binary
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: &format) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to deserialize property list with special characters")
            return
        }
        XCTAssertEqual(format, .xml)

        for tc in testCases {
            let contentData = Data(tc.content.utf8)
            let sha1 = CryptoHelpers.sha1(contentData)
            let sha256 = CryptoHelpers.sha256(contentData)

            XCTAssertNotNil(files[tc.relativePath], "files dictionary missing key: \(tc.relativePath)")
            XCTAssertEqual(files[tc.relativePath] as? Data, sha1)

            guard let entry2 = files2[tc.relativePath] as? [String: Any] else {
                XCTFail("files2 dictionary missing key: \(tc.relativePath)")
                continue
            }
            XCTAssertEqual(entry2["hash2"] as? Data, sha256)
        }
    }

    // MARK: - 4. Deeply Nested Directories

    func testDeeplyNestedDirectories() throws {
        let bundleURL = try createTempBundle(prefix: "DeepNesting")
        defer { cleanupBundle(bundleURL) }

        // Construct a path 20 levels deep
        var pathComponents: [String] = []
        for i in 1...20 {
            pathComponents.append("level_\(i)")
        }
        let deepRelativeDir = pathComponents.joined(separator: "/")
        let deepRelativeFile = deepRelativeDir + "/deep_resource.txt"

        let deepFileURL = bundleURL.appendingPathComponent(deepRelativeFile)
        try FileManager.default.createDirectory(at: deepFileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let sampleContent = Data("Deeply nested file content".utf8)
        try sampleContent.write(to: deepFileURL)

        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        XCTAssertNotNil(files[deepRelativeFile])
        XCTAssertEqual(files[deepRelativeFile] as? Data, CryptoHelpers.sha1(sampleContent))

        guard let entry2 = files2[deepRelativeFile] as? [String: Any] else {
            XCTFail("files2 missing deep relative file")
            return
        }
        XCTAssertEqual(entry2["hash2"] as? Data, CryptoHelpers.sha256(sampleContent))
    }

    // MARK: - 5. Nested Bundles (Frameworks and PlugIns App Extensions)

    func testMultiLevelNestedBundles() throws {
        let bundleURL = try createTempBundle(prefix: "NestedBundles")
        defer { cleanupBundle(bundleURL) }

        // Main app binary
        try "MainAppBinary".write(to: bundleURL.appendingPathComponent("MainApp"), atomically: true, encoding: .utf8)

        // 1. Framework: Frameworks/Alpha.framework
        let alphaDir = bundleURL.appendingPathComponent("Frameworks/Alpha.framework")
        try FileManager.default.createDirectory(at: alphaDir, withIntermediateDirectories: true)
        try "AlphaMachO".write(to: alphaDir.appendingPathComponent("Alpha"), atomically: true, encoding: .utf8)
        let alphaSig = alphaDir.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: alphaSig, withIntermediateDirectories: true)
        try "<plist>AlphaSig</plist>".write(to: alphaSig.appendingPathComponent("CodeResources"), atomically: true, encoding: .utf8)
        try "<plist>AlphaInfo</plist>".write(to: alphaDir.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)

        // 2. Sub-framework inside Framework: Frameworks/Alpha.framework/Frameworks/Beta.framework
        let betaDir = alphaDir.appendingPathComponent("Frameworks/Beta.framework")
        try FileManager.default.createDirectory(at: betaDir, withIntermediateDirectories: true)
        try "BetaMachO".write(to: betaDir.appendingPathComponent("Beta"), atomically: true, encoding: .utf8)
        let betaSig = betaDir.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: betaSig, withIntermediateDirectories: true)
        try "<plist>BetaSig</plist>".write(to: betaSig.appendingPathComponent("CodeResources"), atomically: true, encoding: .utf8)

        // 3. App Extension: PlugIns/WidgetExtension.appex
        let widgetDir = bundleURL.appendingPathComponent("PlugIns/WidgetExtension.appex")
        try FileManager.default.createDirectory(at: widgetDir, withIntermediateDirectories: true)
        try "WidgetBinary".write(to: widgetDir.appendingPathComponent("WidgetExtension"), atomically: true, encoding: .utf8)
        let widgetSig = widgetDir.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: widgetSig, withIntermediateDirectories: true)
        try "<plist>WidgetSig</plist>".write(to: widgetSig.appendingPathComponent("CodeResources"), atomically: true, encoding: .utf8)
        try "WidgetResource".write(to: widgetDir.appendingPathComponent("widget_ui.json"), atomically: true, encoding: .utf8)

        // 4. Resource bundle without Mach-O: Settings.bundle
        let settingsDir = bundleURL.appendingPathComponent("Settings.bundle")
        try FileManager.default.createDirectory(at: settingsDir, withIntermediateDirectories: true)
        try "<plist>RootPlist</plist>".write(to: settingsDir.appendingPathComponent("Root.plist"), atomically: true, encoding: .utf8)

        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: "MainApp", writeToBundle: true)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        // Main app binary excluded
        XCTAssertNil(files["MainApp"])
        XCTAssertNil(files2["MainApp"])

        // Main app's own _CodeSignature excluded
        XCTAssertNil(files["_CodeSignature/CodeResources"])
        XCTAssertNil(files2["_CodeSignature/CodeResources"])

        // Alpha framework binary, Info.plist, CodeResources must be sealed
        XCTAssertNotNil(files["Frameworks/Alpha.framework/Alpha"])
        XCTAssertNotNil(files2["Frameworks/Alpha.framework/Alpha"])
        XCTAssertNotNil(files["Frameworks/Alpha.framework/_CodeSignature/CodeResources"])
        XCTAssertNotNil(files2["Frameworks/Alpha.framework/_CodeSignature/CodeResources"])

        // Beta sub-framework inside Alpha framework must be sealed
        XCTAssertNotNil(files["Frameworks/Alpha.framework/Frameworks/Beta.framework/Beta"])
        XCTAssertNotNil(files2["Frameworks/Alpha.framework/Frameworks/Beta.framework/Beta"])
        XCTAssertNotNil(files["Frameworks/Alpha.framework/Frameworks/Beta.framework/_CodeSignature/CodeResources"])
        XCTAssertNotNil(files2["Frameworks/Alpha.framework/Frameworks/Beta.framework/_CodeSignature/CodeResources"])

        // Widget extension items must be sealed
        XCTAssertNotNil(files["PlugIns/WidgetExtension.appex/WidgetExtension"])
        XCTAssertNotNil(files2["PlugIns/WidgetExtension.appex/WidgetExtension"])
        XCTAssertNotNil(files["PlugIns/WidgetExtension.appex/_CodeSignature/CodeResources"])
        XCTAssertNotNil(files2["PlugIns/WidgetExtension.appex/_CodeSignature/CodeResources"])
        XCTAssertNotNil(files["PlugIns/WidgetExtension.appex/widget_ui.json"])
        XCTAssertNotNil(files2["PlugIns/WidgetExtension.appex/widget_ui.json"])

        // Settings.bundle items must be sealed
        XCTAssertNotNil(files["Settings.bundle/Root.plist"])
        XCTAssertNotNil(files2["Settings.bundle/Root.plist"])
    }

    // MARK: - 6. Symlink Variations & Edge Cases

    func testSymlinkToDirectoryExclusion() throws {
        let bundleURL = try createTempBundle(prefix: "DirSymlink")
        defer { cleanupBundle(bundleURL) }

        // Create a real directory with a file
        let realDir = bundleURL.appendingPathComponent("RealFolder")
        try FileManager.default.createDirectory(at: realDir, withIntermediateDirectories: true)
        try "Content".write(to: realDir.appendingPathComponent("item.txt"), atomically: true, encoding: .utf8)

        // Create a symlink pointing to the directory
        let symlinkDir = bundleURL.appendingPathComponent("SymlinkFolder")
        try FileManager.default.createSymbolicLink(at: symlinkDir, withDestinationURL: realDir)

        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        // Real folder should not be an entry
        XCTAssertNil(files["RealFolder"])
        XCTAssertNil(files2["RealFolder"])

        // The symlink pointing to a directory must NOT be sealed as a file entry
        XCTAssertNil(files["SymlinkFolder"])
        XCTAssertNil(files2["SymlinkFolder"])

        // Real file inside real directory must be sealed
        XCTAssertNotNil(files["RealFolder/item.txt"])
        XCTAssertNotNil(files2["RealFolder/item.txt"])
    }

    func testSymlinkToFileInNestedDirectory() throws {
        let bundleURL = try createTempBundle(prefix: "NestedSymlink")
        defer { cleanupBundle(bundleURL) }

        let subDir = bundleURL.appendingPathComponent("Resources/Fonts")
        try FileManager.default.createDirectory(at: subDir, withIntermediateDirectories: true)
        let fontFile = subDir.appendingPathComponent("CustomFont.ttf")
        let fontContent = Data("Font binary data 12345".utf8)
        try fontContent.write(to: fontFile)

        // Root level symlink to nested file
        let rootLink = bundleURL.appendingPathComponent("DefaultFont.ttf")
        try FileManager.default.createSymbolicLink(at: rootLink, withDestinationURL: fontFile)

        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        let sha1 = CryptoHelpers.sha1(fontContent)
        let sha256 = CryptoHelpers.sha256(fontContent)

        XCTAssertEqual(files["Resources/Fonts/CustomFont.ttf"] as? Data, sha1)
        XCTAssertEqual(files["DefaultFont.ttf"] as? Data, sha1)

        guard let entry2_1 = files2["Resources/Fonts/CustomFont.ttf"] as? [String: Any],
              let entry2_2 = files2["DefaultFont.ttf"] as? [String: Any] else {
            XCTFail("Missing files2 entry")
            return
        }
        XCTAssertEqual(entry2_1["hash2"] as? Data, sha256)
        XCTAssertEqual(entry2_2["hash2"] as? Data, sha256)
    }

    func testBrokenSymlinkErrorHandling() throws {
        let bundleURL = try createTempBundle(prefix: "BrokenSymlink")
        defer { cleanupBundle(bundleURL) }

        // Create a symlink pointing to a non-existent file
        let brokenLink = bundleURL.appendingPathComponent("dangling_link.txt")
        let nonExistentTarget = bundleURL.appendingPathComponent("non_existent_file.txt")
        try FileManager.default.createSymbolicLink(at: brokenLink, withDestinationURL: nonExistentTarget)

        // Sealer should detect that the file cannot be read and throw unreadableFile error rather than crashing
        XCTAssertThrowsError(try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: false)) { error in
            guard let sealerError = error as? BundleSealerError else {
                XCTFail("Expected BundleSealerError, got: \(error)")
                return
            }
            if case .unreadableFile(let path) = sealerError {
                XCTAssertTrue(path.contains("dangling_link.txt"))
            } else {
                XCTFail("Expected .unreadableFile, got: \(sealerError)")
            }
        }
    }

    func testCircularSymlinkErrorHandling() throws {
        let bundleURL = try createTempBundle(prefix: "CircularSymlink")
        defer { cleanupBundle(bundleURL) }

        // Create a circular symlink (symlink pointing to itself)
        let loopLink = bundleURL.appendingPathComponent("loop_link.txt")
        try FileManager.default.createSymbolicLink(at: loopLink, withDestinationURL: loopLink)

        // Sealer should fail gracefully with unreadableFile instead of infinite recursion or crashing
        XCTAssertThrowsError(try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: false)) { error in
            guard let sealerError = error as? BundleSealerError else {
                XCTFail("Expected BundleSealerError, got: \(error)")
                return
            }
            if case .unreadableFile = sealerError {
                // Expected: Reading contents of self-referential symlink fails safely
            } else {
                XCTFail("Expected .unreadableFile, got: \(sealerError)")
            }
        }
    }

    // MARK: - 7. Bundle Without Executable Name or Without Info.plist

    func testBundleWithoutInfoPlistAndNoExecutableSpecified() throws {
        let bundleURL = try createTempBundle(prefix: "NoInfo")
        defer { cleanupBundle(bundleURL) }

        try "Some Asset".write(to: bundleURL.appendingPathComponent("asset.dat"), atomically: true, encoding: .utf8)

        // Should seal cleanly with nil executableName
        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: nil, writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        XCTAssertNotNil(files["asset.dat"])
        XCTAssertNotNil(files2["asset.dat"])
    }

    func testSubdirectoryBinaryNotAccidentallyExcluded() throws {
        let bundleURL = try createTempBundle(prefix: "SubBinary")
        defer { cleanupBundle(bundleURL) }

        // Main binary named "App"
        try "RootApp".write(to: bundleURL.appendingPathComponent("App"), atomically: true, encoding: .utf8)

        // Subdirectory resource coincidentally also named "App"
        let helperDir = bundleURL.appendingPathComponent("Helpers")
        try FileManager.default.createDirectory(at: helperDir, withIntermediateDirectories: true)
        try "HelperApp".write(to: helperDir.appendingPathComponent("App"), atomically: true, encoding: .utf8)

        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: "App", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        // Root "App" is excluded
        XCTAssertNil(files["App"])
        XCTAssertNil(files2["App"])

        // Subfolder "Helpers/App" must NOT be excluded
        XCTAssertNotNil(files["Helpers/App"])
        XCTAssertNotNil(files2["Helpers/App"])
    }

    // MARK: - 8. Directory Symlink Cycle

    func testDirectorySymlinkCycle() throws {
        let bundleURL = try createTempBundle(prefix: "DirCycle")
        defer { cleanupBundle(bundleURL) }

        let subDir = bundleURL.appendingPathComponent("SubDir")
        try FileManager.default.createDirectory(at: subDir, withIntermediateDirectories: true)
        try "Content".write(to: subDir.appendingPathComponent("file.txt"), atomically: true, encoding: .utf8)

        // Create a symlink pointing back to its parent directory
        let cycleSymlink = subDir.appendingPathComponent("cycle_to_parent")
        try FileManager.default.createSymbolicLink(at: cycleSymlink, withDestinationURL: subDir)

        // Also create a symlink pointing back to the bundle root
        let rootCycleSymlink = subDir.appendingPathComponent("cycle_to_root")
        try FileManager.default.createSymbolicLink(at: rootCycleSymlink, withDestinationURL: bundleURL)

        // Sealer must not enter an infinite loop and must successfully finish
        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        XCTAssertNotNil(files["SubDir/file.txt"])
        XCTAssertNotNil(files2["SubDir/file.txt"])
        // Symlinks to directories must be excluded
        XCTAssertNil(files["SubDir/cycle_to_parent"])
        XCTAssertNil(files2["SubDir/cycle_to_parent"])
        XCTAssertNil(files["SubDir/cycle_to_root"])
        XCTAssertNil(files2["SubDir/cycle_to_root"])
    }

    // MARK: - 9. Symlinked Bundle URL & Trailing Slash

    func testSymlinkedBundleURL() throws {
        let realBundleURL = try createTempBundle(prefix: "RealBundle")
        defer { cleanupBundle(realBundleURL) }

        try "Hello".write(to: realBundleURL.appendingPathComponent("data.bin"), atomically: true, encoding: .utf8)

        let symlinkBundleURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("SymlinkedBundle_\(UUID().uuidString).app")
        try FileManager.default.createSymbolicLink(at: symlinkBundleURL, withDestinationURL: realBundleURL)
        defer { try? FileManager.default.removeItem(at: symlinkBundleURL) }

        let data = try BundleSealer.generateCodeResources(for: symlinkBundleURL, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        XCTAssertNotNil(files["data.bin"])
    }

    func testTrailingSlashInBundleURL() throws {
        let bundleURL = try createTempBundle(prefix: "TrailingSlash")
        defer { cleanupBundle(bundleURL) }

        try "Hello".write(to: bundleURL.appendingPathComponent("data.bin"), atomically: true, encoding: .utf8)

        // URL constructed with trailing slash
        let trailingURL = URL(fileURLWithPath: bundleURL.path + "/")

        let data = try BundleSealer.generateCodeResources(for: trailingURL, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        XCTAssertNotNil(files["data.bin"])
        // Keys must not have leading slash
        XCTAssertNil(files["/data.bin"])
    }

    // MARK: - 10. Unreadable File Error

    func testUnreadableFileThrows() throws {
        let bundleURL = try createTempBundle(prefix: "Unreadable")
        defer {
            // Restore permissions before deletion so cleanup doesn't fail
            let unreadableURL = bundleURL.appendingPathComponent("secret.dat")
            try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: unreadableURL.path)
            cleanupBundle(bundleURL)
        }

        let unreadableURL = bundleURL.appendingPathComponent("secret.dat")
        try "Secret Data".write(to: unreadableURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: unreadableURL.path)

        // In Linux root or codespace environments, if user is root or bypasses permissions, skip if readable
        let isReadable = FileManager.default.isReadableFile(atPath: unreadableURL.path)
        if !isReadable {
            XCTAssertThrowsError(try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: false)) { error in
                guard let sealerError = error as? BundleSealerError else {
                    XCTFail("Expected BundleSealerError, got: \(error)")
                    return
                }
                if case .unreadableFile(let path) = sealerError {
                    XCTAssertTrue(path.contains("secret.dat"))
                } else {
                    XCTFail("Expected .unreadableFile, got: \(sealerError)")
                }
            }
        }
    }

    // MARK: - 11. Empty Bundle Directory

    func testEmptyBundleDirectory() throws {
        let bundleURL = try createTempBundle(prefix: "EmptyBundle")
        defer { cleanupBundle(bundleURL) }

        let data = try BundleSealer.generateCodeResources(for: bundleURL, executableName: "None", writeToBundle: false)
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let files = plist["files"] as? [String: Any],
              let files2 = plist["files2"] as? [String: Any] else {
            XCTFail("Failed to parse plist")
            return
        }

        XCTAssertEqual(files.count, 0)
        XCTAssertEqual(files2.count, 0)
    }
}


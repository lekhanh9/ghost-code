import Foundation

public final class GhostSigner: @unchecked Sendable {
    public init() {}

    public static func sign(binaryURL: URL, entitlements: [String: Any]? = nil, outputURL: URL? = nil) throws {
        let signer = GhostSigner()
        try signer.sign(binaryURL: binaryURL, entitlements: entitlements, outputURL: outputURL)
    }

    public func sign(
        binaryURL: URL,
        entitlements: [String: Any]? = nil,
        cert: SecCertificate? = nil,
        key: SecKey? = nil,
        outputURL: URL? = nil
    ) throws {
        var binaryData: Data
        do {
            binaryData = try Data(contentsOf: binaryURL)
        } catch {
            throw MachOWriterError.fileWriteError("Failed to read binary at \(binaryURL.path): \(error.localizedDescription)")
        }

        try sign(binaryData: &binaryData, entitlements: entitlements, cert: cert, key: key)

        let destinationURL = outputURL ?? binaryURL
        do {
            try binaryData.write(to: destinationURL)
        } catch {
            throw MachOWriterError.fileWriteError("Failed to write signed binary to \(destinationURL.path): \(error.localizedDescription)")
        }
    }

    public func sign(
        binaryData: inout Data,
        entitlements: [String: Any]? = nil,
        cert: SecCertificate? = nil,
        key: SecKey? = nil,
        infoPlistData: Data? = nil,
        resourceDirData: Data? = nil
    ) throws {
        // 1. Determine base binary size (up to existing LC_CODE_SIGNATURE if present)
        let codeLimit = getBaseBinarySize(from: binaryData)

        // 2. Encode entitlements if provided
        var xmlData: Data? = nil
        var derData: Data? = nil

        if let entitlements, !entitlements.isEmpty {
            derData = try DEREncoder.encode(entitlements: entitlements)
            xmlData = try PropertyListSerialization.data(fromPropertyList: entitlements, format: .xml, options: 0)
        }

        // 3. Build CodeDirectory with page hashes and special slots
        let codeDirectory = CodeDirectoryBuilder.build(
            binaryData: binaryData,
            codeLimit: codeLimit,
            identifier: "GhostCode",
            xmlEntitlements: xmlData,
            derEntitlements: derData,
            infoPlistData: infoPlistData,
            resourceDirData: resourceDirData
        )

        // 4. Generate CMS signature if cert & key are provided
        var cmsSignature: Data? = nil
        if let cert = cert, let key = key {
            cmsSignature = try CMSSigner.signCodeDirectory(codeDirectoryData: codeDirectory, cert: cert, key: key)
        }

        // 5. Build SuperBlob containing CodeDirectory, XML entitlements, DER entitlements, and CMS blob
        let superBlob = SuperBlobBuilder.build(
            codeDirectory: codeDirectory,
            xmlEntitlements: xmlData,
            derEntitlements: derData,
            cmsSignature: cmsSignature
        )

        // 6. Inject SuperBlob into Mach-O binary
        try MachOWriter.injectCodeSignature(into: &binaryData, signatureData: superBlob)
    }

    public func signBundle(
        appURL: URL,
        cert: SecCertificate? = nil,
        key: SecKey? = nil,
        entitlements: [String: Any]? = nil
    ) throws {
        let fileManager = FileManager.default

        // 1. Sign nested frameworks bottom-up
        let frameworksURL = appURL.appendingPathComponent("Frameworks")
        if fileManager.fileExists(atPath: frameworksURL.path) {
            let frameworkItems = try? fileManager.contentsOfDirectory(at: frameworksURL, includingPropertiesForKeys: nil)
            for item in frameworkItems ?? [] {
                if item.pathExtension == "framework" {
                    let frameworkExeName = item.deletingPathExtension().lastPathComponent
                    let frameworkExeURL = item.appendingPathComponent(frameworkExeName)
                    if fileManager.fileExists(atPath: frameworkExeURL.path) {
                        try sign(binaryURL: frameworkExeURL, entitlements: nil, cert: cert, key: key)
                    }
                } else if item.pathExtension == "dylib" {
                    try sign(binaryURL: item, entitlements: nil, cert: cert, key: key)
                }
            }
        }

        // 2. Sign nested plugins
        let plugInsURL = appURL.appendingPathComponent("PlugIns")
        if fileManager.fileExists(atPath: plugInsURL.path) {
            let pluginItems = try? fileManager.contentsOfDirectory(at: plugInsURL, includingPropertiesForKeys: nil)
            for item in pluginItems ?? [] where item.pathExtension == "appex" {
                try signBundle(appURL: item, cert: cert, key: key, entitlements: entitlements)
            }
        }

        // 3. Generate CodeResources via BundleSealer
        let codeResourcesData = try BundleSealer.generateCodeResources(for: appURL)

        // 4. Locate main executable and Info.plist
        let infoPlistURL = appURL.appendingPathComponent("Info.plist")
        var mainExecutableURL: URL?

        if fileManager.fileExists(atPath: infoPlistURL.path) {
            if let data = try? Data(contentsOf: infoPlistURL),
               let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
               let exeName = plist["CFBundleExecutable"] as? String {
                let candidate = appURL.appendingPathComponent(exeName)
                if fileManager.fileExists(atPath: candidate.path) {
                    mainExecutableURL = candidate
                }
            }
        }

        if mainExecutableURL == nil {
            let appBaseName = appURL.deletingPathExtension().lastPathComponent
            let candidate = appURL.appendingPathComponent(appBaseName)
            if fileManager.fileExists(atPath: candidate.path) {
                mainExecutableURL = candidate
            }
        }

        guard let executableURL = mainExecutableURL else {
            throw MachOWriterError.fileWriteError("Could not locate main executable in bundle at \(appURL.path)")
        }

        let infoPlistData = try? Data(contentsOf: infoPlistURL)

        // 5. Sign main executable
        var exeData = try Data(contentsOf: executableURL)
        try sign(
            binaryData: &exeData,
            entitlements: entitlements,
            cert: cert,
            key: key,
            infoPlistData: infoPlistData,
            resourceDirData: codeResourcesData
        )
        try exeData.write(to: executableURL)
    }

    private func getBaseBinarySize(from data: Data) -> Int {
        guard data.count >= 32 else { return data.count }

        let ncmds = data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 16, as: UInt32.self))
        }
        let sizeofcmds = data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 20, as: UInt32.self))
        }

        let maxOffset = min(data.count, 32 + Int(sizeofcmds))
        var offset = 32

        for _ in 0..<ncmds {
            guard offset + 8 <= maxOffset else { break }
            let cmd = data.withUnsafeBytes { raw in
                UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
            }
            let cmdsize = data.withUnsafeBytes { raw in
                UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self))
            }

            guard cmdsize >= 8, offset + Int(cmdsize) <= maxOffset else { break }

            if cmd == MachOConstants.LC_CODE_SIGNATURE {
                guard cmdsize >= 16 else { break }
                let dataoff = data.withUnsafeBytes { raw in
                    UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset + 8, as: UInt32.self))
                }
                if dataoff > 0 && Int(dataoff) <= data.count {
                    return Int(dataoff)
                }
            }

            offset += Int(cmdsize)
        }

        return data.count
    }
}

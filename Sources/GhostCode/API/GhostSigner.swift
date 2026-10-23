import Foundation

public final class GhostSigner: @unchecked Sendable {
    public init() {}

    public static func sign(binaryURL: URL, entitlements: [String: Any]? = nil, outputURL: URL? = nil) throws {
        let signer = GhostSigner()
        try signer.sign(binaryURL: binaryURL, entitlements: entitlements, outputURL: outputURL)
    }

    public func sign(
        binaryURL: URL,
        identifier: String = "GhostCode",
        entitlements: [String: Any]? = nil,
        cert: SecCertificate? = nil,
        key: SecKey? = nil,
        rawCertificate: Data? = nil,
        rawPrivateKey: Data? = nil,
        teamID: String? = nil,
        outputURL: URL? = nil,
        isAdHoc: Bool? = nil
    ) throws {
        var binaryData: Data
        do {
            binaryData = try Data(contentsOf: binaryURL)
        } catch {
            throw MachOWriterError.fileWriteError("Failed to read binary at \(binaryURL.path): \(error.localizedDescription)")
        }

        try sign(
            binaryData: &binaryData,
            identifier: identifier,
            entitlements: entitlements,
            cert: cert,
            key: key,
            rawCertificate: rawCertificate,
            rawPrivateKey: rawPrivateKey,
            teamID: teamID,
            isAdHoc: isAdHoc
        )

        let destinationURL = outputURL ?? binaryURL
        do {
            try binaryData.write(to: destinationURL)
        } catch {
            throw MachOWriterError.fileWriteError("Failed to write signed binary to \(destinationURL.path): \(error.localizedDescription)")
        }
    }

    public func sign(
        binaryData: inout Data,
        identifier: String = "GhostCode",
        entitlements: [String: Any]? = nil,
        cert: SecCertificate? = nil,
        key: SecKey? = nil,
        rawCertificate: Data? = nil,
        rawPrivateKey: Data? = nil,
        infoPlistData: Data? = nil,
        resourceDirData: Data? = nil,
        teamID: String? = nil,
        isAdHoc: Bool? = nil
    ) throws {
        let hasRawCredentials = (rawCertificate != nil && rawPrivateKey != nil)
        let effectiveIsAdHoc = isAdHoc ?? (!hasRawCredentials && (cert == nil || key == nil))

        // 1. Determine base binary size (up to existing LC_CODE_SIGNATURE if present)
        let baseBinaryEnd = getBaseBinarySize(from: binaryData)
        let codeLimit = (baseBinaryEnd + 15) & ~15

        // If binary is smaller than codeLimit, pad with zeroes up to 16-byte boundary
        if binaryData.count < codeLimit {
            binaryData.append(Data(repeating: 0, count: codeLimit - binaryData.count))
        }

        // 2. Encode entitlements if provided
        var xmlData: Data? = nil
        var derData: Data? = nil

        if let entitlements, !entitlements.isEmpty {
            derData = try DEREncoder.encode(entitlements: entitlements)
            xmlData = try PropertyListSerialization.data(fromPropertyList: entitlements, format: .xml, options: 0)
        }

        // __TEXT vmsize and file type are unchanged by signature injection, so one read covers both passes.
        let reader = try MachOReader(data: binaryData)
        let execSegLimit = reader.textSegmentVMSize ?? 0
        let isExecutableImage = reader.isExecutableImage
        let getTaskAllow = entitlements?["get-task-allow"] as? Bool ?? false

        let buildCodeDirectory = { (data: Data) in
            CodeDirectoryBuilder.build(
                binaryData: data,
                codeLimit: codeLimit,
                identifier: identifier,
                xmlEntitlements: xmlData,
                derEntitlements: derData,
                infoPlistData: infoPlistData,
                resourceDirData: resourceDirData,
                teamID: teamID,
                execSegLimit: execSegLimit,
                isExecutableImage: isExecutableImage,
                getTaskAllow: getTaskAllow,
                isAdHoc: effectiveIsAdHoc
            )
        }

        // PASS 1: Build initial SuperBlob to establish exact length and offsets
        let initialCD = buildCodeDirectory(binaryData)

        var initialCMS: Data? = nil
        if let rawCert = rawCertificate, let rawKey = rawPrivateKey {
            initialCMS = try CMSSigner.signCodeDirectory(codeDirectoryData: initialCD, rawCertDER: rawCert, rawKeyDER: rawKey)
        } else if let cert = cert, let key = key {
            initialCMS = try CMSSigner.signCodeDirectory(codeDirectoryData: initialCD, cert: cert, key: key)
        }

        let initialSuperBlob = SuperBlobBuilder.build(
            codeDirectory: initialCD,
            xmlEntitlements: xmlData,
            derEntitlements: derData,
            cmsSignature: initialCMS
        )

        // Inject initial SuperBlob into Mach-O binary
        // This updates Mach-O headers, increments ncmds, updates sizeofcmds & __LINKEDIT,
        // and appends initialSuperBlob at codeLimit.
        try MachOWriter.injectCodeSignature(into: &binaryData, signatureData: initialSuperBlob)

        // PASS 2: Re-calculate CodeDirectory page hashes from modified binaryData
        // (Page 0 hash now matches the post-injection headers and load commands)
        let finalCD = buildCodeDirectory(binaryData)

        var finalCMS: Data? = nil
        if let rawCert = rawCertificate, let rawKey = rawPrivateKey {
            finalCMS = try CMSSigner.signCodeDirectory(codeDirectoryData: finalCD, rawCertDER: rawCert, rawKeyDER: rawKey)
        } else if let cert = cert, let key = key {
            finalCMS = try CMSSigner.signCodeDirectory(codeDirectoryData: finalCD, cert: cert, key: key)
        }

        let finalSuperBlob = SuperBlobBuilder.build(
            codeDirectory: finalCD,
            xmlEntitlements: xmlData,
            derEntitlements: derData,
            cmsSignature: finalCMS
        )

        // Overwrite the signature at the end of binaryData in-place
        let sigOffset = binaryData.count - initialSuperBlob.count
        if finalSuperBlob.count == initialSuperBlob.count && sigOffset >= 0 {
            binaryData.replaceSubrange(sigOffset..<binaryData.count, with: finalSuperBlob)
        } else {
            try MachOWriter.injectCodeSignature(into: &binaryData, signatureData: finalSuperBlob)
        }
    }

    public func signBundle(
        appURL: URL,
        provisioningProfileURL: URL? = nil,
        cert: SecCertificate? = nil,
        key: SecKey? = nil,
        rawCertificate: Data? = nil,
        rawPrivateKey: Data? = nil,
        entitlements: [String: Any]? = nil,
        teamID: String? = nil
    ) throws {
        let fileManager = FileManager.default
        let hasRawCredentials = (rawCertificate != nil && rawPrivateKey != nil)
        let isAdHoc = !hasRawCredentials && (cert == nil || key == nil)

        // Handle provisioning profile if provided
        let embeddedProvURL = appURL.appendingPathComponent("embedded.mobileprovision")
        if let profileURL = provisioningProfileURL {
            if fileManager.fileExists(atPath: embeddedProvURL.path) {
                try? fileManager.removeItem(at: embeddedProvURL)
            }
            try fileManager.copyItem(at: profileURL, to: embeddedProvURL)
        }

        // 1. Locate Info.plist and read CFBundleIdentifier & CFBundleExecutable
        let infoPlistURL = appURL.appendingPathComponent("Info.plist")
        var bundleID = "GhostCode"
        var exeName: String?
        var infoPlistData: Data? = nil

        if fileManager.fileExists(atPath: infoPlistURL.path) {
            if let data = try? Data(contentsOf: infoPlistURL) {
                infoPlistData = data
                if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] {
                    if let id = plist["CFBundleIdentifier"] as? String, !id.isEmpty {
                        bundleID = id
                    }
                    if let name = plist["CFBundleExecutable"] as? String, !name.isEmpty {
                        exeName = name
                    }
                }
            }
        }

        // 2. Locate main executable URL
        var mainExecutableURL: URL?
        if let exeName = exeName {
            let candidate = appURL.appendingPathComponent(exeName)
            if fileManager.fileExists(atPath: candidate.path) {
                mainExecutableURL = candidate
            }
        }
        if mainExecutableURL == nil {
            let appBaseName = appURL.deletingPathExtension().lastPathComponent
            let candidate = appURL.appendingPathComponent(appBaseName)
            if fileManager.fileExists(atPath: candidate.path) {
                mainExecutableURL = candidate
                exeName = appBaseName
            }
        }

        guard let executableURL = mainExecutableURL else {
            throw MachOWriterError.fileWriteError("Could not locate main executable in bundle at \(appURL.path)")
        }

        // 3. Determine bundle entitlements: use provided, extract from embedded.mobileprovision if nil, or default
        var profileData: Data? = nil
        if fileManager.fileExists(atPath: embeddedProvURL.path) {
            profileData = try? Data(contentsOf: embeddedProvURL)
        }
        let profile = profileData.flatMap { GhostSigner.provisioningProfileDictionary(from: $0) }
        let profileEntitlements = profile?["Entitlements"] as? [String: Any]

        let bundleEntitlements: [String: Any]
        if let entitlements = entitlements {
            bundleEntitlements = entitlements
        } else if let profileEntitlements, !profileEntitlements.isEmpty {
            bundleEntitlements = profileEntitlements
        } else {
            bundleEntitlements = [
                "get-task-allow": true,
                "application-identifier": bundleID
            ]
        }

        // The team identifier comes from the profile (TeamIdentifier[0]) and is required by every
        // non-ad-hoc signature; fall back to the entitlement that Apple mirrors it into.
        let effectiveTeamID = teamID
            ?? (profile?["TeamIdentifier"] as? [String])?.first
            ?? bundleEntitlements["com.apple.developer.team-identifier"] as? String

        // 4. Sign nested frameworks bottom-up
        let frameworksURL = appURL.appendingPathComponent("Frameworks")
        if fileManager.fileExists(atPath: frameworksURL.path) {
            let frameworkItems = try? fileManager.contentsOfDirectory(at: frameworksURL, includingPropertiesForKeys: nil)
            for item in frameworkItems ?? [] {
                if item.pathExtension == "framework" {
                    let frameworkExeName = item.deletingPathExtension().lastPathComponent
                    let frameworkExeURL = item.appendingPathComponent(frameworkExeName)
                    if fileManager.fileExists(atPath: frameworkExeURL.path) {
                        try sign(binaryURL: frameworkExeURL, identifier: frameworkExeName, entitlements: nil, cert: cert, key: key, rawCertificate: rawCertificate, rawPrivateKey: rawPrivateKey, teamID: effectiveTeamID, isAdHoc: isAdHoc)
                    }
                } else if item.pathExtension == "dylib" {
                    let dylibName = item.deletingPathExtension().lastPathComponent
                    try sign(binaryURL: item, identifier: dylibName, entitlements: nil, cert: cert, key: key, rawCertificate: rawCertificate, rawPrivateKey: rawPrivateKey, teamID: effectiveTeamID, isAdHoc: isAdHoc)
                }
            }
        }

        // 5. Sign nested plugins
        let plugInsURL = appURL.appendingPathComponent("PlugIns")
        if fileManager.fileExists(atPath: plugInsURL.path) {
            let pluginItems = try? fileManager.contentsOfDirectory(at: plugInsURL, includingPropertiesForKeys: nil)
            for item in pluginItems ?? [] where item.pathExtension == "appex" {
                try signBundle(appURL: item, cert: cert, key: key, rawCertificate: rawCertificate, rawPrivateKey: rawPrivateKey, entitlements: bundleEntitlements, teamID: effectiveTeamID)
            }
        }

        // 6. Generate CodeResources via BundleSealer (pass executableName to exclude it)
        let codeResourcesData = try BundleSealer.generateCodeResources(for: appURL, executableName: exeName)

        // 7. Sign main executable
        var exeData = try Data(contentsOf: executableURL)
        try sign(
            binaryData: &exeData,
            identifier: bundleID,
            entitlements: bundleEntitlements,
            cert: cert,
            key: key,
            rawCertificate: rawCertificate,
            rawPrivateKey: rawPrivateKey,
            infoPlistData: infoPlistData,
            resourceDirData: codeResourcesData,
            teamID: effectiveTeamID,
            isAdHoc: isAdHoc
        )
        try exeData.write(to: executableURL)
    }

    /// Parses the XML plist embedded inside a CMS-wrapped provisioning profile.
    public static func provisioningProfileDictionary(from data: Data) -> [String: Any]? {
        guard let str = String(data: data, encoding: .isoLatin1),
              let startRange = str.range(of: "<plist", options: .caseInsensitive),
              let endRange = str.range(of: "</plist>", options: [.caseInsensitive, .backwards]),
              startRange.lowerBound < endRange.upperBound else {
            return nil
        }
        let xmlSubstring = str[startRange.lowerBound..<endRange.upperBound]
        guard let xmlData = xmlSubstring.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: xmlData, options: [], format: nil) as? [String: Any] else {
            return nil
        }
        return plist
    }

    /// Extracts the Entitlements dictionary from an embedded.mobileprovision or provisioning profile data.
    public static func extractEntitlements(fromMobileProvisionData data: Data) -> [String: Any]? {
        provisioningProfileDictionary(from: data)?["Entitlements"] as? [String: Any]
    }

    /// The provisioning profile's team ID, which `TeamIdentifier` stores as an array whose first
    /// entry is authoritative. Required for any non-ad-hoc CodeDirectory's `teamOffset`.
    public static func extractTeamIdentifier(fromMobileProvisionData data: Data) -> String? {
        guard let profile = provisioningProfileDictionary(from: data) else {
            return nil
        }
        if let team = (profile["TeamIdentifier"] as? [String])?.first, !team.isEmpty {
            return team
        }
        return (profile["Entitlements"] as? [String: Any])?["com.apple.developer.team-identifier"] as? String
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

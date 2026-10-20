import Foundation
import GhostCode

#if canImport(Security) && os(macOS)
import Security
#endif

struct CLIArgs {
    var p12Path: String?
    var password: String?
    var provisionPath: String?
    var targetPath: String?
    var entitlementsPath: String?
    var outputPath: String?
    var adhoc: Bool = false
}

func parseArguments(_ args: [String]) -> CLIArgs {
    var parsed = CLIArgs()
    var i = 1
    while i < args.count {
        let arg = args[i]
        switch arg {
        case "--adhoc":
            parsed.adhoc = true
        case "--p12":
            if i + 1 < args.count { parsed.p12Path = args[i + 1]; i += 1 }
        case "--password":
            if i + 1 < args.count { parsed.password = args[i + 1]; i += 1 }
        case "--provision":
            if i + 1 < args.count { parsed.provisionPath = args[i + 1]; i += 1 }
        case "--entitlements":
            if i + 1 < args.count { parsed.entitlementsPath = args[i + 1]; i += 1 }
        case "--output", "-o":
            if i + 1 < args.count { parsed.outputPath = args[i + 1]; i += 1 }
        default:
            if !arg.hasPrefix("-") && parsed.targetPath == nil {
                parsed.targetPath = arg
            }
        }
        i += 1
    }
    return parsed
}

struct CLIError: Error, CustomStringConvertible {
    let description: String
}

func loadCredentials(p12Path: String?, password: String?, adhoc: Bool) throws -> (SecCertificate?, SecKey?) {
    if adhoc {
        return (nil, nil)
    }
    guard let p12Path = p12Path else {
        return (nil, nil)
    }
    let p12URL = URL(fileURLWithPath: p12Path)
    guard let p12Data = try? Data(contentsOf: p12URL) else {
        throw CLIError(description: "Could not read PKCS#12 file at \(p12Path)")
    }

    #if canImport(Security) && os(macOS)
    var items: CFArray?
    let options: [String: Any] = [
        kSecImportExportPassphrase as String: password ?? ""
    ]
    let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
    if status == errSecSuccess, let itemsArray = items as? [[String: Any]], let first = itemsArray.first {
        let identity = first[kSecImportItemIdentity as String] as! SecIdentity
        var cert: SecCertificate?
        SecIdentityCopyCertificate(identity, &cert)
        var key: SecKey?
        SecIdentityCopyPrivateKey(identity, &key)
        return (cert, key)
    } else {
        fputs("Warning: SecPKCS12Import failed with status \(status), using raw credentials\n", stderr)
        return (SecCertificate(data: p12Data), SecKey(keyData: p12Data))
    }
    #else
    let cert = SecCertificate(data: p12Data)
    let key = SecKey(keyData: p12Data)
    return (cert, key)
    #endif
}

@discardableResult
func runCommand(_ executable: String, _ arguments: [String], currentDirectory: URL? = nil) throws -> Int32 {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    if let currentDirectory = currentDirectory {
        process.currentDirectoryURL = currentDirectory
    }
    try process.run()
    process.waitUntilExit()
    return process.terminationStatus
}

func main() {
    let args = parseArguments(CommandLine.arguments)
    guard let targetPath = args.targetPath else {
        print("Usage: GhostCLI <target.app or .ipa or binary> [--adhoc] [--p12 <path>] [--password <pass>] [--provision <path>] [--entitlements <path>] [--output <path>]")
        return
    }

    let targetURL = URL(fileURLWithPath: targetPath)
    var entitlements: [String: Any]? = nil

    if let entPath = args.entitlementsPath {
        let entURL = URL(fileURLWithPath: entPath)
        if let data = try? Data(contentsOf: entURL),
           let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] {
            entitlements = plist
        }
    }

    let provURL = args.provisionPath.map { URL(fileURLWithPath: $0) }
    let signer = GhostSigner()

    do {
        let (cert, key) = try loadCredentials(p12Path: args.p12Path, password: args.password, adhoc: args.adhoc)

        if targetURL.pathExtension.lowercased() == "ipa" {
            let outputPath = args.outputPath ?? targetURL.path
            let destinationURL = URL(fileURLWithPath: outputPath).standardized
            let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("ghostcli_\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: tempDir) }

            print("Unpacking IPA: \(targetURL.path)...")
            let unzipTool = FileManager.default.fileExists(atPath: "/usr/bin/unzip") ? "/usr/bin/unzip" : "/usr/bin/env"
            let unzipArgs = unzipTool == "/usr/bin/env" ? ["unzip", "-q", targetURL.path, "-d", tempDir.path] : ["-q", targetURL.path, "-d", tempDir.path]
            let unzipStatus = try runCommand(unzipTool, unzipArgs)
            guard unzipStatus == 0 else {
                throw CLIError(description: "Failed to unpack IPA with exit code \(unzipStatus)")
            }

            let payloadURL = tempDir.appendingPathComponent("Payload")
            guard FileManager.default.fileExists(atPath: payloadURL.path) else {
                throw CLIError(description: "Payload directory missing in IPA")
            }

            let payloadItems = try FileManager.default.contentsOfDirectory(at: payloadURL, includingPropertiesForKeys: nil)
            guard let appURL = payloadItems.first(where: { $0.pathExtension == "app" }) else {
                throw CLIError(description: "No .app bundle found inside Payload directory")
            }

            print("Signing bundle: \(appURL.path)...")
            try signer.signBundle(
                appURL: appURL,
                provisioningProfileURL: provURL,
                cert: cert,
                key: key,
                entitlements: entitlements
            )

            print("Repackaging IPA into \(destinationURL.path)...")
            if FileManager.default.fileExists(atPath: destinationURL.path) {
                try? FileManager.default.removeItem(at: destinationURL)
            }
            try FileManager.default.createDirectory(at: destinationURL.deletingLastPathComponent(), withIntermediateDirectories: true)

            let zipTool = FileManager.default.fileExists(atPath: "/usr/bin/zip") ? "/usr/bin/zip" : "/usr/bin/env"
            let zipArgs = zipTool == "/usr/bin/env" ? ["zip", "-qry", destinationURL.path, "Payload"] : ["-qry", destinationURL.path, "Payload"]
            let zipStatus = try runCommand(zipTool, zipArgs, currentDirectory: tempDir)
            guard zipStatus == 0 else {
                throw CLIError(description: "Failed to repackage IPA with exit code \(zipStatus)")
            }

            print("Successfully signed IPA: \(destinationURL.path)")
        } else {
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: targetURL.path, isDirectory: &isDir), isDir.boolValue, targetURL.pathExtension == "app" {
                if let outPath = args.outputPath, outPath.hasSuffix(".ipa") {
                    let destinationURL = URL(fileURLWithPath: outPath).standardized
                    let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("ghostcli_\(UUID().uuidString)")
                    let payloadDir = tempDir.appendingPathComponent("Payload")
                    try FileManager.default.createDirectory(at: payloadDir, withIntermediateDirectories: true)
                    defer { try? FileManager.default.removeItem(at: tempDir) }

                    let destAppURL = payloadDir.appendingPathComponent(targetURL.lastPathComponent)
                    try FileManager.default.copyItem(at: targetURL, to: destAppURL)

                    print("Signing bundle: \(destAppURL.path)...")
                    try signer.signBundle(
                        appURL: destAppURL,
                        provisioningProfileURL: provURL,
                        cert: cert,
                        key: key,
                        entitlements: entitlements
                    )

                    print("Packaging bundle into IPA: \(destinationURL.path)...")
                    if FileManager.default.fileExists(atPath: destinationURL.path) {
                        try? FileManager.default.removeItem(at: destinationURL)
                    }
                    try FileManager.default.createDirectory(at: destinationURL.deletingLastPathComponent(), withIntermediateDirectories: true)

                    let zipTool = FileManager.default.fileExists(atPath: "/usr/bin/zip") ? "/usr/bin/zip" : "/usr/bin/env"
                    let zipArgs = zipTool == "/usr/bin/env" ? ["zip", "-qry", destinationURL.path, "Payload"] : ["-qry", destinationURL.path, "Payload"]
                    let zipStatus = try runCommand(zipTool, zipArgs, currentDirectory: tempDir)
                    guard zipStatus == 0 else {
                        throw CLIError(description: "Failed to package IPA with exit code \(zipStatus)")
                    }
                    print("Successfully signed and packaged IPA: \(destinationURL.path)")
                } else {
                    let targetAppURL: URL
                    if let outPath = args.outputPath {
                        let outURL = URL(fileURLWithPath: outPath).standardized
                        if outURL.path != targetURL.standardized.path {
                            if FileManager.default.fileExists(atPath: outURL.path) {
                                try? FileManager.default.removeItem(at: outURL)
                            }
                            try FileManager.default.createDirectory(at: outURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                            try FileManager.default.copyItem(at: targetURL, to: outURL)
                        }
                        targetAppURL = outURL
                    } else {
                        targetAppURL = targetURL
                    }

                    print("Signing bundle: \(targetAppURL.path)...")
                    try signer.signBundle(
                        appURL: targetAppURL,
                        provisioningProfileURL: provURL,
                        cert: cert,
                        key: key,
                        entitlements: entitlements
                    )
                    print("Successfully signed bundle.")
                }
            } else {
                print("Signing binary: \(targetURL.path)...")
                var binaryEntitlements = entitlements
                if binaryEntitlements == nil, let pURL = provURL, let pData = try? Data(contentsOf: pURL) {
                    binaryEntitlements = GhostSigner.extractEntitlements(fromMobileProvisionData: pData)
                }
                let outURL = args.outputPath.map { URL(fileURLWithPath: $0) }
                try signer.sign(
                    binaryURL: targetURL,
                    entitlements: binaryEntitlements,
                    cert: cert,
                    key: key,
                    outputURL: outURL,
                    isAdHoc: args.adhoc ? true : (cert == nil || key == nil)
                )
                print("Successfully signed binary.")
            }
        }
    } catch {
        fputs("Error signing: \(error)\n", stderr)
        exit(1)
    }
}

main()

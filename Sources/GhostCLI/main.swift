import Foundation
import GhostCode

struct CLIArgs {
    var p12Path: String?
    var password: String?
    var provisionPath: String?
    var targetPath: String?
    var entitlementsPath: String?
    var outputPath: String?
}

func parseArguments(_ args: [String]) -> CLIArgs {
    var parsed = CLIArgs()
    var i = 1
    while i < args.count {
        let arg = args[i]
        switch arg {
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

func main() {
    let args = parseArguments(CommandLine.arguments)
    guard let targetPath = args.targetPath else {
        print("Usage: GhostCLI <target.app or binary> [--p12 <path>] [--password <pass>] [--provision <path>] [--entitlements <path>] [--output <path>]")
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

    let signer = GhostSigner()

    do {
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: targetURL.path, isDirectory: &isDir), isDir.boolValue, targetURL.pathExtension == "app" {
            print("Signing bundle: \(targetURL.path)...")
            try signer.signBundle(appURL: targetURL, entitlements: entitlements)
            print("Successfully signed bundle.")
        } else {
            print("Signing binary: \(targetURL.path)...")
            let outURL = args.outputPath.map { URL(fileURLWithPath: $0) }
            try signer.sign(binaryURL: targetURL, entitlements: entitlements, outputURL: outURL)
            print("Successfully signed binary.")
        }
    } catch {
        fputs("Error signing: \(error)\n", stderr)
        exit(1)
    }
}

main()

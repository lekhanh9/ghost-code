import Foundation

public enum BundleSealerError: Error, LocalizedError, Equatable {
    case enumerationFailed(String)
    case unreadableFile(String)
    case serializationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .enumerationFailed(let path):
            return "Failed to enumerate bundle at \(path)"
        case .unreadableFile(let path):
            return "Failed to read file at \(path)"
        case .serializationFailed(let reason):
            return "Failed to serialize CodeResources plist: \(reason)"
        }
    }
}

public final class BundleSealer: Sendable {

    /// Default code signing resource rules for v1 (files) matching Apple codesign specification.
    public static let defaultRules: [String: any Sendable] = [
        "^.*": true,
        "^.*\\.lproj/": [
            "optional": true,
            "weight": 1000.0
        ],
        "^.*\\.lproj/locversion.plist$": [
            "omit": true,
            "weight": 1100.0
        ],
        "^Base\\.lproj/": [
            "weight": 1010.0
        ],
        "^version.plist$": true
    ]

    /// Default code signing resource rules for v2 (files2) matching Apple codesign specification.
    public static let defaultRules2: [String: any Sendable] = [
        ".*\\.dSYM($|/)": [
            "weight": 11.0
        ],
        "^(.*/)?\\.DS_Store$": [
            "omit": true,
            "weight": 2000.0
        ],
        "^.*": true,
        "^.*\\.lproj/": [
            "optional": true,
            "weight": 1000.0
        ],
        "^.*\\.lproj/locversion.plist$": [
            "omit": true,
            "weight": 1100.0
        ],
        "^Base\\.lproj/": [
            "weight": 1010.0
        ],
        "^Info\\.plist$": [
            "omit": true,
            "weight": 20.0
        ],
        "^PkgInfo$": [
            "omit": true,
            "weight": 20.0
        ],
        "^embedded\\.provisionprofile$": [
            "weight": 20.0
        ],
        "^version\\.plist$": [
            "weight": 20.0
        ]
    ]

    public let bundleURL: URL
    public let executableName: String?
    public let rules: [String: any Sendable]
    public let rules2: [String: any Sendable]

    public init(
        bundleURL: URL,
        executableName: String? = nil,
        rules: [String: any Sendable] = BundleSealer.defaultRules,
        rules2: [String: any Sendable] = BundleSealer.defaultRules2
    ) {
        self.bundleURL = bundleURL
        self.executableName = executableName
        self.rules = rules
        self.rules2 = rules2
    }

    /// Generates _CodeSignature/CodeResources XML plist data for the given app bundle.
    /// Also writes the plist to `[appURL]/_CodeSignature/CodeResources` when `writeToBundle` is true.
    @discardableResult
    public static func generateCodeResources(
        for appURL: URL,
        executableName: String? = nil,
        writeToBundle: Bool = true,
        rules: [String: any Sendable] = BundleSealer.defaultRules,
        rules2: [String: any Sendable] = BundleSealer.defaultRules2
    ) throws -> Data {
        let sealer = BundleSealer(bundleURL: appURL, executableName: executableName, rules: rules, rules2: rules2)
        let data = try sealer.buildData()
        if writeToBundle {
            try writeCodeResources(data, to: appURL)
        }
        return data
    }

    /// Seals the bundle by generating CodeResources and writing it to `[appURL]/_CodeSignature/CodeResources`.
    @discardableResult
    public static func seal(
        appURL: URL,
        executableName: String? = nil,
        rules: [String: any Sendable] = BundleSealer.defaultRules,
        rules2: [String: any Sendable] = BundleSealer.defaultRules2
    ) throws -> Data {
        return try generateCodeResources(
            for: appURL,
            executableName: executableName,
            writeToBundle: true,
            rules: rules,
            rules2: rules2
        )
    }

    /// Instance method to build the XML plist data.
    public func build() throws -> Data {
        return try buildData()
    }

    /// Instance method to seal the bundle and write CodeResources to disk.
    @discardableResult
    public func seal() throws -> Data {
        let data = try buildData()
        try Self.writeCodeResources(data, to: bundleURL)
        return data
    }

    private static func writeCodeResources(_ data: Data, to appURL: URL) throws {
        let sigDir = appURL.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: sigDir, withIntermediateDirectories: true)
        let codeResourcesURL = sigDir.appendingPathComponent("CodeResources")
        try data.write(to: codeResourcesURL, options: .atomic)
    }

    private func buildData() throws -> Data {
        let fileManager = FileManager.default
        let canonicalBundleURL = bundleURL.resolvingSymlinksInPath()
        let bundlePath = canonicalBundleURL.path
        let bundlePathPrefix = bundlePath.hasSuffix("/") ? bundlePath : bundlePath + "/"

        // Determine executable name from Info.plist if not explicitly provided
        var execName = executableName
        if execName == nil {
            let infoURL = canonicalBundleURL.appendingPathComponent("Info.plist")
            if let data = try? Data(contentsOf: infoURL),
               let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
               let name = plist["CFBundleExecutable"] as? String {
                execName = name
            }
        }

        var isBundleDir: ObjCBool = false
        guard fileManager.fileExists(atPath: canonicalBundleURL.path, isDirectory: &isBundleDir), isBundleDir.boolValue else {
            throw BundleSealerError.enumerationFailed(bundleURL.path)
        }

        guard let enumerator = fileManager.enumerator(
            at: canonicalBundleURL,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .isDirectoryKey],
            options: []
        ) else {
            throw BundleSealerError.enumerationFailed(bundleURL.path)
        }

        struct CandidateFile {
            let relativePath: String
            let url: URL
        }

        var candidateFiles: [CandidateFile] = []

        for case let fileURL as URL in enumerator {
            let standardized = fileURL.path
            guard standardized.hasPrefix(bundlePathPrefix) else { continue }
            let relativePath = String(standardized.dropFirst(bundlePathPrefix.count))

            // Ignore the current bundle's own _CodeSignature directory and its contents
            if relativePath == "_CodeSignature" || relativePath.hasPrefix("_CodeSignature/") {
                continue
            }

            // Exclude directories (both direct directories and symlinks pointing to directories)
            var isDir: ObjCBool = false
            if fileManager.fileExists(atPath: fileURL.path, isDirectory: &isDir), isDir.boolValue {
                continue
            }

            let canonicalFileURL = fileURL.resolvingSymlinksInPath()
            var isCanonicalDir: ObjCBool = false
            if fileManager.fileExists(atPath: canonicalFileURL.path, isDirectory: &isCanonicalDir), isCanonicalDir.boolValue {
                continue
            }

            // Exclude main executable binary
            if let execName = execName, relativePath == execName {
                continue
            }

            candidateFiles.append(CandidateFile(relativePath: relativePath, url: fileURL))
        }

        // Sort files deterministically
        candidateFiles.sort { $0.relativePath < $1.relativePath }

        let compiledRules = rules.compactMap { CompiledRule(pattern: $0.key, config: $0.value) }
        let compiledRules2 = rules2.compactMap { CompiledRule(pattern: $0.key, config: $0.value) }

        var files: [String: Any] = [:]
        var files2: [String: [String: Any]] = [:]

        for candidate in candidateFiles {
            let fileData: Data
            do {
                fileData = try Data(contentsOf: candidate.url)
            } catch {
                throw BundleSealerError.unreadableFile(candidate.url.path)
            }

            let sha1 = CryptoHelpers.sha1(fileData)
            let sha256 = CryptoHelpers.sha256(fileData)

            let eval1 = Self.evaluate(path: candidate.relativePath, against: compiledRules)
            if !eval1.omit {
                if eval1.optional {
                    files[candidate.relativePath] = [
                        "hash": sha1,
                        "optional": true
                    ]
                } else {
                    files[candidate.relativePath] = sha1
                }
            }

            let eval2 = Self.evaluate(path: candidate.relativePath, against: compiledRules2)
            if !eval2.omit {
                var entry: [String: Any] = [
                    "hash2": sha256
                ]
                if eval2.optional {
                    entry["optional"] = true
                }
                files2[candidate.relativePath] = entry
            }
        }

        let plistDict: [String: Any] = [
            "files": files,
            "files2": files2,
            "rules": rules,
            "rules2": rules2
        ]

        do {
            return try PropertyListSerialization.data(fromPropertyList: plistDict, format: .xml, options: 0)
        } catch {
            throw BundleSealerError.serializationFailed(error.localizedDescription)
        }
    }

    private struct CompiledRule {
        let pattern: String
        let regex: NSRegularExpression
        let weight: Double
        let omit: Bool
        let optional: Bool

        init?(pattern: String, config: any Sendable) {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
            self.pattern = pattern
            self.regex = regex

            if let dict = config as? [String: any Sendable] {
                self.weight = (dict["weight"] as? Double) ?? (dict["weight"] as? NSNumber)?.doubleValue ?? 1.0
                self.omit = (dict["omit"] as? Bool) ?? false
                self.optional = (dict["optional"] as? Bool) ?? false
            } else if let boolVal = config as? Bool {
                self.weight = 1.0
                self.omit = !boolVal
                self.optional = false
            } else {
                self.weight = 1.0
                self.omit = false
                self.optional = false
            }
        }

        func matches(_ path: String) -> Bool {
            let range = NSRange(path.startIndex..<path.endIndex, in: path)
            return regex.firstMatch(in: path, options: [], range: range) != nil
        }
    }

    private struct RuleEvaluation {
        let omit: Bool
        let optional: Bool
    }

    private static func evaluate(path: String, against rules: [CompiledRule]) -> RuleEvaluation {
        var bestWeight: Double = -Double.infinity
        var winningRule: CompiledRule?

        for rule in rules {
            if rule.matches(path) {
                if rule.weight > bestWeight {
                    bestWeight = rule.weight
                    winningRule = rule
                }
            }
        }

        guard let winner = winningRule else {
            return RuleEvaluation(omit: false, optional: false)
        }
        return RuleEvaluation(omit: winner.omit, optional: winner.optional)
    }
}

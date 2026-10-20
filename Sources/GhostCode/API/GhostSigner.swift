import Foundation

public final class GhostSigner: @unchecked Sendable {
    public init() {}

    public static func sign(binaryURL: URL, entitlements: [String: Any]? = nil, outputURL: URL? = nil) throws {
        let signer = GhostSigner()
        try signer.sign(binaryURL: binaryURL, entitlements: entitlements, outputURL: outputURL)
    }

    public func sign(binaryURL: URL, entitlements: [String: Any]? = nil, outputURL: URL? = nil) throws {
        var binaryData: Data
        do {
            binaryData = try Data(contentsOf: binaryURL)
        } catch {
            throw MachOWriterError.fileWriteError("Failed to read binary at \(binaryURL.path): \(error.localizedDescription)")
        }

        try sign(binaryData: &binaryData, entitlements: entitlements)

        let destinationURL = outputURL ?? binaryURL
        do {
            try binaryData.write(to: destinationURL)
        } catch {
            throw MachOWriterError.fileWriteError("Failed to write signed binary to \(destinationURL.path): \(error.localizedDescription)")
        }
    }

    public func sign(binaryData: inout Data, entitlements: [String: Any]? = nil) throws {
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
            derEntitlements: derData
        )

        // 4. Build SuperBlob containing CodeDirectory, XML entitlements, and DER entitlements
        let superBlob = SuperBlobBuilder.build(
            codeDirectory: codeDirectory,
            xmlEntitlements: xmlData,
            derEntitlements: derData
        )

        // 5. Inject SuperBlob into Mach-O binary
        try MachOWriter.injectCodeSignature(into: &binaryData, signatureData: superBlob)
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

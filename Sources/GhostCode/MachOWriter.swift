import Foundation

public enum MachOWriterError: Swift.Error, Equatable {
    case fileTooSmall
    case invalidMagic(UInt32)
    case malformedLoadCommands
    case linkeditSegmentNotFound
    case insufficientHeaderSpace
    case offsetOverflow
    case fileWriteError(String)
}

public final class MachOWriter: @unchecked Sendable {
    public typealias Error = MachOWriterError

    public static func injectCodeSignature(into fileURL: URL, signatureData: Data) throws {
        var data: Data
        do {
            data = try Data(contentsOf: fileURL)
        } catch {
            throw Error.fileWriteError("Failed to read file at \(fileURL.path): \(error.localizedDescription)")
        }

        try injectCodeSignature(into: &data, signatureData: signatureData)

        do {
            try data.write(to: fileURL)
        } catch {
            throw Error.fileWriteError("Failed to write updated Mach-O to \(fileURL.path): \(error.localizedDescription)")
        }
    }

    public static func injectCodeSignature(into data: inout Data, signatureData: Data) throws {
        guard data.count >= MemoryLayout<MachHeader64>.size else {
            throw Error.fileTooSmall
        }

        // 1. Read & Validate Mach Header
        let magic = data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 0, as: UInt32.self))
        }
        guard magic == MachOConstants.MH_MAGIC_64 else {
            throw Error.invalidMagic(magic)
        }

        var ncmds = data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 16, as: UInt32.self))
        }
        var sizeofcmds = data.withUnsafeBytes { raw in
            UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 20, as: UInt32.self))
        }

        let currentOffset = MemoryLayout<MachHeader64>.size
        let loadCommandsEnd = currentOffset + Int(sizeofcmds)
        guard loadCommandsEnd <= data.count else {
            throw Error.malformedLoadCommands
        }

        var linkeditOffset: Int?
        var linkeditFileoff: UInt64 = 0
        var linkeditVmsize: UInt64 = 0
        var codeSignatureCmdOffset: Int?
        var existingDataoff: UInt32?
        var minDataFileOffset: Int = data.count

        // 2. Scan Load Commands
        try data.withUnsafeBytes { raw in
            var offset = currentOffset
            for _ in 0..<ncmds {
                guard offset + 8 <= loadCommandsEnd else {
                    throw Error.malformedLoadCommands
                }

                let cmd = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
                let cmdsize = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self))

                guard cmdsize >= 8, offset + Int(cmdsize) <= loadCommandsEnd else {
                    throw Error.malformedLoadCommands
                }

                if cmd == MachOConstants.LC_SEGMENT_64 {
                    guard cmdsize >= 72 else { throw Error.malformedLoadCommands }
                    let segnamePtr = raw.baseAddress!.advanced(by: offset + 8)
                    let segname = String(
                        decoding: UnsafeRawBufferPointer(start: segnamePtr, count: 16).prefix(while: { $0 != 0 }),
                        as: UTF8.self
                    )

                    let fileoff = UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: offset + 40, as: UInt64.self))
                    let vmsize = UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: offset + 32, as: UInt64.self))

                    if fileoff > 0 && Int(fileoff) < minDataFileOffset {
                        minDataFileOffset = Int(fileoff)
                    }

                    if segname == "__LINKEDIT" {
                        linkeditOffset = offset
                        linkeditFileoff = fileoff
                        linkeditVmsize = vmsize
                    }
                } else if cmd == MachOConstants.LC_CODE_SIGNATURE {
                    guard cmdsize >= 16 else { throw Error.malformedLoadCommands }
                    codeSignatureCmdOffset = offset
                    existingDataoff = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset + 8, as: UInt32.self))
                }

                offset += Int(cmdsize)
            }
        }

        guard let linkeditOffset else {
            throw Error.linkeditSegmentNotFound
        }

        // 3. Determine Base Binary End (strip existing signature if present)
        let binaryBaseEnd: Int
        if let existingDataoff, let codeSignatureCmdOffset {
            guard Int(existingDataoff) <= data.count else {
                throw Error.malformedLoadCommands
            }
            binaryBaseEnd = Int(existingDataoff)
            _ = codeSignatureCmdOffset
        } else {
            binaryBaseEnd = data.count
        }

        // 4. Align Signature Offset to 16 bytes
        let alignedSignatureOffset = (binaryBaseEnd + 15) & ~15
        guard alignedSignatureOffset <= UInt32.max else {
            throw Error.offsetOverflow
        }

        // Truncate back to binary base and insert padding up to aligned offset
        if data.count > binaryBaseEnd {
            data.removeSubrange(binaryBaseEnd..<data.count)
        }
        if alignedSignatureOffset > binaryBaseEnd {
            let paddingCount = alignedSignatureOffset - binaryBaseEnd
            data.append(Data(repeating: 0, count: paddingCount))
        }

        // 5. Append Signature Data
        data.append(signatureData)
        let newFileSize = data.count

        // 6. Update __LINKEDIT segment filesize and vmsize
        guard UInt64(newFileSize) >= linkeditFileoff else {
            throw Error.malformedLoadCommands
        }
        let newLinkeditFilesize = UInt64(newFileSize) - linkeditFileoff

        // Page alignment: 16KB (0x4000) for iOS ARM64 or 4KB (0x1000) for macOS x86_64
        let pageSize: UInt64 = (linkeditVmsize > 0 && linkeditVmsize % 0x4000 == 0) ? 0x4000 : 0x1000
        let newLinkeditVmsize = (newLinkeditFilesize + (pageSize - 1)) & ~(pageSize - 1)

        data.writeUnaligned(newLinkeditVmsize, at: linkeditOffset + 32)
        data.writeUnaligned(newLinkeditFilesize, at: linkeditOffset + 48)

        // 7. Update or Insert LC_CODE_SIGNATURE command
        if let codeSignatureCmdOffset {
            data.writeUnaligned(UInt32(alignedSignatureOffset), at: codeSignatureCmdOffset + 8)
            data.writeUnaligned(UInt32(signatureData.count), at: codeSignatureCmdOffset + 12)
        } else {
            // Need 16 bytes to append a new linkedit_data_command
            guard loadCommandsEnd + 16 <= minDataFileOffset, loadCommandsEnd + 16 <= data.count else {
                throw Error.insufficientHeaderSpace
            }

            data.writeUnaligned(MachOConstants.LC_CODE_SIGNATURE, at: loadCommandsEnd)
            data.writeUnaligned(UInt32(16), at: loadCommandsEnd + 4)
            data.writeUnaligned(UInt32(alignedSignatureOffset), at: loadCommandsEnd + 8)
            data.writeUnaligned(UInt32(signatureData.count), at: loadCommandsEnd + 12)

            ncmds += 1
            sizeofcmds += 16
            data.writeUnaligned(ncmds, at: 16)
            data.writeUnaligned(sizeofcmds, at: 20)
        }
    }
}

public func injectCodeSignature(into fileURL: URL, signatureData: Data) throws {
    try MachOWriter.injectCodeSignature(into: fileURL, signatureData: signatureData)
}

private extension Data {
    mutating func writeUnaligned<T: FixedWidthInteger>(_ value: T, at offset: Int) {
        var leValue = value.littleEndian
        Swift.withUnsafeBytes(of: &leValue) { raw in
            self.replaceSubrange(offset..<(offset + MemoryLayout<T>.size), with: raw)
        }
    }
}

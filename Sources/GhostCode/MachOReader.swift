import Foundation

public final class MachOReader: @unchecked Sendable {
    public enum Error: Swift.Error, Equatable {
        case fileTooSmall
        case invalidMagic(UInt32)
        case malformedLoadCommand(offset: Int)
        case fileReadError(String)
    }

    public struct ParsedCommand: Sendable, Equatable {
        public let cmd: UInt32
        public let cmdsize: UInt32
        public let offset: Int
        public let payload: Data
    }

    public let data: Data
    public let header: MachHeader64
    public let commands: [ParsedCommand]

    public var codeSignatureCommand: LinkeditDataCommand? {
        guard let cmd = commands.first(where: { $0.cmd == MachOConstants.LC_CODE_SIGNATURE }) else {
            return nil
        }
        guard cmd.payload.count >= 8 else {
            return nil
        }

        return cmd.payload.withUnsafeBytes { raw in
            let dataoff = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 0, as: UInt32.self))
            let datasize = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
            return LinkeditDataCommand(cmd: cmd.cmd, cmdsize: cmd.cmdsize, dataoff: dataoff, datasize: datasize)
        }
    }

    public init(data: Data) throws {
        guard data.count >= MemoryLayout<MachHeader64>.size else {
            throw Error.fileTooSmall
        }

        self.data = data

        let parsedHeader = data.withUnsafeBytes { raw -> MachHeader64 in
            MachHeader64(
                magic: UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 0, as: UInt32.self)),
                cpuType: UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 4, as: UInt32.self)),
                cpuSubtype: UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 8, as: UInt32.self)),
                fileType: UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 12, as: UInt32.self)),
                ncmds: UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 16, as: UInt32.self)),
                sizeofcmds: UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 20, as: UInt32.self)),
                flags: UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 24, as: UInt32.self)),
                reserved: UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: 28, as: UInt32.self))
            )
        }

        guard parsedHeader.magic == MachOConstants.MH_MAGIC_64 else {
            throw Error.invalidMagic(parsedHeader.magic)
        }

        self.header = parsedHeader

        var parsedCommands: [ParsedCommand] = []
        var currentOffset = MemoryLayout<MachHeader64>.size
        let maxOffset = currentOffset + Int(parsedHeader.sizeofcmds)

        guard maxOffset <= data.count else {
            throw Error.malformedLoadCommand(offset: currentOffset)
        }

        try data.withUnsafeBytes { raw in
            for _ in 0..<parsedHeader.ncmds {
                guard currentOffset + 8 <= maxOffset else {
                    throw Error.malformedLoadCommand(offset: currentOffset)
                }

                let cmd = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: currentOffset, as: UInt32.self))
                let cmdsize = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: currentOffset + 4, as: UInt32.self))

                guard cmdsize >= 8, currentOffset + Int(cmdsize) <= maxOffset else {
                    throw Error.malformedLoadCommand(offset: currentOffset)
                }

                let payloadSlice = data.subdata(in: (currentOffset + 8)..<(currentOffset + Int(cmdsize)))
                parsedCommands.append(ParsedCommand(cmd: cmd, cmdsize: cmdsize, offset: currentOffset, payload: payloadSlice))

                currentOffset += Int(cmdsize)
            }
        }

        self.commands = parsedCommands
    }

    public convenience init(contentsOf url: URL) throws {
        do {
            let fileData = try Data(contentsOf: url)
            try self.init(data: fileData)
        } catch let err as Error {
            throw err
        } catch {
            throw Error.fileReadError(error.localizedDescription)
        }
    }
}

import XCTest
@testable import GhostCode

final class MachOReaderTests: XCTestCase {
    private func createMachOBinary(
        ncmds: UInt32,
        sizeofcmds: UInt32,
        appendCommands: (inout Data) -> Void
    ) -> Data {
        var data = Data()

        // 32-byte mach_header_64
        var header = MachHeader64(
            magic: MachOConstants.MH_MAGIC_64,
            cpuType: 0x0100000c, // CPU_TYPE_ARM64
            cpuSubtype: 0,
            fileType: 2,         // MH_EXECUTE
            ncmds: ncmds,
            sizeofcmds: sizeofcmds,
            flags: 0x00200085,
            reserved: 0
        )

        withUnsafeBytes(of: &header.magic) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.cpuType) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.cpuSubtype) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.fileType) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.ncmds) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.sizeofcmds) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.flags) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &header.reserved) { data.append(contentsOf: $0) }

        appendCommands(&data)
        return data
    }

    func testStructureLayouts() {
        XCTAssertEqual(MemoryLayout<MachHeader64>.size, 32)
        XCTAssertEqual(MemoryLayout<LoadCommand>.size, 8)
        XCTAssertEqual(MemoryLayout<LinkeditDataCommand>.size, 16)
        XCTAssertEqual(MemoryLayout<SuperBlobHeader>.size, 12)
        XCTAssertEqual(MemoryLayout<BlobIndex>.size, 8)
    }

    func testParseMachOWithoutCodeSignature() throws {
        let binary = createMachOBinary(ncmds: 1, sizeofcmds: 16) { data in
            // Dummy generic command (cmd = 0x1, cmdsize = 16)
            var cmd: UInt32 = 0x1
            var cmdsize: UInt32 = 16
            var payload: UInt64 = 0x12345678
            withUnsafeBytes(of: &cmd) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &cmdsize) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &payload) { data.append(contentsOf: $0) }
        }

        let reader = try MachOReader(data: binary)
        XCTAssertEqual(reader.header.magic, MachOConstants.MH_MAGIC_64)
        XCTAssertEqual(reader.header.ncmds, 1)
        XCTAssertEqual(reader.header.sizeofcmds, 16)
        XCTAssertEqual(reader.commands.count, 1)
        XCTAssertNil(reader.codeSignatureCommand)
    }

    func testParseMachOWithCodeSignature() throws {
        let binary = createMachOBinary(ncmds: 2, sizeofcmds: 32) { data in
            // Command 1: generic load command (cmd = 0x2, cmdsize = 16)
            var cmd1: UInt32 = 0x2
            var cmdsize1: UInt32 = 16
            var payload1: UInt64 = 0
            withUnsafeBytes(of: &cmd1) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &cmdsize1) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &payload1) { data.append(contentsOf: $0) }

            // Command 2: LC_CODE_SIGNATURE (cmd = 0x1d, cmdsize = 16, dataoff = 4096, datasize = 512)
            var cmd2: UInt32 = MachOConstants.LC_CODE_SIGNATURE
            var cmdsize2: UInt32 = 16
            var dataoff: UInt32 = 4096
            var datasize: UInt32 = 512
            withUnsafeBytes(of: &cmd2) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &cmdsize2) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &dataoff) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &datasize) { data.append(contentsOf: $0) }
        }

        let reader = try MachOReader(data: binary)
        XCTAssertEqual(reader.header.ncmds, 2)
        XCTAssertEqual(reader.commands.count, 2)

        let sig = try XCTUnwrap(reader.codeSignatureCommand)
        XCTAssertEqual(sig.cmd, MachOConstants.LC_CODE_SIGNATURE)
        XCTAssertEqual(sig.cmdsize, 16)
        XCTAssertEqual(sig.dataoff, 4096)
        XCTAssertEqual(sig.datasize, 512)
    }

    func testInvalidMagicThrows() {
        var binary = createMachOBinary(ncmds: 0, sizeofcmds: 0) { _ in }
        binary[0] = 0x00

        XCTAssertThrowsError(try MachOReader(data: binary)) { error in
            guard case MachOReader.Error.invalidMagic = error else {
                XCTFail("Expected invalidMagic error, got \(error)")
                return
            }
        }
    }

    func testFileTooSmallThrows() {
        let truncated = Data([0xCF, 0xFA, 0xED, 0xFE])
        XCTAssertThrowsError(try MachOReader(data: truncated)) { error in
            XCTAssertEqual(error as? MachOReader.Error, .fileTooSmall)
        }
    }

    func testMalformedLoadCommandThrows() {
        let binary = createMachOBinary(ncmds: 1, sizeofcmds: 16) { data in
            // cmdsize = 4 is illegal (< 8 bytes)
            var cmd: UInt32 = 0x1
            var cmdsize: UInt32 = 4
            withUnsafeBytes(of: &cmd) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &cmdsize) { data.append(contentsOf: $0) }
        }

        XCTAssertThrowsError(try MachOReader(data: binary)) { error in
            guard case MachOReader.Error.malformedLoadCommand = error else {
                XCTFail("Expected malformedLoadCommand error, got \(error)")
                return
            }
        }
    }
}

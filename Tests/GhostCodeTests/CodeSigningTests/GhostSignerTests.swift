import XCTest
@testable import GhostCode

final class GhostSignerTests: XCTestCase {
    private func createMockBinary() -> Data {
        var data = Data()
        var header = MachHeader64(
            magic: MachOConstants.MH_MAGIC_64,
            cpuType: 0x0100000c, // ARM64
            cpuSubtype: 0,
            fileType: 2,         // MH_EXECUTE
            ncmds: 2,
            sizeofcmds: 144,
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

        // Segment 1: __TEXT
        appendSegment(name: "__TEXT", fileoff: 0, filesize: 4096, vmsize: 4096, to: &data)
        // Segment 2: __LINKEDIT
        appendSegment(name: "__LINKEDIT", fileoff: 4096, filesize: 0, vmsize: 4096, to: &data)

        // Pad up to 4096 bytes
        if data.count < 4096 {
            data.append(Data(repeating: 0, count: 4096 - data.count))
        }

        return data
    }

    private func appendSegment(name: String, fileoff: UInt64, filesize: UInt64, vmsize: UInt64, to data: inout Data) {
        var cmd = MachOConstants.LC_SEGMENT_64
        var cmdsize: UInt32 = 72
        withUnsafeBytes(of: &cmd) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &cmdsize) { data.append(contentsOf: $0) }

        var nameBytes = [UInt8](repeating: 0, count: 16)
        let utf8 = Array(name.utf8.prefix(16))
        for (i, b) in utf8.enumerated() { nameBytes[i] = b }
        data.append(contentsOf: nameBytes)

        var vmaddr: UInt64 = 0x100000000
        var vmSize = vmsize
        var fileOff = fileoff
        var fileSize = filesize
        var maxprot: Int32 = 7
        var initprot: Int32 = 5
        var nsects: UInt32 = 0
        var flags: UInt32 = 0

        withUnsafeBytes(of: &vmaddr) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &vmSize) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &fileOff) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &fileSize) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &maxprot) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &initprot) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &nsects) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &flags) { data.append(contentsOf: $0) }
    }

    func testSignBinaryWithEntitlementsContainsSlotMinus7() throws {
        let binaryData = createMockBinary()
        let tempDir = FileManager.default.temporaryDirectory
        let inputURL = tempDir.appendingPathComponent("unsigned_\(UUID().uuidString).bin")
        let outputURL = tempDir.appendingPathComponent("signed_\(UUID().uuidString).bin")

        try binaryData.write(to: inputURL)
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let entitlements: [String: Any] = [
            "get-task-allow": true,
            "application-identifier": "TEAM123.com.example.app"
        ]

        let signer = GhostSigner()
        try signer.sign(binaryURL: inputURL, entitlements: entitlements, outputURL: outputURL)

        // Read signed binary
        let reader = try MachOReader(contentsOf: outputURL)
        let sigCmd = try XCTUnwrap(reader.codeSignatureCommand)
        XCTAssertEqual(sigCmd.cmd, MachOConstants.LC_CODE_SIGNATURE)
        XCTAssertGreaterThan(sigCmd.datasize, 0)

        // Read SuperBlob
        let signedData = try Data(contentsOf: outputURL)
        let superBlobOffset = Int(sigCmd.dataoff)
        let superBlob = signedData.subdata(in: superBlobOffset..<(superBlobOffset + Int(sigCmd.datasize)))

        // Verify SuperBlob header
        let magic = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) })
        let totalLength = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self) })
        let count = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt32.self) })

        XCTAssertEqual(magic, MachOConstants.CSMAGIC_EMBEDDED_SIGNATURE)
        XCTAssertEqual(totalLength, UInt32(superBlob.count))
        XCTAssertGreaterThanOrEqual(count, 2) // CodeDirectory + DER (and optional XML)

        // Search for Slot 7 (CSSLOT_DER_ENTITLEMENTS)
        var foundSlot7 = false
        var derBlobOffset: Int?

        for i in 0..<Int(count) {
            let entryOffset = 12 + i * 8
            let slotType = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entryOffset, as: UInt32.self) })
            let blobOffset = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entryOffset + 4, as: UInt32.self) })

            if slotType == MachOConstants.CSSLOT_DER_ENTITLEMENTS {
                foundSlot7 = true
                derBlobOffset = Int(blobOffset)
            }
        }

        // Verify Slot 7 was found in SuperBlob
        XCTAssertTrue(foundSlot7, "SuperBlob must contain a BlobIndex for CSSLOT_DER_ENTITLEMENTS (Slot 7)")
        let offset = try XCTUnwrap(derBlobOffset)

        // Check DER Blob Header: magic 0xfade7172
        let derMagic = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) })
        XCTAssertEqual(derMagic, MachOConstants.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS)
    }

    func testSignInPlace() throws {
        let binaryData = createMockBinary()
        let tempDir = FileManager.default.temporaryDirectory
        let fileURL = tempDir.appendingPathComponent("inplace_\(UUID().uuidString).bin")

        try binaryData.write(to: fileURL)
        defer {
            try? FileManager.default.removeItem(at: fileURL)
        }

        try GhostSigner.sign(binaryURL: fileURL, entitlements: ["get-task-allow": false])

        let reader = try MachOReader(contentsOf: fileURL)
        XCTAssertNotNil(reader.codeSignatureCommand)
    }
}

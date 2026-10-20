import XCTest
@testable import GhostCode

final class MachOWriterTests: XCTestCase {
    
    // MARK: - Test Helpers
    
    private func createMockBinary(
        segments: [(name: String, fileoff: UInt64, filesize: UInt64, vmsize: UInt64)] = [
            ("__TEXT", 0, 4096, 4096),
            ("__LINKEDIT", 4096, 0, 4096)
        ],
        existingSignature: (dataoff: UInt32, data: Data)? = nil,
        paddingUpTo: Int = 4096
    ) -> Data {
        var data = Data()
        
        let hasCodeSig = (existingSignature != nil)
        let ncmds = UInt32(segments.count + (hasCodeSig ? 1 : 0))
        let sizeofcmds = UInt32(segments.count * 72 + (hasCodeSig ? 16 : 0))
        
        // 1. Mach-O Header (32 bytes)
        var header = MachHeader64(
            magic: MachOConstants.MH_MAGIC_64,
            cpuType: 0x0100000c, // ARM64
            cpuSubtype: 0,
            fileType: 2,         // MH_EXECUTE
            ncmds: ncmds,
            sizeofcmds: sizeofcmds,
            flags: 0x00200085,
            reserved: 0
        )
        
        appendLittleEndian(&header.magic, to: &data)
        appendLittleEndian(&header.cpuType, to: &data)
        appendLittleEndian(&header.cpuSubtype, to: &data)
        appendLittleEndian(&header.fileType, to: &data)
        appendLittleEndian(&header.ncmds, to: &data)
        appendLittleEndian(&header.sizeofcmds, to: &data)
        appendLittleEndian(&header.flags, to: &data)
        appendLittleEndian(&header.reserved, to: &data)
        
        // 2. Segment Load Commands (72 bytes each)
        for seg in segments {
            var cmd = MachOConstants.LC_SEGMENT_64
            var cmdsize: UInt32 = 72
            appendLittleEndian(&cmd, to: &data)
            appendLittleEndian(&cmdsize, to: &data)
            
            // 16-byte segname
            var nameBytes = [UInt8](repeating: 0, count: 16)
            let utf8 = Array(seg.name.utf8.prefix(16))
            for (idx, byte) in utf8.enumerated() {
                nameBytes[idx] = byte
            }
            data.append(contentsOf: nameBytes)
            
            var vmaddr: UInt64 = 0x100000000
            var vmsize = seg.vmsize
            var fileoff = seg.fileoff
            var filesize = seg.filesize
            var maxprot: Int32 = 7
            var initprot: Int32 = 5
            var nsects: UInt32 = 0
            var flags: UInt32 = 0
            
            appendLittleEndian(&vmaddr, to: &data)
            appendLittleEndian(&vmsize, to: &data)
            appendLittleEndian(&fileoff, to: &data)
            appendLittleEndian(&filesize, to: &data)
            appendLittleEndian(&maxprot, to: &data)
            appendLittleEndian(&initprot, to: &data)
            appendLittleEndian(&nsects, to: &data)
            appendLittleEndian(&flags, to: &data)
        }
        
        // 3. Optional LC_CODE_SIGNATURE Load Command (16 bytes)
        if let existingSignature {
            var cmd = MachOConstants.LC_CODE_SIGNATURE
            var cmdsize: UInt32 = 16
            var dataoff = existingSignature.dataoff
            var datasize = UInt32(existingSignature.data.count)
            
            appendLittleEndian(&cmd, to: &data)
            appendLittleEndian(&cmdsize, to: &data)
            appendLittleEndian(&dataoff, to: &data)
            appendLittleEndian(&datasize, to: &data)
        }
        
        // 4. Pad header/data up to paddingUpTo
        if data.count < paddingUpTo {
            data.append(Data(repeating: 0, count: paddingUpTo - data.count))
        }
        
        // 5. If existing signature is provided, append it at existingSignature.dataoff
        if let existingSignature {
            if data.count < Int(existingSignature.dataoff) {
                data.append(Data(repeating: 0, count: Int(existingSignature.dataoff) - data.count))
            }
            data.append(existingSignature.data)
        }
        
        return data
    }
    
    private func appendLittleEndian<T: FixedWidthInteger>(_ value: inout T, to data: inout Data) {
        var le = value.littleEndian
        withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
    }
    
    // MARK: - Writer Tests
    
    func testInjectCodeSignatureFresh() throws {
        // Mock binary without LC_CODE_SIGNATURE
        var binary = createMockBinary()
        let initialSize = binary.count
        XCTAssertEqual(initialSize, 4096)
        
        let initialReader = try MachOReader(data: binary)
        XCTAssertEqual(initialReader.header.ncmds, 2)
        XCTAssertEqual(initialReader.header.sizeofcmds, 144)
        XCTAssertNil(initialReader.codeSignatureCommand)
        
        // 500 bytes of dummy signature
        let dummySignature = Data((0..<500).map { UInt8($0 % 256) })
        try MachOWriter.injectCodeSignature(into: &binary, signatureData: dummySignature)
        
        // Verify via MachOReader
        let updatedReader = try MachOReader(data: binary)
        XCTAssertEqual(updatedReader.header.ncmds, 3)
        XCTAssertEqual(updatedReader.header.sizeofcmds, 160)
        
        let codeSig = try XCTUnwrap(updatedReader.codeSignatureCommand)
        XCTAssertEqual(codeSig.cmd, MachOConstants.LC_CODE_SIGNATURE)
        XCTAssertEqual(codeSig.cmdsize, 16)
        XCTAssertEqual(codeSig.dataoff, 4096)
        XCTAssertEqual(codeSig.datasize, 500)
        
        // Verify signature offset is 16-byte aligned
        XCTAssertEqual(codeSig.dataoff % 16, 0)
        
        // Verify signature content matches
        let extractedSig = binary.subdata(in: Int(codeSig.dataoff)..<(Int(codeSig.dataoff) + Int(codeSig.datasize)))
        XCTAssertEqual(extractedSig, dummySignature)
        
        // Verify __LINKEDIT segment updated filesize and vmsize
        let linkeditCommand = try XCTUnwrap(updatedReader.commands.first { cmd in
            guard cmd.cmd == MachOConstants.LC_SEGMENT_64 else { return false }
            let segname = String(decoding: cmd.payload.prefix(16).prefix(while: { $0 != 0 }), as: UTF8.self)
            return segname == "__LINKEDIT"
        })
        
        let vmsize = linkeditCommand.payload.withUnsafeBytes { raw in
            UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: 24, as: UInt64.self))
        }
        let filesize = linkeditCommand.payload.withUnsafeBytes { raw in
            UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: 40, as: UInt64.self))
        }
        
        XCTAssertEqual(filesize, 500)
        XCTAssertEqual(vmsize, 4096)
        XCTAssertEqual(binary.count, 4096 + 500)
    }
    
    func testInjectCodeSignatureReplaceExisting() throws {
        let oldSigData = Data(repeating: 0xAA, count: 200)
        var binary = createMockBinary(
            existingSignature: (dataoff: 4096, data: oldSigData)
        )
        XCTAssertEqual(binary.count, 4096 + 200)
        
        let initialReader = try MachOReader(data: binary)
        XCTAssertEqual(initialReader.header.ncmds, 3)
        XCTAssertEqual(initialReader.header.sizeofcmds, 160)
        XCTAssertEqual(initialReader.codeSignatureCommand?.datasize, 200)
        
        // Replace with new signature of 350 bytes
        let newSigData = Data(repeating: 0xBB, count: 350)
        try MachOWriter.injectCodeSignature(into: &binary, signatureData: newSigData)
        
        let updatedReader = try MachOReader(data: binary)
        // Command count and sizeofcmds should remain the same (in-place update)
        XCTAssertEqual(updatedReader.header.ncmds, 3)
        XCTAssertEqual(updatedReader.header.sizeofcmds, 160)
        
        let codeSig = try XCTUnwrap(updatedReader.codeSignatureCommand)
        XCTAssertEqual(codeSig.dataoff, 4096)
        XCTAssertEqual(codeSig.datasize, 350)
        
        let extractedSig = binary.subdata(in: Int(codeSig.dataoff)..<(Int(codeSig.dataoff) + Int(codeSig.datasize)))
        XCTAssertEqual(extractedSig, newSigData)
        XCTAssertEqual(binary.count, 4096 + 350)
    }
    
    func testInjectCodeSignatureWithUnalignedBaseAppendsPadding() throws {
        // Base binary ends at 4101 bytes (unaligned: 4101 % 16 != 0)
        var binary = createMockBinary(
            segments: [
                ("__TEXT", 0, 4096, 4096),
                ("__LINKEDIT", 4096, 5, 4096)
            ],
            paddingUpTo: 4101
        )
        XCTAssertEqual(binary.count, 4101)
        
        let sigData = Data([0xDE, 0xAD, 0xBE, 0xEF])
        try MachOWriter.injectCodeSignature(into: &binary, signatureData: sigData)
        
        let reader = try MachOReader(data: binary)
        let codeSig = try XCTUnwrap(reader.codeSignatureCommand)
        
        // 4101 aligned to 16 bytes is 4112
        XCTAssertEqual(codeSig.dataoff, 4112)
        XCTAssertEqual(codeSig.dataoff % 16, 0)
        XCTAssertEqual(codeSig.datasize, 4)
        
        // Verify padding bytes (4101..<4112) are zero
        let paddingSlice = binary.subdata(in: 4101..<4112)
        XCTAssertEqual(paddingSlice.count, 11)
        XCTAssertTrue(paddingSlice.allSatisfy { $0 == 0 })
        
        // Verify signature data is present right after padding
        let extracted = binary.subdata(in: 4112..<4116)
        XCTAssertEqual(extracted, sigData)
    }
    
    func testInjectCodeSignatureFileURL() throws {
        let binary = createMockBinary()
        let tempDir = FileManager.default.temporaryDirectory
        let tempFile = tempDir.appendingPathComponent("test_macho_\(UUID().uuidString).bin")
        try binary.write(to: tempFile)
        
        defer {
            try? FileManager.default.removeItem(at: tempFile)
        }
        
        let signature = Data(repeating: 0x42, count: 128)
        try MachOWriter.injectCodeSignature(into: tempFile, signatureData: signature)
        
        let reader = try MachOReader(contentsOf: tempFile)
        let sigCmd = try XCTUnwrap(reader.codeSignatureCommand)
        XCTAssertEqual(sigCmd.datasize, 128)
        XCTAssertEqual(sigCmd.dataoff, 4096)
        
        let fileData = try Data(contentsOf: tempFile)
        let payload = fileData.subdata(in: Int(sigCmd.dataoff)..<(Int(sigCmd.dataoff) + Int(sigCmd.datasize)))
        XCTAssertEqual(payload, signature)
    }
    
    func testInjectCodeSignatureGlobalHelperFunction() throws {
        let binary = createMockBinary()
        let tempDir = FileManager.default.temporaryDirectory
        let tempFile = tempDir.appendingPathComponent("test_helper_\(UUID().uuidString).bin")
        try binary.write(to: tempFile)
        
        defer {
            try? FileManager.default.removeItem(at: tempFile)
        }
        
        let signature = Data(repeating: 0x77, count: 64)
        // Tests the top-level free function `injectCodeSignature(into:signatureData:)`
        try injectCodeSignature(into: tempFile, signatureData: signature)
        
        let reader = try MachOReader(contentsOf: tempFile)
        let sigCmd = try XCTUnwrap(reader.codeSignatureCommand)
        XCTAssertEqual(sigCmd.datasize, 64)
    }
    
    // MARK: - Error Handling Tests
    
    func testFileTooSmallThrows() {
        var data = Data([0xCF, 0xFA, 0xED, 0xFE])
        XCTAssertThrowsError(try MachOWriter.injectCodeSignature(into: &data, signatureData: Data())) { error in
            XCTAssertEqual(error as? MachOWriter.Error, .fileTooSmall)
        }
    }
    
    func testInvalidMagicThrows() {
        var binary = createMockBinary()
        binary[0] = 0x00
        binary[1] = 0x00
        XCTAssertThrowsError(try MachOWriter.injectCodeSignature(into: &binary, signatureData: Data())) { error in
            guard case MachOWriter.Error.invalidMagic = error else {
                XCTFail("Expected invalidMagic error, got \(error)")
                return
            }
        }
    }
    
    func testLinkeditSegmentNotFoundThrows() {
        // Binary with only __TEXT segment
        var binary = createMockBinary(segments: [
            ("__TEXT", 0, 4096, 4096)
        ])
        
        XCTAssertThrowsError(try MachOWriter.injectCodeSignature(into: &binary, signatureData: Data())) { error in
            XCTAssertEqual(error as? MachOWriter.Error, .linkeditSegmentNotFound)
        }
    }
    
    func testInsufficientHeaderSpaceThrows() {
        // Binary where load commands completely fill up to minDataFileOffset with no space for 16 more bytes
        // loadCommandsEnd = 32 + 72 = 104 bytes. Let paddingUpTo be exactly 104 bytes.
        var binary = createMockBinary(
            segments: [
                ("__LINKEDIT", 104, 0, 4096)
            ],
            paddingUpTo: 104
        )
        
        XCTAssertThrowsError(try MachOWriter.injectCodeSignature(into: &binary, signatureData: Data([1, 2]))) { error in
            XCTAssertEqual(error as? MachOWriter.Error, .insufficientHeaderSpace)
        }
    }
    
    func testMalformedLoadCommandsThrows() {
        // cmdsize is corrupted (< 8)
        var binary = createMockBinary()
        // Offset 32 is the start of first load command. cmdsize is at offset 36.
        binary[36] = 4
        binary[37] = 0
        binary[38] = 0
        binary[39] = 0
        
        XCTAssertThrowsError(try MachOWriter.injectCodeSignature(into: &binary, signatureData: Data())) { error in
            XCTAssertEqual(error as? MachOWriter.Error, .malformedLoadCommands)
        }
    }
    
    func testNonExistentFileThrowsFileWriteError() {
        let invalidURL = URL(fileURLWithPath: "/non/existent/path/binary_\(UUID().uuidString)")
        XCTAssertThrowsError(try MachOWriter.injectCodeSignature(into: invalidURL, signatureData: Data())) { error in
            guard case MachOWriter.Error.fileWriteError = error else {
                XCTFail("Expected fileWriteError, got \(error)")
                return
            }
        }
    }
}

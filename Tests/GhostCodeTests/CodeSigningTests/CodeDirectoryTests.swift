import XCTest
@testable import GhostCode

final class CodeDirectoryTests: XCTestCase {
    func testNativeSHA256StandardVectors() {
        // Test vector: empty string
        let emptyHash = NativeSHA256.hash(Data())
        let emptyHex = emptyHash.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(emptyHex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        // Test vector: "abc"
        let abcHash = NativeSHA256.hash(Data("abc".utf8))
        let abcHex = abcHash.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(abcHex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    func testCodeDirectoryWithSpecialSlotMinus7() {
        let dummyBinary = Data(repeating: 0x90, count: 8192) // 2 pages
        let derData = Data([0x30, 0x05, 0x01, 0x01, 0xFF])
        let xmlData = Data("<plist></plist>".utf8)

        let cdData = CodeDirectoryBuilder.build(
            binaryData: dummyBinary,
            codeLimit: 8192,
            identifier: "com.example.test",
            xmlEntitlements: xmlData,
            derEntitlements: derData
        )

        // Read CodeDirectory header
        let magic = UInt32(bigEndian: cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) })
        let length = UInt32(bigEndian: cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self) })
        let hashOffset = UInt32(bigEndian: cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self) })
        let nSpecialSlots = UInt32(bigEndian: cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 24, as: UInt32.self) })
        let nCodeSlots = UInt32(bigEndian: cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 28, as: UInt32.self) })

        XCTAssertEqual(magic, MachOConstants.CSMAGIC_CODEDIRECTORY)
        XCTAssertEqual(length, UInt32(cdData.count))
        XCTAssertEqual(nSpecialSlots, 7)
        XCTAssertEqual(nCodeSlots, 2)

        // Verify Slot -7 (DER hash)
        // Offset in cdData: hashOffset - (7 * 32)
        let slot7Offset = Int(hashOffset) - (7 * 32)
        let slot7Hash = cdData.subdata(in: slot7Offset..<(slot7Offset + 32))
        let expectedDerHash = CodeDirectoryBuilder.sha256(derData)
        XCTAssertEqual(slot7Hash, expectedDerHash)

        // Verify Slot -5 (XML hash)
        let slot5Offset = Int(hashOffset) - (5 * 32)
        let slot5Hash = cdData.subdata(in: slot5Offset..<(slot5Offset + 32))
        let expectedXmlHash = CodeDirectoryBuilder.sha256(xmlData)
        XCTAssertEqual(slot5Hash, expectedXmlHash)

        // Verify Code Slot 0
        let codeSlot0 = cdData.subdata(in: Int(hashOffset)..<(Int(hashOffset) + 32))
        let expectedPage0Hash = CodeDirectoryBuilder.sha256(dummyBinary.subdata(in: 0..<4096))
        XCTAssertEqual(codeSlot0, expectedPage0Hash)
    }
}

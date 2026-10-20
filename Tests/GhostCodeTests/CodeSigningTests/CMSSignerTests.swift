import XCTest
@testable import GhostCode

final class CMSSignerTests: XCTestCase {
    func testCMSSignerGeneratesSignature() throws {
        let codeDirectoryData = Data("CodeDirectoryBytes_Test".utf8)
        let cert = SecCertificate()
        let key = SecKey()

        let signature = try CMSSigner.signCodeDirectory(codeDirectoryData: codeDirectoryData, cert: cert, key: key)
        XCTAssertFalse(signature.isEmpty)

        // Verify SuperBlobBuilder with CMS signature (Slot 0x10000 / CSSLOT_SIGNATURESLOT)
        let superBlob = SuperBlobBuilder.build(
            codeDirectory: codeDirectoryData,
            cmsSignature: signature
        )

        let magic = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) })
        let count = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt32.self) })
        XCTAssertEqual(magic, MachOConstants.CSMAGIC_EMBEDDED_SIGNATURE)
        XCTAssertEqual(count, 2) // CodeDirectory (0) + Signature (0x10000)

        // Find signature slot
        var foundSigSlot = false
        for i in 0..<Int(count) {
            let offset = 12 + i * 8
            let type = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) })
            let blobOffset = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self) })

            if type == MachOConstants.CSSLOT_SIGNATURESLOT {
                foundSigSlot = true
                // Check blob wrapper magic 0xfade0b01
                let blobMagic = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: Int(blobOffset), as: UInt32.self) })
                XCTAssertEqual(blobMagic, MachOConstants.CSMAGIC_BLOBWRAPPER)
            }
        }
        XCTAssertTrue(foundSigSlot)
    }
}

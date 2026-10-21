import XCTest
@testable import GhostCode

final class GhostCodeTests: XCTestCase {
    func testMachOStructuresSize() {
        XCTAssertEqual(MemoryLayout<MachHeader64>.size, 32)
        XCTAssertEqual(MemoryLayout<LoadCommand>.size, 8)
        XCTAssertEqual(MemoryLayout<LinkeditDataCommand>.size, 16)
    }

    func testConstantsValues() {
        XCTAssertEqual(Constants.MachO.MH_MAGIC_64, 0xfeedfacf)
        XCTAssertEqual(Constants.MachO.LC_CODE_SIGNATURE, 0x1d)
        XCTAssertEqual(Constants.MachO.LC_SEGMENT_64, 0x19)

        XCTAssertEqual(Constants.CodeSigning.CSMAGIC_CODEDIRECTORY, 0xfade0c02)
        XCTAssertEqual(Constants.CodeSigning.CSMAGIC_EMBEDDED_SIGNATURE, 0xfade0cc0)
        XCTAssertEqual(Constants.CodeSigning.CSMAGIC_BLOBWRAPPER, 0xfade0b01)
        XCTAssertEqual(Constants.CodeSigning.CSSLOT_CODEDIRECTORY, 0)
        XCTAssertEqual(Constants.CodeSigning.CSSLOT_ENTITLEMENTS, 5)
        XCTAssertEqual(Constants.CodeSigning.CSSLOT_SIGNATURESLOT, 0x10000)

        XCTAssertEqual(Constants.CodeSigning.CS_HASHTYPE_SHA256, 2)
        XCTAssertEqual(Constants.CodeSigning.CS_PAGE_SIZE, 4096)

        XCTAssertEqual(Constants.Bundle.codeResourcesPath, "_CodeSignature/CodeResources")
        XCTAssertEqual(Constants.Bundle.embeddedProvisioningProfile, "embedded.mobileprovision")

        XCTAssertEqual(Constants.OIDs.appleCodeSigningEKU, "1.2.840.113635.100.6.1.13")
        XCTAssertEqual(Constants.OIDs.contentTypeData, "1.2.840.113549.1.7.1")
        XCTAssertEqual(Constants.OIDs.contentTypeSignedData, "1.2.840.113549.1.7.2")
    }
}

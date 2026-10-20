import XCTest
@testable import GhostCode

final class GhostCodeTests: XCTestCase {
    func testMachOStructuresSize() {
        XCTAssertEqual(MemoryLayout<MachHeader64>.size, 32)
        XCTAssertEqual(MemoryLayout<LoadCommand>.size, 8)
        XCTAssertEqual(MemoryLayout<LinkeditDataCommand>.size, 16)
    }
}

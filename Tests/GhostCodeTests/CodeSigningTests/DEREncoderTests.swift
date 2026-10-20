import XCTest
@testable import GhostCode

final class DEREncoderTests: XCTestCase {
    func testEncodeBoolean() {
        let trueBytes = DEREncoder.encodeBoolean(true)
        XCTAssertEqual(trueBytes, Data([0x01, 0x01, 0xFF]))

        let falseBytes = DEREncoder.encodeBoolean(false)
        XCTAssertEqual(falseBytes, Data([0x01, 0x01, 0x00]))
    }

    func testEncodeUTF8String() {
        let strBytes = DEREncoder.encodeString("test")
        XCTAssertEqual(strBytes, Data([0x0C, 0x04, 0x74, 0x65, 0x73, 0x74]))
    }

    func testEncodeSimpleEntitlementsDictionary() throws {
        let entitlements: [String: Any] = ["get-task-allow": true]
        let encoded = try DEREncoder.encode(entitlements: entitlements)

        // Expected format:
        // 0x30 (outer Sequence/Dict)
        // 0x15 (21 bytes total)
        //   0x30 (inner Sequence/Pair)
        //   0x13 (19 bytes total)
        //     0x0C (UTF8String key)
        //     0x0E (14 bytes)
        //     "get-task-allow" (14 bytes ASCII)
        //     0x01 (Boolean value)
        //     0x01 (1 byte)
        //     0xFF (true)
        XCTAssertEqual(encoded[0], 0x30) // Root Sequence
        XCTAssertEqual(encoded[1], 0x15) // Total length: 21 bytes

        XCTAssertEqual(encoded[2], 0x30) // First pair Sequence
        XCTAssertEqual(encoded[3], 0x13) // Pair length: 19 bytes

        XCTAssertEqual(encoded[4], 0x0C) // UTF8String tag
        XCTAssertEqual(encoded[5], 0x0E) // 14 bytes
        let keySlice = encoded.subdata(in: 6..<20)
        XCTAssertEqual(String(data: keySlice, encoding: .utf8), "get-task-allow")

        XCTAssertEqual(encoded[20], 0x01) // Boolean tag
        XCTAssertEqual(encoded[21], 0x01) // 1 byte
        XCTAssertEqual(encoded[22], 0xFF) // true
    }

    func testEncodeMultipleEntitlementsSorted() throws {
        let entitlements: [String: Any] = [
            "beta": false,
            "alpha": true
        ]
        let encoded = try DEREncoder.encode(entitlements: entitlements)
        XCTAssertEqual(encoded[0], 0x30)

        // Keys must be sorted: "alpha" first, then "beta"
        let alphaBytes = "alpha".data(using: .utf8)!
        let betaBytes = "beta".data(using: .utf8)!

        let alphaRange = encoded.range(of: alphaBytes)
        let betaRange = encoded.range(of: betaBytes)

        XCTAssertNotNil(alphaRange)
        XCTAssertNotNil(betaRange)
        XCTAssertLessThan(alphaRange!.lowerBound, betaRange!.lowerBound)
    }

    func testEncodeArrayOfStrings() throws {
        let entitlements: [String: Any] = [
            "keychain-access-groups": ["group1", "group2"]
        ]
        let encoded = try DEREncoder.encode(entitlements: entitlements)
        XCTAssertEqual(encoded[0], 0x30)

        // Must contain 0x31 for Array/Set
        XCTAssertTrue(encoded.contains(0x31))
    }

    func testTopLevelHelperFunction() throws {
        let data = try encode(entitlements: ["get-task-allow": true])
        XCTAssertEqual(data[0], 0x30)
    }
}

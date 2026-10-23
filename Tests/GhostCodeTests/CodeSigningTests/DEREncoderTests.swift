import XCTest
@testable import GhostCode

final class DEREncoderTests: XCTestCase {
    func testEncodeValuePrimitives() throws {
        XCTAssertEqual(try DEREncoder.encodeValue(true), Data([0x01, 0x01, 0xFF]))
        XCTAssertEqual(try DEREncoder.encodeValue(false), Data([0x01, 0x01, 0x00]))
        XCTAssertEqual(
            try DEREncoder.encodeValue("test"),
            Data([0x0C, 0x04, 0x74, 0x65, 0x73, 0x74])
        )
    }

    func testEncodeUnsupportedTypeThrows() {
        XCTAssertThrowsError(try DEREncoder.encodeValue(Date())) { error in
            guard case DEREncoderError.unsupportedType = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }

    /// Apple's layout is `0x70 <len> <INTEGER 1> <0xB0 <len> <entry>...>`, not a plain SEQUENCE.
    func testEncodeSimpleEntitlementsDictionary() throws {
        let encoded = try DEREncoder.encode(entitlements: ["get-task-allow": true])
        let key = Data("get-task-allow".utf8)

        var expected = Data([0x70, 0x1A])          // envelope, 26 bytes
        expected.append(contentsOf: [0x02, 0x01, 0x01]) // version
        expected.append(contentsOf: [0xB0, 0x15])  // dictionary, 21 bytes
        expected.append(contentsOf: [0x30, 0x13])  // entry pair, 19 bytes
        expected.append(contentsOf: [0x0C, UInt8(key.count)])
        expected.append(key)
        expected.append(contentsOf: [0x01, 0x01, 0xFF])

        XCTAssertEqual(encoded, expected)
    }

    func testEncodeMultipleEntitlementsSorted() throws {
        let encoded = try DEREncoder.encode(entitlements: ["beta": false, "alpha": true])
        XCTAssertEqual(encoded.first, 0x70)

        let alphaBytes = Data("alpha".utf8)
        let betaBytes = Data("beta".utf8)

        guard let alphaRange = encoded.range(of: alphaBytes),
              let betaRange = encoded.range(of: betaBytes) else {
            return XCTFail("keys missing from encoded entitlements")
        }
        XCTAssertLessThan(alphaRange.lowerBound, betaRange.lowerBound)
    }

    func testEncodeArrayOfStrings() throws {
        let encoded = try DEREncoder.encode(
            entitlements: ["keychain-access-groups": ["group1", "group2"]]
        )
        // plist arrays are SEQUENCE (0x30) inside the 0xB0 dictionary.
        XCTAssertTrue(encoded.contains(0x30))
        XCTAssertNotNil(encoded.range(of: Data("group1".utf8)))
        XCTAssertNotNil(encoded.range(of: Data("group2".utf8)))
    }

    func testEncodeNestedDictionary() throws {
        let encoded = try DEREncoder.encode(
            entitlements: ["safaridomainURLs": ["https://example.com": true]]
        )
        XCTAssertNotNil(encoded.range(of: Data("https://example.com".utf8)))
    }
}

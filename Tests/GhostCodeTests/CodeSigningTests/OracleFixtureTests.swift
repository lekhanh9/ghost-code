import Foundation
import XCTest
@testable import GhostCode

/// Byte-level comparison against the zsign oracle in `Fixtures/oracle_dual`. zsign was run as
/// `zsign -d -f -L -k test.p12 -p zsign -m test.mobileprovision Payload/Test.app` over a mock arm64
/// Mach-O (`app.bin`) and the slot blobs were dumped before the signature region was rewritten.
///
/// Two intentional divergences keep these tests from being a single `XCTAssertEqual`:
/// - `flags`: zsign writes 0 for a non-ad-hoc directory; ghost-code follows `codesign` and sets
///   `CS_ENTITLEMENTS_VALIDATED | CS_GET_TASK_ALLOW`. Tests mask the flags word.
/// - certificate order: zsign serializes the chain before the leaf; ghost-code (like `codesign`)
///   puts the leaf first. The CMS test swaps the two certificate elements before comparing.
final class OracleFixtureTests: XCTestCase {
    private let fixtureDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // CodeSigningTests
        .deletingLastPathComponent() // GhostCodeTests
        .appendingPathComponent("Fixtures/oracle_dual")

    private func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: fixtureDir.appendingPathComponent(name))
    }

    private func dictionaryFromPlist(_ data: Data) throws -> [String: Any] {
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dict = plist as? [String: Any] else {
            throw DERError.malformedCertificate("fixture plist is not a dictionary")
        }
        return dict
    }

    private func entitlementsDictionary() -> [String: Any] {
        [
            "application-identifier": "ABCDE12345.com.example.test",
            "get-task-allow": true,
            "com.apple.developer.team-identifier": "ABCDE12345"
        ]
    }

    private func extractedCMSValues() throws -> [String: Any] {
        let data = try fixture("extracted.json")
        let object = try JSONSerialization.jsonObject(with: data, options: [])
        guard let dict = object as? [String: Any] else {
            throw DERError.malformedCertificate("extracted.json is not an object")
        }
        return dict
    }

    // MARK: - Slot blobs

    func testRequirementsBlobMatchesZsignByteForByte() throws {
        let ours = CodeSigningSlot.requirements(
            bundleID: "com.example.test",
            subjectCommonName: "iPhone Development: com.example.test"
        )
        XCTAssertEqual(ours, try fixture("Requirements.slot.new"))
    }

    func testDEREntitlementsBlobMatchesZsignByteForByte() throws {
        let ours = CodeSigningSlot.derEntitlements(
            try DEREncoder.encode(entitlements: entitlementsDictionary())
        )
        XCTAssertEqual(ours, try fixture("Entitlements.der.slot.new"))
    }

    func testXMLEntitlementsAreSemanticallyIdenticalToZsign() throws {
        let xml = try PropertyListSerialization.data(
            fromPropertyList: entitlementsDictionary(),
            format: .xml,
            options: 0
        )
        let oracleXML = try dictionaryFromPlist(fixture("Entitlements.plist.new"))
        let oursXML = try dictionaryFromPlist(xml)
        XCTAssertEqual(
            NSDictionary(dictionary: oursXML),
            NSDictionary(dictionary: oracleXML)
        )
    }

    // MARK: - CodeDirectories

    /// Masks the four `flags` bytes at offset 12 where ghost-code deliberately diverges from zsign.
    private func maskFlags(_ cd: Data) -> Data {
        var masked = cd
        masked.replaceSubrange(12..<16, with: Data(repeating: 0xEE, count: 4))
        return masked
    }

    private func buildOracleCD(hash: CodeDirectoryHash) throws -> Data {
        let requirements = try fixture("Requirements.slot.new")
        let xmlEntitlements = try fixture("Entitlements.slot.new")
        let derEntitlements = try fixture("Entitlements.der.slot.new")
        let infoPlist = try fixture("Info.plist")
        let codeResources = try fixture("CodeResources")
        let binary = try fixture("app.bin")

        return CodeDirectoryBuilder.build(
            binaryData: binary,
            codeLimit: 0x8000,
            identifier: "com.example.test",
            requirementsBlob: requirements,
            xmlEntitlementsBlob: xmlEntitlements,
            derEntitlementsBlob: derEntitlements,
            infoPlistData: infoPlist,
            resourceDirData: codeResources,
            teamID: "ABCDE12345",
            execSegLimit: 0x4000,
            isExecutableImage: true,
            getTaskAllow: true,
            isAdHoc: false,
            hash: hash
        )
    }

    func testSHA1CodeDirectoryMatchesZsignExceptFlags() throws {
        let ours = try buildOracleCD(hash: .sha1)
        let oracle = try fixture("CodeDirectory_SHA1.slot.new")
        XCTAssertEqual(ours.count, oracle.count, "a length change shifts every later slot")
        XCTAssertEqual(maskFlags(ours), maskFlags(oracle))

        // Document the divergence we masked: codesign-style flags vs zsign's zero.
        let ourFlags = ours.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: 12, as: UInt32.self)) }
        XCTAssertEqual(
            ourFlags,
            GhostCodeConstants.CodeSigning.CS_ENTITLEMENTS_VALIDATED | GhostCodeConstants.CodeSigning.CS_GET_TASK_ALLOW
        )
    }

    func testSHA256CodeDirectoryMatchesZsignExceptFlags() throws {
        let ours = try buildOracleCD(hash: .sha256)
        let oracle = try fixture("CodeDirectory_SHA256.slot.new")
        XCTAssertEqual(ours.count, oracle.count)
        XCTAssertEqual(maskFlags(ours), maskFlags(oracle))
    }

    // MARK: - CMS

    private func oracleCMSRequest(certificates: [Data]) throws -> PKCS7SignatureRequest {
        let values = try extractedCMSValues()
        let primaryCD = try fixture("CodeDirectory_SHA1.slot.new")
        let alternateCD = try fixture("CodeDirectory_SHA256.slot.new")

        let cdHashes = [
            CryptoHelpers.sha1(primaryCD),
            Data(CryptoHelpers.sha256(alternateCD).prefix(CodeDirectoryHash.sha1.hashSize))
        ]
        guard let signingTime = values["signingTime"] as? String,
              let signatureBase64 = values["signatureBase64"] as? String,
              let signature = Data(base64Encoded: signatureBase64) else {
            throw DERError.malformedCertificate("extracted.json is missing CMS inputs")
        }

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        let signingDate = formatter.date(from: signingTime) ?? Date(timeIntervalSince1970: 0)

        return PKCS7SignatureRequest(
            content: primaryCD,
            certificates: certificates,
            cdHashes: cdHashes,
            sha256CDHash: CryptoHelpers.sha256(alternateCD),
            signatureAlgorithmOID: GhostCodeConstants.OIDs.rsaEncryption,
            signatureAlgorithmHasNullParameters: true,
            signingTime: signingDate,
            sign: { _ in signature }
        )
    }

    private func oracleCertificates() throws -> [Data] {
        let values = try extractedCMSValues()
        guard let certs = values["certsBase64"] as? [String] else {
            throw DERError.malformedCertificate("extracted.json has no certsBase64")
        }
        return certs.compactMap { Data(base64Encoded: $0) }
    }

    /// zsign order is [chain, leaf]; ghost-code follows codesign's [leaf, chain]. The certificate
    /// elements in the CMS are compared with their positions swapped.
    func testCMSByteIdenticalToZsignModuloCertificateOrder() throws {
        let oracle = try fixture("CMSSignature.slot.new")
        let certs = try oracleCertificates() // [CA, leaf] as zsign serialized them
        let ours = try CodeSigningSlot.cmsSignature(
            PKCS7Builder.build(oracleCMSRequest(certificates: [certs[1], certs[0]]))
        )

        // Constants derived from `openssl asn1parse -inform der -in CMSSignature.der.new`:
        // the certificates [0] wrapper (0x732 = 1842 bytes of content) spans bytes 54..<1900 of
        // the bare CMS (62..<1908 with the 8-byte blob header); the CA element covers 58..<953
        // and the leaf 953..<1900.
        let base = 8 // blob wrapper header
        let certsStart = base + 58
        let caLength = 895
        let leafLength = 947
        let certsEnd = base + 1900

        XCTAssertEqual(ours.count, oracle.count)
        XCTAssertEqual(ours[..<certsStart], oracle[..<certsStart], "ContentInfo/SignedData prefix")
        XCTAssertEqual(
            ours[certsStart..<(certsStart + leafLength)],
            oracle[(certsStart + caLength)..<certsEnd],
            "our leaf-first slot must hold the same leaf bytes zsign put second"
        )
        XCTAssertEqual(
            ours[(certsStart + leafLength)..<certsEnd],
            oracle[certsStart..<(certsStart + caLength)],
            "our CA follows the leaf with the same bytes zsign put first"
        )
        XCTAssertEqual(ours[certsEnd...], oracle[certsEnd...], "SignerInfo and signature region")

        // Sanity: the bare CMS equals the oracle CMS bytes too, after the same swap.
        let bareOurs = try PKCS7Builder.build(oracleCMSRequest(certificates: [certs[1], certs[0]]))
        let bareOracle = try fixture("CMSSignature.der.new")
        XCTAssertEqual(bareOurs.count, bareOracle.count)
        XCTAssertEqual(bareOurs[..<58], bareOracle[..<58])
        XCTAssertEqual(bareOurs[58..<1005], bareOracle[953..<1900])
        XCTAssertEqual(bareOurs[1005..<1900], bareOracle[58..<953])
        XCTAssertEqual(bareOurs[1900...], bareOracle[1900...])
    }

    // MARK: - SuperBlob

    /// Fed every slot blob the oracle produced, the SuperBlob must match zsign: same index table,
    /// same offsets, same payloads. The CMS payload is compared modulo certificate order (see above).
    func testSuperBlobByteIdenticalWhenFedOracleSlots() throws {
        let primaryCD = try fixture("CodeDirectory_SHA1.slot.new")
        let alternateCD = try fixture("CodeDirectory_SHA256.slot.new")
        let requirements = try fixture("Requirements.slot.new")
        let xmlEntitlements = try fixture("Entitlements.slot.new")
        let derEntitlements = try fixture("Entitlements.der.slot.new")
        let certs = try oracleCertificates()
        let cms = try CodeSigningSlot.cmsSignature(
            PKCS7Builder.build(oracleCMSRequest(certificates: [certs[1], certs[0]]))
        )

        let ours = SuperBlobBuilder.build(
            codeDirectory: primaryCD,
            requirementsBlob: requirements,
            xmlEntitlementsBlob: xmlEntitlements,
            derEntitlementsBlob: derEntitlements,
            alternateCodeDirectory: alternateCD,
            cmsSignatureBlob: cms
        )
        let oracle = try fixture("CodeSignature.blob.new")

        XCTAssertEqual(ours.count, oracle.count)

        let oracleSlots = try parseSuperBlob(oracle)
        let ourSlots = try parseSuperBlob(ours)
        XCTAssertEqual(ourSlots.map(\.type), oracleSlots.map(\.type), "slot order")
        XCTAssertEqual(ourSlots.map(\.offset), oracleSlots.map(\.offset), "slot offsets")
        XCTAssertEqual(ourSlots.map { $0.data.count }, oracleSlots.map { $0.data.count }, "slot lengths")

        for (ours, theirs) in zip(ourSlots, oracleSlots) {
            if ours.type == MachOConstants.CSSLOT_SIGNATURESLOT {
                assertCMS(ours.data, equalsModuloCertOrder: theirs.data)
            } else {
                XCTAssertEqual(ours.data, theirs.data, "slot \(String(format: "%#x", ours.type))")
            }
        }
    }

    private func assertCMS(_ ours: Data, equalsModuloCertOrder oracle: Data, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(ours.count, oracle.count, file: file, line: line)
        let certsStart = 8 + 58
        let caLength = 895
        let leafLength = 947
        let certsEnd = 8 + 1900
        XCTAssertEqual(ours[..<certsStart], oracle[..<certsStart], file: file, line: line)
        XCTAssertEqual(
            ours[certsStart..<(certsStart + leafLength)],
            oracle[(certsStart + caLength)..<certsEnd],
            file: file, line: line
        )
        XCTAssertEqual(
            ours[(certsStart + leafLength)..<certsEnd],
            oracle[certsStart..<(certsStart + caLength)],
            file: file, line: line
        )
        XCTAssertEqual(ours[certsEnd...], oracle[certsEnd...], file: file, line: line)
    }

    private func parseSuperBlob(_ blob: Data) throws -> [(type: UInt32, offset: Int, data: Data)] {
        guard blob.count >= 12 else { throw DERError.truncated }
        let count = Int(blob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt32.self).bigEndian })
        var entries: [(UInt32, Int, Data)] = []
        for i in 0..<count {
            let entryOffset = 12 + i * 8
            let type = blob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entryOffset, as: UInt32.self).bigEndian }
            let start = Int(blob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: entryOffset + 4, as: UInt32.self).bigEndian })
            let end = i + 1 < count
                ? Int(blob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 12 + (i + 1) * 8 + 4, as: UInt32.self).bigEndian })
                : blob.count
            guard start <= end, end <= blob.count else { throw DERError.truncated }
            entries.append((type, start, blob.subdata(in: start..<end)))
        }
        return entries
    }
}

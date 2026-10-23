import XCTest
@testable import GhostCode

private typealias OIDs = GhostCodeConstants.OIDs

final class CMSSignerTests: XCTestCase {
    private let content = Data("CodeDirectoryBytes_Test".utf8)
    private let fixedTime = Date(timeIntervalSince1970: 1_700_000_000)

    private func request(
        signatureAlgorithmOID: String = OIDs.sha256WithRSAEncryption,
        hasNullParameters: Bool = true,
        sign: PKCS7ContentSigner? = nil
    ) -> PKCS7SignatureRequest {
        PKCS7SignatureRequest(
            content: content,
            certificates: SigningFixtures.certificateChain,
            cdHashes: [SigningFixtures.randomHash(20)],
            sha256CDHash: SigningFixtures.randomHash(32),
            signatureAlgorithmOID: signatureAlgorithmOID,
            signatureAlgorithmHasNullParameters: hasNullParameters,
            signingTime: fixedTime,
            sign: sign ?? { _ in Data(repeating: 0xAB, count: 256) }
        )
    }

    /// ContentInfo -> SEQUENCE{ OID signedData, [0] SignedData }
    private func signedDataContent(of cms: Data) throws -> DERTLV {
        let contentInfo = try DERTLV.parseSingle(cms).requiring(tag: DER.tagSequence)
        let children = contentInfo.children
        guard children.count >= 2 else { throw DERError.malformedCertificate("ContentInfo has no content") }
        XCTAssertEqual(DER.objectIdentifierValue(children[0].content), OIDs.contentTypeSignedData)
        let wrapper = try children[1].requiring(tag: 0xA0)
        guard let signedData = wrapper.children.first else {
            throw DERError.malformedCertificate("empty [0] content")
        }
        return try signedData.requiring(tag: DER.tagSequence)
    }

    private func signerInfo(in cms: Data) throws -> DERTLV {
        let signedData = try signedDataContent(of: cms)
        let fields = signedData.children
        // version, digestAlgorithms, encapContentInfo, [0] certificates, signerInfos
        guard fields.count >= 5 else { throw DERError.malformedCertificate("short SignedData") }
        let signerInfos = try fields[4].requiring(tag: DER.tagSet)
        guard let info = signerInfos.children.first else { throw DERError.malformedCertificate("no signer info") }
        return try info.requiring(tag: DER.tagSequence)
    }

    func testBuildProducesWellFormedCMS() throws {
        let cms = try PKCS7Builder.build(request())
        let signedData = try signedDataContent(of: cms)
        let fields = signedData.children

        XCTAssertEqual(fields[0].tag, DER.tagInteger)
        XCTAssertEqual([UInt8](fields[0].content), [0x01], "SignedData version must be 1")
        XCTAssertEqual(fields[1].tag, DER.tagSet, "digestAlgorithms")
        let digestAlgorithm = fields[1].children.first?.children.first?.content ?? Data()
        XCTAssertEqual(DER.objectIdentifierValue(digestAlgorithm), OIDs.sha256)
        XCTAssertEqual(fields[2].tag, DER.tagSequence, "encapContentInfo is detached: data OID only")
        XCTAssertEqual(DER.objectIdentifierValue(fields[2].children.first?.content ?? Data()), OIDs.contentTypeData)
        XCTAssertEqual(fields[3].tag, 0xA0, "certificates")
        XCTAssertEqual(fields[3].children.count, SigningFixtures.certificateChain.count)

        let info = try signerInfo(in: cms)
        XCTAssertEqual([UInt8](info.children[0].content), [0x01], "SignerInfo version")
        XCTAssertEqual(info.children[1].tag, DER.tagSequence, "issuerAndSerialNumber")
        XCTAssertEqual(info.children[2].tag, DER.tagSequence, "digestAlgorithm")
        XCTAssertEqual(info.children[3].tag, 0xA0, "signedAttrs")
        XCTAssertEqual(info.children[4].tag, DER.tagSequence, "signatureAlgorithm")
        XCTAssertEqual(info.children[5].tag, DER.tagOctetString, "signature")
    }

    /// Apple's verifier walks the attributes positionally: 9.1 last, 9.2 just before it.
    func testSignedAttributeOrder() throws {
        let make = request()
        let cms = try PKCS7Builder.build(make)
        let info = try signerInfo(in: cms)
        guard let attrs = info.children.first(where: { $0.tag == 0xA0 }) else {
            return XCTFail("missing signed attributes")
        }
        let oids = attrs.children.map { DER.objectIdentifierValue($0.children.first?.content ?? Data()) }
        XCTAssertEqual(oids, [
            OIDs.cmsContentType,
            OIDs.cmsSigningTime,
            OIDs.cmsMessageDigest,
            OIDs.appleCMSCodeDirectoryHashes2,
            OIDs.appleCMSCodeDirectoryHashes
        ])
    }

    func testMessageDigestAndCDHashes2() throws {
        let req = request()
        let cms = try PKCS7Builder.build(req)
        let info = try signerInfo(in: cms)
        let attrs: [DERTLV] = info.children.first(where: { $0.tag == 0xA0 })?.children ?? []
        func values(for oid: String) -> [DERTLV] {
            guard let attribute = attrs.first(where: {
                DER.objectIdentifierValue($0.children.first?.content ?? Data()) == oid
            }), let valueSet = attribute.children.dropFirst().first else {
                return []
            }
            return valueSet.children
        }
        XCTAssertEqual(
            values(for: OIDs.cmsMessageDigest).first?.content,
            CryptoHelpers.sha256(content)
        )
        let cdHashes2 = values(for: OIDs.appleCMSCodeDirectoryHashes2).first?.children ?? []
        XCTAssertEqual(DER.objectIdentifierValue(cdHashes2.first?.content ?? Data()), OIDs.sha256)
        XCTAssertEqual(cdHashes2.last?.content, req.sha256CDHash, "raw 32 bytes, not a nested DigestInfo")
        XCTAssertEqual(
            values(for: OIDs.appleCMSCodeDirectoryHashes).first?.content,
            PKCS7Builder.cdHashesPlist(req.cdHashes)
        )
    }

    /// The "0x31 vs 0xA0" trap: the attributes hash as a SET but are written as a context tag.
    func testSignatureCoversTheSetEncodingOfTheAttributes() throws {
        let recorder = SignatureRecorder()
        let req = request(sign: { toBeSigned in
            recorder.toBeSigned = toBeSigned
            return Data(repeating: 0x23, count: 64)
        })
        let cms = try PKCS7Builder.build(req)
        let info = try signerInfo(in: cms)
        let writtenAttributes: Data? = info.children.first(where: { $0.tag == 0xA0 })?.content

        let expected = DER.set(PKCS7Builder.signedAttributesContent(of: req))
        XCTAssertEqual(recorder.toBeSigned, expected)
        XCTAssertNotEqual(recorder.toBeSigned, writtenAttributes)
        XCTAssertEqual(info.children.last?.content, Data(repeating: 0x23, count: 64))
    }

    func testCDHashesPlistMatchesApplesExactBytes() {
        let hash = Data([UInt8](0..<20))
        let plist = PKCS7Builder.cdHashesPlist([hash])
        // zsign ends the plist with a newline, so the oracle bytes do too.
        let expected = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
        \t<key>cdhashes</key>
        \t<array>
        \t\t<data>
        \t\tAAECAwQFBgcICQoLDA0ODxAREhM=
        \t\t</data>
        \t</array>
        </dict>
        </plist>
        """ + "\n"
        XCTAssertEqual(String(decoding: plist, as: UTF8.self), expected)
    }

    func testRSAKeepsNullParametersAndECDSADropsThem() throws {
        let rsa = try signerInfo(in: PKCS7Builder.build(request()))
        let rsaAlgorithm = rsa.children[4]
        XCTAssertEqual(rsaAlgorithm.children.count, 2, "RSA algorithm identifier carries NULL parameters")
        XCTAssertEqual(rsaAlgorithm.children.last?.tag, 0x05, "NULL parameter")
        XCTAssertEqual(rsaAlgorithm.children.last?.content, Data(), "NULL parameter has empty content")

        let ecdsa = try signerInfo(in: PKCS7Builder.build(request(
            signatureAlgorithmOID: OIDs.ecdsaWithSHA256,
            hasNullParameters: false
        )))
        XCTAssertEqual(DER.objectIdentifierValue(ecdsa.children[4].children.first?.content ?? Data()), OIDs.ecdsaWithSHA256)
        XCTAssertEqual(ecdsa.children[4].children.count, 1, "ECDSA algorithm identifier carries no parameters")
    }

    func testRejectsUndersizedCDHashes() {
        var bad = request()
        bad = PKCS7SignatureRequest(
            content: bad.content,
            certificates: bad.certificates,
            cdHashes: [SigningFixtures.randomHash(32)],
            sha256CDHash: bad.sha256CDHash,
            signatureAlgorithmOID: bad.signatureAlgorithmOID,
            signatureAlgorithmHasNullParameters: bad.signatureAlgorithmHasNullParameters,
            signingTime: bad.signingTime,
            sign: bad.sign
        )
        XCTAssertThrowsError(try PKCS7Builder.build(bad)) { error in
            guard case PKCS7BuilderError.cdHashHasWrongLength(expected: 20, actual: 32) = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }

    func testRejectsEmptyCertificateChain() {
        let req = PKCS7SignatureRequest(
            content: content,
            certificates: [],
            cdHashes: [],
            sha256CDHash: SigningFixtures.randomHash(32),
            signatureAlgorithmOID: OIDs.sha256WithRSAEncryption,
            signingTime: fixedTime,
            sign: { _ in Data() }
        )
        XCTAssertThrowsError(try PKCS7Builder.build(req)) { error in
            guard case PKCS7BuilderError.emptyCertificateChain = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }

    func testSuperBlobCarriesCMSSignatureInSlot0x10000() throws {
        let cms = try PKCS7Builder.build(request())
        let superBlob = SuperBlobBuilder.build(
            codeDirectory: content,
            cmsSignatureBlob: CodeSigningSlot.cmsSignature(cms)
        )

        let magic = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) })
        let count = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt32.self) })
        XCTAssertEqual(magic, MachOConstants.CSMAGIC_EMBEDDED_SIGNATURE)
        XCTAssertEqual(count, 2, "CodeDirectory (0) + Signature (0x10000)")

        var foundSigSlot = false
        for i in 0..<Int(count) {
            let offset = 12 + i * 8
            let type = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) })
            let blobOffset = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self) })
            if type == MachOConstants.CSSLOT_SIGNATURESLOT {
                foundSigSlot = true
                let blobMagic = UInt32(bigEndian: superBlob.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: Int(blobOffset), as: UInt32.self) })
                XCTAssertEqual(blobMagic, MachOConstants.CSMAGIC_BLOBWRAPPER)
            }
        }
        XCTAssertTrue(foundSigSlot)
    }
}

/// Captures the bytes a signer closure was handed; test-only, mutable state owned by the test.
private final class SignatureRecorder: @unchecked Sendable {
    var toBeSigned: Data?
}

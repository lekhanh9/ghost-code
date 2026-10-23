import Foundation

/// Signs the DER-encoded authenticated attributes of a CMS signer info and returns the signature
/// octets. `SecKey.createSignature` on-device and a fixed value in tests both satisfy it, which is
/// what keeps this builder free of a crypto backend.
public typealias PKCS7ContentSigner = @Sendable (Data) throws -> Data

public enum PKCS7BuilderError: Swift.Error, Equatable {
    case emptyCertificateChain
    case invalidCertificate(String)
    case cdHashHasWrongLength(expected: Int, actual: Int)
}

/// The inputs a CMS detached signature over a code signature needs. The private-key operation is
/// injected so the builder stays dependency-free: callers sign on-device with `SecKey`, and tests
/// sign with a pre-computed value.
public struct PKCS7SignatureRequest: Sendable {
    /// The slot-0 CodeDirectory blob. Apple verifies the detached content against these exact bytes.
    public let content: Data
    /// The signing certificate followed by its issuers, serialized in the order given.
    public let certificates: [Data]
    /// One entry per CodeDirectory in the SuperBlob, as the 20-byte hash that goes into the
    /// `cdhashes` plist: the full SHA-1 of a SHA-1 directory, the truncated SHA-256 otherwise.
    public let cdHashes: [Data]
    /// The full 32-byte SHA-256 of the SHA-256 CodeDirectory, or of slot 0 when there is no
    /// alternate. `errSecCSSignatureFailed` is Apple's response to a directory this does not name.
    public let sha256CDHash: Data
    public let signatureAlgorithmOID: String
    /// Whether the signature algorithm carries `NULL` parameters, which RSA requires and ECDSA forbids.
    public let signatureAlgorithmHasNullParameters: Bool
    public let signingTime: Date
    /// Detached, which is what Apple emits: the content travels in the CodeDirectory slot and the
    /// PKCS#7 `encapContentInfo` carries only the data OID. Tests that need a real, verifiable
    /// signature sign the attributes over an *attached* copy of the content, because the to-be-signed
    /// bytes depend on nothing but the attributes themselves.
    public let detached: Bool
    /// Signs the DER-encoded authenticated attributes and returns the signature octets.
    public let sign: @Sendable (Data) throws -> Data

    public init(
        content: Data,
        certificates: [Data],
        cdHashes: [Data],
        sha256CDHash: Data,
        signatureAlgorithmOID: String,
        signatureAlgorithmHasNullParameters: Bool = true,
        signingTime: Date = Date(),
        detached: Bool = true,
        sign: @escaping @Sendable (Data) throws -> Data
    ) {
        self.content = content
        self.certificates = certificates
        self.cdHashes = cdHashes
        self.sha256CDHash = sha256CDHash
        self.signatureAlgorithmOID = signatureAlgorithmOID
        self.signatureAlgorithmHasNullParameters = signatureAlgorithmHasNullParameters
        self.signingTime = signingTime
        self.detached = detached
        self.sign = sign
    }
}

public enum PKCS7Builder {
    private typealias OIDs = GhostCodeConstants.OIDs
    private static let oid = OIDs.self

    /// Apple's `cdhashes` attribute: an XML plist holding each directory's hash as `<data>`.
    public static func cdHashesPlist(_ cdHashes: [Data]) -> Data {
        var xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
        \t<key>cdhashes</key>
        \t<array>

        """
        for cdHash in cdHashes {
            let base64 = cdHash.base64EncodedString()
            xml += "\t\t<data>\n\t\t\(base64)\n\t\t</data>\n"
        }
        xml += "\t</array>\n</dict>\n</plist>\n"
        return Data(xml.utf8)
    }

    /// The content of the `[0]` signed attributes: the exact bytes the signature covers.
    public static func signedAttributesContent(of request: PKCS7SignatureRequest) -> Data {
        var content = attribute(oid.cmsContentType, DER.set(DER.objectIdentifier(oid.contentTypeData)))
        content += attribute(oid.cmsSigningTime, DER.set(DER.utcTime(utcTimeValue(request.signingTime))))
        content += attribute(
            oid.cmsMessageDigest,
            DER.set(DER.octetString(CryptoHelpers.sha256(request.content)))
        )
        content += attribute(
            oid.appleCMSCodeDirectoryHashes2,
            DER.set(DER.sequence(
                DER.objectIdentifier(oid.sha256) + DER.octetString(request.sha256CDHash)
            ))
        )
        content += attribute(
            oid.appleCMSCodeDirectoryHashes,
            DER.set(DER.octetString(cdHashesPlist(request.cdHashes)))
        )
        return content
    }

    public static func build(_ request: PKCS7SignatureRequest) throws -> Data {
        guard let leafDER = request.certificates.first else {
            throw PKCS7BuilderError.emptyCertificateChain
        }
        let leaf = try X509Certificate(der: leafDER)
        for cdHash in request.cdHashes where cdHash.count != GhostCodeConstants.CodeSigning.CS_HASHSIZE_SHA1 {
            throw PKCS7BuilderError.cdHashHasWrongLength(
                expected: GhostCodeConstants.CodeSigning.CS_HASHSIZE_SHA1,
                actual: cdHash.count
            )
        }

        let signedAttributes = signedAttributesContent(of: request)
        // SignerInfo hashes the attributes as a SET OF, even though they are serialized in-place
        // as a context tag; digesting the `[0]` encoding instead produces a signature nobody accepts.
        let signature = try request.sign(DER.set(signedAttributes))

        var signerInfo = DER.integer(1)
        signerInfo += DER.sequence(leaf.issuerDER + leaf.serialDER)
        signerInfo += DER.sequence(DER.objectIdentifier(oid.sha256))
        signerInfo += DER.contextConstructed(0, signedAttributes)
        signerInfo += DER.sequence(signatureAlgorithmIdentifier(request))
        signerInfo += DER.octetString(signature)

        var encapContentInfo = DER.sequence(DER.objectIdentifier(oid.contentTypeData))
        if !request.detached {
            encapContentInfo = DER.sequence(
                DER.objectIdentifier(oid.contentTypeData)
                    + DER.contextConstructed(0, DER.octetString(request.content))
            )
        }

        var signedData = DER.integer(1)
        signedData += DER.set(DER.sequence(DER.objectIdentifier(oid.sha256)))
        signedData += encapContentInfo
        signedData += DER.contextConstructed(0, Data(request.certificates.reduce(into: Data()) { $0.append($1) }))
        signedData += DER.set(DER.sequence(signerInfo))

        return DER.sequence(
            DER.objectIdentifier(oid.contentTypeSignedData)
                + DER.contextConstructed(0, DER.sequence(signedData))
        )
    }

    /// RFC 5280 UTCTime, which is what both `codesign` and OpenSSL's CMS emit for these dates.
    static func utcTimeValue(_ date: Date) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return Data(formatter.string(from: date).utf8)
    }

    private static func signatureAlgorithmIdentifier(_ request: PKCS7SignatureRequest) -> Data {
        var content = DER.objectIdentifier(request.signatureAlgorithmOID)
        if request.signatureAlgorithmHasNullParameters {
            content += DER.element(tag: 0x05, content: Data())
        }
        return content
    }

    private static func attribute(_ oidDotted: String, _ values: Data) -> Data {
        DER.sequence(DER.objectIdentifier(oidDotted) + values)
    }
}

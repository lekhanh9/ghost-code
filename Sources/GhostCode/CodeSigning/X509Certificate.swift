import Foundation

/// The fields of an X.509 certificate that Apple's code signature needs: the designated
/// requirement wants the subject common name, and the CMS signer info wants the issuer, the
/// serial number and the key algorithm, all copied verbatim from the certificate.
public struct X509Certificate: Sendable, Equatable {
    public let der: Data
    public let issuerDER: Data
    public let serialDER: Data
    public let subjectDER: Data
    public let subjectCommonName: String?
    public let publicKeyAlgorithmOID: String?

    public enum Error: Swift.Error, Equatable {
        case notACertificate
        case missingField(String)
    }

    public init(der: Data) throws {
        self.der = der

        let root = try DERTLV.parseSingle(der).requiring(tag: DER.tagSequence)
        guard let tbsCertificate = root.children.first else {
            throw Error.notACertificate
        }

        let fields = tbsCertificate.children
        // `[0] EXPLICIT version` is absent only in X.509v1 certificates, which Apple never issues.
        let offset = fields.first?.tag == 0xA0 ? 1 : 0
        guard fields.count > offset + 6 else {
            throw Error.missingField("tbsCertificate has \(fields.count) fields, need \(offset + 7)")
        }

        self.serialDER = fields[offset].encoded
        self.issuerDER = fields[offset + 2].encoded
        self.subjectDER = fields[offset + 4].encoded
        self.publicKeyAlgorithmOID = fields[offset + 5].children.first?.objectIdentifierValue
            .flatMap { DER.objectIdentifierValue(Data($0)) }
        self.subjectCommonName = Self.commonName(in: fields[offset + 4])
    }

    /// The CMS SignerInfo signature algorithm. OpenSSL (and therefore zsign) writes the
    /// certificate's SPKI algorithm for RSA keys (`rsaEncryption`, NULL parameters) and
    /// `ecdsa-with-SHA256` (no parameters) for EC keys; Apple's verifier accepts both.
    public var signatureAlgorithmOID: String {
        usesRSA
            ? GhostCodeConstants.OIDs.rsaEncryption
            : GhostCodeConstants.OIDs.ecdsaWithSHA256
    }

    public var usesRSA: Bool {
        publicKeyAlgorithmOID == GhostCodeConstants.OIDs.rsaEncryption
    }

    /// The last `commonName` (2.5.4.3) in the subject, which is where Apple puts the
    /// "iPhone Development: <bundle id>" string that the designated requirement matches.
    private static func commonName(in subject: DERTLV) -> String? {
        let commonNameArc: [UInt8] = [0x55, 0x04, 0x03]
        var found: String?
        for relativeDistinguishedName in subject.children {
            for attributeTypeAndValue in relativeDistinguishedName.children {
                let attributes = attributeTypeAndValue.children
                guard attributes.count >= 2,
                      Array(attributes[0].content) == commonNameArc else {
                    continue
                }
                found = String(decoding: attributes[1].content, as: UTF8.self)
            }
        }
        return found
    }
}

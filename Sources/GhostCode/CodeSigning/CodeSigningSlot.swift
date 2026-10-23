import Foundation

/// The code-signing blobs that live in the SuperBlob slots. Each one is a magic number and a
/// length followed by its payload, and the CodeDirectory hashes the *whole blob* including that
/// 8-byte header.
public enum CodeSigningSlot {
    public static func blob(magic: UInt32, payload: Data) -> Data {
        var result = Data()
        appendBigEndian(magic, to: &result)
        appendBigEndian(UInt32(8 + payload.count), to: &result)
        result.append(payload)
        return result
    }

    public static func xmlEntitlements(_ xml: Data) -> Data {
        blob(magic: GhostCodeConstants.CodeSigning.CSMAGIC_EMBEDDED_ENTITLEMENTS, payload: xml)
    }

    /// `derPayload` is `DEREncoder.encode(entitlements:)`, which already carries the 0x70 envelope.
    public static func derEntitlements(_ derPayload: Data) -> Data {
        blob(magic: GhostCodeConstants.CodeSigning.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, payload: derPayload)
    }

    public static func cmsSignature(_ cms: Data) -> Data {
        blob(magic: GhostCodeConstants.CodeSigning.CSMAGIC_BLOBWRAPPER, payload: cms)
    }

    /// The designated requirement `identifier "<id>" and anchor apple generic and
    /// certificate leaf[subject.CN] = "<cn>" and certificate 1[field.1.2.840.113635.100.6.2.1]`.
    ///
    /// Returns nil when either string is missing, in which case slot 2 is simply left out of the
    /// signature and the CodeDirectory's -2 slot hashes to zero.
    public static func requirements(bundleID: String, subjectCommonName: String?) -> Data? {
        guard !bundleID.isEmpty, let subjectCommonName, !subjectCommonName.isEmpty else {
            return nil
        }

        var expression = Data()
        appendBigEndian(GhostCodeConstants.CodeSigning.REQ_OP_TRUE, to: &expression)
        appendBigEndian(GhostCodeConstants.CodeSigning.REQ_OP_AND, to: &expression)
        appendBigEndian(GhostCodeConstants.CodeSigning.REQ_OP_IDENT, to: &expression)
        expression.append(paddedString(bundleID))

        appendBigEndian(GhostCodeConstants.CodeSigning.REQ_OP_AND, to: &expression)
        appendBigEndian(GhostCodeConstants.CodeSigning.REQ_OP_APPLE_GENERIC_ANCHOR, to: &expression)

        appendBigEndian(GhostCodeConstants.CodeSigning.REQ_OP_AND, to: &expression)
        appendBigEndian(GhostCodeConstants.CodeSigning.REQ_OP_CERT_FIELD, to: &expression)
        appendBigEndian(UInt32(0), to: &expression) // slot 0 is the leaf certificate
        expression.append(paddedString("subject.CN"))
        appendBigEndian(GhostCodeConstants.CodeSigning.REQ_MATCH_EQUAL, to: &expression)
        expression.append(paddedString(subjectCommonName))

        appendBigEndian(GhostCodeConstants.CodeSigning.REQ_OP_CERT_GENERIC, to: &expression)
        appendBigEndian(UInt32(1), to: &expression) // slot 1 is the intermediate certificate
        expression.append(paddedString(Data(GhostCodeConstants.CodeSigning.APPLE_WWDR_MARKER_OID_DER)))
        appendBigEndian(GhostCodeConstants.CodeSigning.REQ_MATCH_EXISTS, to: &expression)

        let innerRequirement = blob(
            magic: GhostCodeConstants.CodeSigning.CSMAGIC_REQUIREMENT,
            payload: expression
        )

        var requirements = Data()
        appendBigEndian(GhostCodeConstants.CodeSigning.CSMAGIC_REQUIREMENTS, to: &requirements)
        appendBigEndian(UInt32(20 + innerRequirement.count), to: &requirements)
        appendBigEndian(UInt32(1), to: &requirements) // one entry
        appendBigEndian(GhostCodeConstants.CodeSigning.SEC_DESIGNATED_REQUIREMENT_TYPE, to: &requirements)
        appendBigEndian(UInt32(20), to: &requirements) // offset of the single requirement blob
        requirements.append(innerRequirement)
        return requirements
    }

    /// A length-prefixed string padded with NULs to the next 4-byte boundary, as requirement
    /// expressions require.
    private static func paddedString(_ string: String) -> Data {
        paddedString(Data(string.utf8))
    }

    private static func paddedString(_ bytes: Data) -> Data {
        var result = Data()
        appendBigEndian(UInt32(bytes.count), to: &result)
        result.append(bytes)
        let padding = (4 - (bytes.count % 4)) % 4
        if padding > 0 {
            result.append(Data(repeating: 0, count: padding))
        }
        return result
    }

    static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }
}

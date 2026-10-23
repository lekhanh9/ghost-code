import Foundation

public struct SuperBlobBuilder {
    public struct BlobEntry {
        public let type: UInt32
        public let data: Data

        public init(type: UInt32, data: Data) {
            self.type = type
            self.data = data
        }
    }

    /// Assembles the embedded signature SuperBlob. Every argument is a complete slot blob already
    /// carrying its magic and length; only the CodeDirectory and the alternate CodeDirectory are
    /// bare blobs because their callers built them that way.
    public static func build(
        codeDirectory: Data,
        requirementsBlob: Data? = nil,
        xmlEntitlementsBlob: Data? = nil,
        derEntitlementsBlob: Data? = nil,
        alternateCodeDirectory: Data? = nil,
        cmsSignatureBlob: Data? = nil
    ) -> Data {
        var entries = [BlobEntry]()

        // 1. CodeDirectory (CSSLOT_CODEDIRECTORY = 0)
        entries.append(BlobEntry(type: MachOConstants.CSSLOT_CODEDIRECTORY, data: codeDirectory))

        // 2. Requirements (CSSLOT_REQUIREMENTS = 2)
        if let requirements = requirementsBlob {
            entries.append(BlobEntry(type: MachOConstants.CSSLOT_REQUIREMENTS, data: requirements))
        }

        // 3. XML Entitlements (CSSLOT_ENTITLEMENTS = 5)
        if let xml = xmlEntitlementsBlob {
            entries.append(BlobEntry(type: MachOConstants.CSSLOT_ENTITLEMENTS, data: xml))
        }

        // 4. DER Entitlements (CSSLOT_DER_ENTITLEMENTS = 7)
        if let der = derEntitlementsBlob {
            entries.append(BlobEntry(type: MachOConstants.CSSLOT_DER_ENTITLEMENTS, data: der))
        }

        // 5. Alternate CodeDirectory (CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000), the SHA-256
        // partner of the SHA-1 CodeDirectory in slot 0
        if let alternate = alternateCodeDirectory {
            entries.append(BlobEntry(type: GhostCodeConstants.CodeSigning.CSSLOT_ALTERNATE_CODEDIRECTORIES, data: alternate))
        }

        // 6. CMS Signature (CSSLOT_SIGNATURESLOT = 0x10000) wrapped in CSMAGIC_BLOBWRAPPER
        if let cms = cmsSignatureBlob {
            entries.append(BlobEntry(type: MachOConstants.CSSLOT_SIGNATURESLOT, data: cms))
        }

        return build(entries: entries)
    }

    public static func build(entries: [BlobEntry]) -> Data {
        let count = UInt32(entries.count)
        let headerSize = 12
        let indexTableSize = entries.count * 8
        var currentBlobOffset = headerSize + indexTableSize

        var indexData = Data()
        var payloadData = Data()

        for entry in entries {
            appendBigEndian(entry.type, to: &indexData)
            appendBigEndian(UInt32(currentBlobOffset), to: &indexData)

            payloadData.append(entry.data)
            currentBlobOffset += entry.data.count
        }

        let totalLength = UInt32(currentBlobOffset)
        var result = Data()
        appendBigEndian(MachOConstants.CSMAGIC_EMBEDDED_SIGNATURE, to: &result)
        appendBigEndian(totalLength, to: &result)
        appendBigEndian(count, to: &result)
        result.append(indexData)
        result.append(payloadData)

        return result
    }

    private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var be = value.bigEndian
        withUnsafeBytes(of: &be) { data.append(contentsOf: $0) }
    }
}

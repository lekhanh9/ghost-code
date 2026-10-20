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

    public static func build(
        codeDirectory: Data,
        xmlEntitlements: Data? = nil,
        derEntitlements: Data? = nil,
        cmsSignature: Data? = nil
    ) -> Data {
        var entries = [BlobEntry]()

        // 1. CodeDirectory (CSSLOT_CODEDIRECTORY = 0)
        entries.append(BlobEntry(type: MachOConstants.CSSLOT_CODEDIRECTORY, data: codeDirectory))

        // 2. XML Entitlements (CSSLOT_ENTITLEMENTS = 5)
        if let xml = xmlEntitlements {
            var blob = Data()
            appendBigEndian(MachOConstants.CSMAGIC_EMBEDDED_ENTITLEMENTS, to: &blob)
            appendBigEndian(UInt32(8 + xml.count), to: &blob)
            blob.append(xml)
            entries.append(BlobEntry(type: MachOConstants.CSSLOT_ENTITLEMENTS, data: blob))
        }

        // 3. DER Entitlements (CSSLOT_DER_ENTITLEMENTS = 7)
        if let der = derEntitlements {
            var blob = Data()
            appendBigEndian(MachOConstants.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, to: &blob)
            appendBigEndian(UInt32(8 + der.count), to: &blob)
            blob.append(der)
            entries.append(BlobEntry(type: MachOConstants.CSSLOT_DER_ENTITLEMENTS, data: blob))
        }

        // 4. CMS Signature (CSSLOT_SIGNATURESLOT = 0x10000) wrapped in CSMAGIC_BLOBWRAPPER
        if let cms = cmsSignature {
            var blob = Data()
            appendBigEndian(MachOConstants.CSMAGIC_BLOBWRAPPER, to: &blob)
            appendBigEndian(UInt32(8 + cms.count), to: &blob)
            blob.append(cms)
            entries.append(BlobEntry(type: MachOConstants.CSSLOT_SIGNATURESLOT, data: blob))
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

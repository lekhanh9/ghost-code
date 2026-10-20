import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

@frozen
public struct CodeDirectory: Sendable, Equatable {
    public var magic: UInt32         // 0xfade0c02
    public var length: UInt32        // Total length of CodeDirectory blob
    public var version: UInt32       // Compatibility version (e.g. 0x20400)
    public var flags: UInt32         // Flags
    public var hashOffset: UInt32    // Offset of code slot 0
    public var identOffset: UInt32   // Offset of identifier string
    public var nSpecialSlots: UInt32 // Number of special slots (e.g. 7)
    public var nCodeSlots: UInt32    // Number of ordinary code slots
    public var codeLimit: UInt32     // Limit of binary covered by code signature
    public var hashSize: UInt8       // Size of each hash in bytes (32 for SHA-256)
    public var hashType: UInt8       // Type of hash (2 for SHA-256)
    public var platform: UInt8       // Platform identifier (0)
    public var pageSize: UInt8       // Log2(page size) (12 => 4096 bytes)
    public var spare2: UInt32        // Unused (must be zero)

    public init(
        magic: UInt32 = MachOConstants.CSMAGIC_CODEDIRECTORY,
        length: UInt32 = 0,
        version: UInt32 = 0x20400,
        flags: UInt32 = 0,
        hashOffset: UInt32 = 0,
        identOffset: UInt32 = 0,
        nSpecialSlots: UInt32 = 7,
        nCodeSlots: UInt32 = 0,
        codeLimit: UInt32 = 0,
        hashSize: UInt8 = 32,
        hashType: UInt8 = MachOConstants.CS_HASHTYPE_SHA256,
        platform: UInt8 = 0,
        pageSize: UInt8 = 12,
        spare2: UInt32 = 0
    ) {
        self.magic = magic
        self.length = length
        self.version = version
        self.flags = flags
        self.hashOffset = hashOffset
        self.identOffset = identOffset
        self.nSpecialSlots = nSpecialSlots
        self.nCodeSlots = nCodeSlots
        self.codeLimit = codeLimit
        self.hashSize = hashSize
        self.hashType = hashType
        self.platform = platform
        self.pageSize = pageSize
        self.spare2 = spare2
    }
}

public struct CodeDirectoryBuilder {
    public static let defaultPageSize: Int = 4096
    public static let defaultPageSizeExponent: UInt8 = 12 // 2^12 = 4096

    public static func build(
        binaryData: Data,
        codeLimit: Int? = nil,
        identifier: String = "GhostCode",
        xmlEntitlements: Data? = nil,
        derEntitlements: Data? = nil
    ) -> Data {
        let actualCodeLimit = min(codeLimit ?? binaryData.count, binaryData.count)
        let pageSize = defaultPageSize
        let nCodeSlots = (actualCodeLimit + pageSize - 1) / pageSize

        // Slots:
        // Slot -5 = CSSLOT_ENTITLEMENTS (XML)
        // Slot -7 = CSSLOT_DER_ENTITLEMENTS (DER)
        let nSpecialSlots: UInt32 = (derEntitlements != nil) ? 7 : ((xmlEntitlements != nil) ? 5 : 7)

        let hashSize: Int = 32 // SHA-256
        let headerSize = 44

        let identOffset = headerSize
        let identBytes = Data(identifier.utf8) + Data([0x00])

        let specialSlotsOffset = identOffset + identBytes.count
        let specialSlotsByteCount = Int(nSpecialSlots) * hashSize
        let hashOffset = specialSlotsOffset + specialSlotsByteCount

        let codeSlotsByteCount = nCodeSlots * hashSize
        let totalLength = hashOffset + codeSlotsByteCount

        let header = CodeDirectory(
            magic: MachOConstants.CSMAGIC_CODEDIRECTORY,
            length: UInt32(totalLength),
            version: 0x20400,
            flags: 0x20002, // ad-hoc
            hashOffset: UInt32(hashOffset),
            identOffset: UInt32(identOffset),
            nSpecialSlots: nSpecialSlots,
            nCodeSlots: UInt32(nCodeSlots),
            codeLimit: UInt32(actualCodeLimit),
            hashSize: UInt8(hashSize),
            hashType: MachOConstants.CS_HASHTYPE_SHA256,
            platform: 0,
            pageSize: defaultPageSizeExponent,
            spare2: 0
        )

        var blob = Data()
        appendBigEndian(header.magic, to: &blob)
        appendBigEndian(header.length, to: &blob)
        appendBigEndian(header.version, to: &blob)
        appendBigEndian(header.flags, to: &blob)
        appendBigEndian(header.hashOffset, to: &blob)
        appendBigEndian(header.identOffset, to: &blob)
        appendBigEndian(header.nSpecialSlots, to: &blob)
        appendBigEndian(header.nCodeSlots, to: &blob)
        appendBigEndian(header.codeLimit, to: &blob)
        blob.append(header.hashSize)
        blob.append(header.hashType)
        blob.append(header.platform)
        blob.append(header.pageSize)
        appendBigEndian(header.spare2, to: &blob)

        // Identifier string
        blob.append(identBytes)

        // Special slots buffer: nSpecialSlots * 32 bytes
        // Slot -k is stored at: (nSpecialSlots - k) * 32
        var specialSlotsData = Data(repeating: 0, count: specialSlotsByteCount)

        if let xml = xmlEntitlements, nSpecialSlots >= 5 {
            let digest = sha256(xml)
            let offset = Int(nSpecialSlots - 5) * hashSize
            specialSlotsData.replaceSubrange(offset..<(offset + hashSize), with: digest)
        }

        if let der = derEntitlements, nSpecialSlots >= 7 {
            let digest = sha256(der)
            let offset = Int(nSpecialSlots - 7) * hashSize
            specialSlotsData.replaceSubrange(offset..<(offset + hashSize), with: digest)
        }

        blob.append(specialSlotsData)

        // Code slots: hash each 4096-byte page of binary up to codeLimit
        for slotIndex in 0..<nCodeSlots {
            let start = slotIndex * pageSize
            let end = min(start + pageSize, actualCodeLimit)
            let pageSlice = binaryData.subdata(in: start..<end)
            let digest = sha256(pageSlice)
            blob.append(digest)
        }

        return blob
    }

    public static func sha256(_ data: Data) -> Data {
        CryptoHelpers.sha256(data)
    }

    private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var be = value.bigEndian
        withUnsafeBytes(of: &be) { data.append(contentsOf: $0) }
    }
}

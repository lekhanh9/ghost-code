import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

private typealias CS = GhostCodeConstants.CodeSigning

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
    public var platform: UInt8       // Platform identifier (0); `spare1` in Apple's header
    public var pageSize: UInt8       // Log2(page size) (12 => 4096 bytes)
    public var spare2: UInt32        // Unused (must be zero)

    /// >= 0x20100. Zero until scatter blobs are emitted.
    public var scatterOffset: UInt32
    /// >= 0x20200. Offset of the NUL-terminated team string, or zero when absent.
    public var teamOffset: UInt32
    /// >= 0x20300.
    public var spare3: UInt32
    public var codeLimit64: UInt64
    /// >= 0x20400.
    public var execSegBase: UInt64
    public var execSegLimit: UInt64
    public var execSegFlags: UInt64

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
        spare2: UInt32 = 0,
        scatterOffset: UInt32 = 0,
        teamOffset: UInt32 = 0,
        spare3: UInt32 = 0,
        codeLimit64: UInt64 = 0,
        execSegBase: UInt64 = 0,
        execSegLimit: UInt64 = 0,
        execSegFlags: UInt64 = 0
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
        self.scatterOffset = scatterOffset
        self.teamOffset = teamOffset
        self.spare3 = spare3
        self.codeLimit64 = codeLimit64
        self.execSegBase = execSegBase
        self.execSegLimit = execSegLimit
        self.execSegFlags = execSegFlags
    }

    /// The header is version-gated: a verifier sizes everything after it from `version`, so writing
    /// fewer bytes than this returns makes the identifier string be parsed as the extension fields.
    public static func headerLength(version: UInt32) -> Int {
        var length = CS.CS_CODEDIRECTORY_BASE_HEADER_SIZE
        if version >= CS.CS_SUPPORTSSCATTER {
            length += 4 // scatterOffset
        }
        if version >= CS.CS_SUPPORTSTEAMID {
            length += 4 // teamOffset
        }
        if version >= CS.CS_SUPPORTS64BITLIMIT {
            length += 4 + 8 // spare3 + codeLimit64
        }
        if version >= CS.CS_SUPPORTSEXECSEG {
            length += 8 + 8 + 8 // execSegBase + execSegLimit + execSegFlags
        }
        return length
    }
}

/// The hash a CodeDirectory blob is built with. Apple's verifier picks the CD by this, so a
/// signature carries a SHA-1 CD as slot 0 and a SHA-256 CD as the slot 0x1000 alternate.
public enum CodeDirectoryHash: Sendable {
    case sha1
    case sha256

    public var hashSize: Int {
        switch self {
        case .sha1: return CS.CS_HASHSIZE_SHA1
        case .sha256: return CS.CS_HASHSIZE_SHA256
        }
    }

    public var hashType: UInt8 {
        switch self {
        case .sha1: return MachOConstants.CS_HASHTYPE_SHA1
        case .sha256: return MachOConstants.CS_HASHTYPE_SHA256
        }
    }

    public func hash(_ data: Data) -> Data {
        switch self {
        case .sha1: return CryptoHelpers.sha1(data)
        case .sha256: return CryptoHelpers.sha256(data)
        }
    }
}

public struct CodeDirectoryBuilder {
    public static let defaultPageSize: Int = 4096
    public static let defaultPageSizeExponent: UInt8 = 12 // 2^12 = 4096

    public static func build(
        binaryData: Data,
        codeLimit: Int? = nil,
        identifier: String = "GhostCode",
        requirementsBlob: Data? = nil,
        xmlEntitlementsBlob: Data? = nil,
        derEntitlementsBlob: Data? = nil,
        infoPlistData: Data? = nil,
        resourceDirData: Data? = nil,
        teamID: String? = nil,
        execSegLimit: UInt64 = 0,
        isExecutableImage: Bool = false,
        getTaskAllow: Bool = false,
        isAdHoc: Bool = true,
        hash: CodeDirectoryHash = .sha256
    ) -> Data {
        let version: UInt32 = CS.CS_SUPPORTSEXECSEG
        let actualCodeLimit = min(codeLimit ?? binaryData.count, binaryData.count)
        let pageSize = defaultPageSize
        let nCodeSlots = (actualCodeLimit + pageSize - 1) / pageSize

        let hashSize: Int = hash.hashSize
        let emptyHash = Data(repeating: 0, count: hashSize)

        // Special slots have negative indexes; slot -k is stored at index (nSpecialSlots - k).
        // Listed here from the most negative to -1 so unused high slots can be trimmed off the front.
        // Entitlement, requirement and resource-directory slots hash the whole blob header and all;
        // Info.plist and CodeResources hash the file contents as they sit on disk.
        var specialSlots: [Data] = [
            derEntitlementsBlob.map(hash.hash) ?? emptyHash,  // -7 CSSLOT_DER_ENTITLEMENTS
            emptyHash,                                   // -6 reserved
            xmlEntitlementsBlob.map(hash.hash) ?? emptyHash,  // -5 CSSLOT_ENTITLEMENTS
            emptyHash,                                   // -4 reserved
            resourceDirData.map(hash.hash) ?? emptyHash,  // -3 CSSLOT_RESOURCEDIR
            requirementsBlob.map(hash.hash) ?? emptyHash,  // -2 CSSLOT_REQUIREMENTS
            infoPlistData.map(hash.hash) ?? emptyHash    // -1 CSSLOT_INFOPLIST
        ]
        if let firstUsed = specialSlots.firstIndex(where: { $0 != emptyHash }) {
            specialSlots.removeSubrange(0..<firstUsed)
        } else {
            specialSlots.removeAll()
        }

        var flags: UInt32 = 0
        if xmlEntitlementsBlob != nil || derEntitlementsBlob != nil {
            flags |= CS.CS_ENTITLEMENTS_VALIDATED
        }
        if isAdHoc {
            flags |= CS.CS_ADHOC
        }
        if getTaskAllow {
            flags |= CS.CS_GET_TASK_ALLOW
        }

        var execSegFlags: UInt64 = 0
        if isExecutableImage {
            execSegFlags |= CS.CS_EXECSEG_MAIN_BINARY
        }
        if getTaskAllow {
            execSegFlags |= CS.CS_EXECSEG_ALLOW_UNSIGNED
        }

        let headerSize = CodeDirectory.headerLength(version: version)
        let identOffset = headerSize
        let identBytes = Data(identifier.utf8) + Data([0x00])

        var teamBytes: Data? = nil
        if let teamID, !teamID.isEmpty {
            teamBytes = Data(teamID.utf8) + Data([0x00])
        }
        let teamOffset = teamBytes.map { _ in UInt32(identOffset + identBytes.count) } ?? 0

        let specialSlotsByteCount = specialSlots.count * hashSize
        let hashOffset = identOffset
            + identBytes.count
            + (teamBytes?.count ?? 0)
            + specialSlotsByteCount

        let codeSlotsByteCount = nCodeSlots * hashSize
        let totalLength = hashOffset + codeSlotsByteCount

        let header = CodeDirectory(
            magic: MachOConstants.CSMAGIC_CODEDIRECTORY,
            length: UInt32(totalLength),
            version: version,
            flags: flags,
            hashOffset: UInt32(hashOffset),
            identOffset: UInt32(identOffset),
            nSpecialSlots: UInt32(specialSlots.count),
            nCodeSlots: UInt32(nCodeSlots),
            codeLimit: UInt32(actualCodeLimit),
            hashSize: UInt8(hashSize),
            hashType: hash.hashType,
            platform: 0,
            pageSize: defaultPageSizeExponent,
            spare2: 0,
            scatterOffset: 0,
            teamOffset: teamOffset,
            spare3: 0,
            codeLimit64: 0,
            execSegBase: 0,
            execSegLimit: execSegLimit,
            execSegFlags: execSegFlags
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
        appendBigEndian(header.scatterOffset, to: &blob)
        appendBigEndian(header.teamOffset, to: &blob)
        appendBigEndian(header.spare3, to: &blob)
        appendBigEndian(header.codeLimit64, to: &blob)
        appendBigEndian(header.execSegBase, to: &blob)
        appendBigEndian(header.execSegLimit, to: &blob)
        appendBigEndian(header.execSegFlags, to: &blob)

        blob.append(identBytes)
        if let teamBytes {
            blob.append(teamBytes)
        }
        for slot in specialSlots {
            blob.append(slot)
        }

        // Code slots: hash each page of binary up to codeLimit
        for slotIndex in 0..<nCodeSlots {
            let start = slotIndex * pageSize
            let end = min(start + pageSize, actualCodeLimit)
            let pageSlice = binaryData.subdata(in: start..<end)
            blob.append(hash.hash(pageSlice))
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

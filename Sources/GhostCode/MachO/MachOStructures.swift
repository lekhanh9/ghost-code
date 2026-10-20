import Foundation

@frozen
public struct MachHeader64: Sendable, Equatable {
    public var magic: UInt32
    public var cpuType: UInt32
    public var cpuSubtype: UInt32
    public var fileType: UInt32
    public var ncmds: UInt32
    public var sizeofcmds: UInt32
    public var flags: UInt32
    public var reserved: UInt32

    public init(
        magic: UInt32 = 0,
        cpuType: UInt32 = 0,
        cpuSubtype: UInt32 = 0,
        fileType: UInt32 = 0,
        ncmds: UInt32 = 0,
        sizeofcmds: UInt32 = 0,
        flags: UInt32 = 0,
        reserved: UInt32 = 0
    ) {
        self.magic = magic
        self.cpuType = cpuType
        self.cpuSubtype = cpuSubtype
        self.fileType = fileType
        self.ncmds = ncmds
        self.sizeofcmds = sizeofcmds
        self.flags = flags
        self.reserved = reserved
    }
}

@frozen
public struct LoadCommand: Sendable, Equatable {
    public var cmd: UInt32
    public var cmdsize: UInt32

    public init(cmd: UInt32 = 0, cmdsize: UInt32 = 0) {
        self.cmd = cmd
        self.cmdsize = cmdsize
    }
}

@frozen
public struct LinkeditDataCommand: Sendable, Equatable {
    public var cmd: UInt32
    public var cmdsize: UInt32
    public var dataoff: UInt32
    public var datasize: UInt32

    public init(
        cmd: UInt32 = 0,
        cmdsize: UInt32 = 0,
        dataoff: UInt32 = 0,
        datasize: UInt32 = 0
    ) {
        self.cmd = cmd
        self.cmdsize = cmdsize
        self.dataoff = dataoff
        self.datasize = datasize
    }
}

@frozen
public struct SuperBlobHeader: Sendable, Equatable {
    public var magic: UInt32
    public var length: UInt32
    public var count: UInt32

    public init(magic: UInt32 = 0, length: UInt32 = 0, count: UInt32 = 0) {
        self.magic = magic
        self.length = length
        self.count = count
    }
}

@frozen
public struct BlobIndex: Sendable, Equatable {
    public var type: UInt32
    public var offset: UInt32

    public init(type: UInt32 = 0, offset: UInt32 = 0) {
        self.type = type
        self.offset = offset
    }
}

public enum MachOConstants {
    public static let MH_MAGIC_64: UInt32 = 0xfeedfacf
    public static let LC_SEGMENT_64: UInt32 = 0x19
    public static let LC_CODE_SIGNATURE: UInt32 = 0x1d
    public static let CSMAGIC_CODEDIRECTORY: UInt32 = 0xfade0c02
    public static let CSMAGIC_EMBEDDED_SIGNATURE: UInt32 = 0xfade0cc0
    public static let CS_MAGIC_EMBEDDED_SIGNATURE: UInt32 = 0xfade0cc0
    public static let CSMAGIC_EMBEDDED_ENTITLEMENTS: UInt32 = 0xfade7171
    public static let CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: UInt32 = 0xfade7172
    public static let CSMAGIC_BLOBWRAPPER: UInt32 = 0xfade0b01

    public static let CSSLOT_CODEDIRECTORY: UInt32 = 0
    public static let CSSLOT_INFOPLIST: UInt32 = 1
    public static let CSSLOT_REQUIREMENTS: UInt32 = 2
    public static let CSSLOT_RESOURCEDIR: UInt32 = 3
    public static let CSSLOT_APPLICATION: UInt32 = 4
    public static let CSSLOT_ENTITLEMENTS: UInt32 = 5
    public static let CSSLOT_DER_ENTITLEMENTS: UInt32 = 7
    public static let CSSLOT_SIGNATURESLOT: UInt32 = 0x10000

    public static let CS_HASHTYPE_SHA1: UInt8 = 1
    public static let CS_HASHTYPE_SHA256: UInt8 = 2
}

public let CSMAGIC_BLOBWRAPPER: UInt32 = MachOConstants.CSMAGIC_BLOBWRAPPER
public let CS_HASHTYPE_SHA1: UInt8 = MachOConstants.CS_HASHTYPE_SHA1


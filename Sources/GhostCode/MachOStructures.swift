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

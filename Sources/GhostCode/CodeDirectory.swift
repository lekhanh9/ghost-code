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
        #if canImport(CryptoKit)
        return Data(CryptoKit.SHA256.hash(data: data))
        #else
        return NativeSHA256.hash(data)
        #endif
    }

    private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var be = value.bigEndian
        withUnsafeBytes(of: &be) { data.append(contentsOf: $0) }
    }
}

// MARK: - Native SHA-256 for non-Darwin environments (Zero-Dependency)

public enum NativeSHA256 {
    private static let K: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    public static func hash(_ data: Data) -> Data {
        var h0: UInt32 = 0x6a09e667
        var h1: UInt32 = 0xbb67ae85
        var h2: UInt32 = 0x3c6ef372
        var h3: UInt32 = 0xa54ff53a
        var h4: UInt32 = 0x510e527f
        var h5: UInt32 = 0x9b05688c
        var h6: UInt32 = 0x1f83d9ab
        var h7: UInt32 = 0x5be0cd19

        var message = data
        let bitLength = UInt64(data.count) * 8

        // Pad message: append 0x80, then 0x00 until count % 64 == 56
        message.append(0x80)
        while (message.count % 64) != 56 {
            message.append(0x00)
        }

        // Append 64-bit big-endian length
        var beLength = bitLength.bigEndian
        withUnsafeBytes(of: &beLength) { message.append(contentsOf: $0) }

        // Process each 64-byte chunk
        var w = [UInt32](repeating: 0, count: 64)
        for chunkStart in stride(from: 0, to: message.count, by: 64) {
            for i in 0..<16 {
                let offset = chunkStart + i * 4
                w[i] = message.withUnsafeBytes { raw in
                    UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
                }
            }

            for i in 16..<64 {
                let s0 = (w[i - 15] &>> 7 | w[i - 15] &<< 25) ^
                         (w[i - 15] &>> 18 | w[i - 15] &<< 14) ^
                         (w[i - 15] &>> 3)
                let s1 = (w[i - 2] &>> 17 | w[i - 2] &<< 15) ^
                         (w[i - 2] &>> 19 | w[i - 2] &<< 13) ^
                         (w[i - 2] &>> 10)
                w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4
            var f = h5
            var g = h6
            var h = h7

            for i in 0..<64 {
                let s1 = (e &>> 6 | e &<< 26) ^ (e &>> 11 | e &<< 21) ^ (e &>> 25 | e &<< 7)
                let ch = (e & f) ^ ((~e) & g)
                let temp1 = h &+ s1 &+ ch &+ K[i] &+ w[i]
                let s0 = (a &>> 2 | a &<< 30) ^ (a &>> 13 | a &<< 19) ^ (a &>> 22 | a &<< 10)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let temp2 = s0 &+ maj

                h = g
                g = f
                f = e
                e = d &+ temp1
                d = c
                c = b
                b = a
                a = temp1 &+ temp2
            }

            h0 = h0 &+ a
            h1 = h1 &+ b
            h2 = h2 &+ c
            h3 = h3 &+ d
            h4 = h4 &+ e
            h5 = h5 &+ f
            h6 = h6 &+ g
            h7 = h7 &+ h
        }

        var result = Data()
        let parts = [h0.bigEndian, h1.bigEndian, h2.bigEndian, h3.bigEndian, h4.bigEndian, h5.bigEndian, h6.bigEndian, h7.bigEndian]
        for var part in parts {
            withUnsafeBytes(of: &part) { result.append(contentsOf: $0) }
        }
        return result
    }
}

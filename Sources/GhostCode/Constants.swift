//
//  Constants.swift
//  GhostCode
//
//  Centralized constants for Mach-O binaries, Apple Code Signing (SuperBlob, CodeDirectory, CMS),
//  Bundle structures, and Cryptographic OIDs.
//

import Foundation

public enum GhostCodeConstants {

    // MARK: - Mach-O Binary Architecture & Load Commands

    public enum MachO {
        /// 64-bit Mach-O magic number (0xfeedfacf)
        public static let MH_MAGIC_64: UInt32 = 0xfeedfacf
        /// 64-bit reverse byte-order Mach-O magic (0xcffaedfe)
        public static let MH_CIGAM_64: UInt32 = 0xcffaedfe
        /// 32-bit Mach-O magic number (0xfeedface)
        public static let MH_MAGIC: UInt32 = 0xfeedface
        /// 32-bit reverse byte-order Mach-O magic (0xcefaedfe)
        public static let MH_CIGAM: UInt32 = 0xcefaedfe
        /// Fat/Universal binary magic (0xcafebabe)
        public static let FAT_MAGIC: UInt32 = 0xcafebabe
        /// Fat/Universal reverse byte-order magic (0xbebafeca)
        public static let FAT_CIGAM: UInt32 = 0xbebafeca
        /// Fat/Universal 64-bit magic (0xcafebabf)
        public static let FAT_MAGIC_64: UInt32 = 0xcafebabf
        /// Fat/Universal 64-bit reverse byte-order magic (0xbfbafeca)
        public static let FAT_CIGAM_64: UInt32 = 0xbfbafeca

        /// Load Command: 64-bit Segment (__PAGEZERO, __TEXT, __LINKEDIT, etc.)
        public static let LC_SEGMENT_64: UInt32 = 0x19
        /// Load Command: 32-bit Segment
        public static let LC_SEGMENT: UInt32 = 0x1
        /// Load Command: Embedded Code Signature
        public static let LC_CODE_SIGNATURE: UInt32 = 0x1d
        /// Load Command: Segment split info
        public static let LC_SEGMENT_SPLIT_INFO: UInt32 = 0x1e
        /// Load Command: Function starts
        public static let LC_FUNCTION_STARTS: UInt32 = 0x26
        /// Load Command: Data in code
        public static let LC_DATA_IN_CODE: UInt32 = 0x29
        /// Load Command: Code signature optimization / dyld info
        public static let LC_DYLD_INFO: UInt32 = 0x22
        public static let LC_DYLD_INFO_ONLY: UInt32 = (0x22 | 0x80000000)
    }

    // MARK: - Apple Code Signing Structures, Magic & Slots

    public enum CodeSigning {
        // SuperBlob and Component Magic Numbers
        public static let CSMAGIC_CODEDIRECTORY: UInt32 = 0xfade0c02
        public static let CSMAGIC_EMBEDDED_SIGNATURE: UInt32 = 0xfade0cc0
        public static let CS_MAGIC_EMBEDDED_SIGNATURE: UInt32 = 0xfade0cc0
        public static let CSMAGIC_REQUIREMENT: UInt32 = 0xfade0c00
        public static let CSMAGIC_REQUIREMENTS: UInt32 = 0xfade0c01
        public static let CSMAGIC_BLOBWRAPPER: UInt32 = 0xfade0b01
        public static let CSMAGIC_EMBEDDED_ENTITLEMENTS: UInt32 = 0xfade7171
        public static let CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: UInt32 = 0xfade7172

        // Special Slot Indices (Negative offsets in CodeDirectory)
        public static let CSSLOT_CODEDIRECTORY: UInt32 = 0
        public static let CSSLOT_INFOPLIST: UInt32 = 1
        public static let CSSLOT_REQUIREMENTS: UInt32 = 2
        public static let CSSLOT_RESOURCEDIR: UInt32 = 3
        public static let CSSLOT_APPLICATION: UInt32 = 4
        public static let CSSLOT_ENTITLEMENTS: UInt32 = 5
        public static let CSSLOT_DER_ENTITLEMENTS: UInt32 = 7
        public static let CSSLOT_SIGNATURESLOT: UInt32 = 0x10000

        // Hash Algorithms
        public static let CS_HASHTYPE_SHA1: UInt8 = 1
        public static let CS_HASHTYPE_SHA256: UInt8 = 2
        public static let CS_HASHTYPE_SHA256_TRUNCATED: UInt8 = 3
        public static let CS_HASHTYPE_SHA384: UInt8 = 4

        // Hash Output Lengths in Bytes
        public static let CS_HASHSIZE_SHA1: Int = 20
        public static let CS_HASHSIZE_SHA256: Int = 32
        public static let CS_HASHSIZE_SHA384: Int = 48

        // CodeDirectory Paging
        public static let CS_PAGE_SIZE: Int = 4096
        public static let CS_PAGE_SIZE_BITS: UInt8 = 12

        // CodeDirectory Feature Flags and Versions
        public static let CS_SUPPORTSSCATTER: UInt32 = 0x20100
        public static let CS_SUPPORTSTEAMID: UInt32 = 0x20200
        public static let CS_SUPPORTSEXECSEG: UInt32 = 0x20400
        public static let CS_EXECSEG_MAIN_BINARY: UInt64 = 0x1
    }

    // MARK: - Bundle Structure & Paths

    public enum Bundle {
        public static let codeSignatureDirectory = "_CodeSignature"
        public static let codeResourcesPath = "_CodeSignature/CodeResources"
        public static let embeddedProvisioningProfile = "embedded.mobileprovision"
        public static let infoPlist = "Info.plist"
        public static let pkgInfo = "PkgInfo"
    }

    // MARK: - Cryptographic Object Identifiers (OIDs)

    public enum OIDs {
        /// PKCS#7 Data: 1.2.840.113549.1.7.1
        public static let contentTypeData = "1.2.840.113549.1.7.1"
        /// PKCS#7 SignedData: 1.2.840.113549.1.7.2
        public static let contentTypeSignedData = "1.2.840.113549.1.7.2"
        /// RSA Encryption: 1.2.840.113549.1.1.1
        public static let rsaEncryption = "1.2.840.113549.1.1.1"
        /// SHA-256 with RSA Encryption: 1.2.840.113549.1.1.11
        public static let sha256WithRSAEncryption = "1.2.840.113549.1.1.11"
        /// SHA-1 with RSA Encryption: 1.2.840.113549.1.1.5
        public static let sha1WithRSAEncryption = "1.2.840.113549.1.1.5"
        /// Apple Code Signing Extended Key Usage: 1.2.840.113635.100.6.1.13
        public static let appleCodeSigningEKU = "1.2.840.113635.100.6.1.13"
    }
}

/// Global alias for convenient access to GhostCode constants.
public typealias Constants = GhostCodeConstants

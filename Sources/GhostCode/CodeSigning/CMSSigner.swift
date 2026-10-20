import Foundation

#if canImport(Security)
import Security
#endif

public enum CMSSignerError: Swift.Error, Equatable {
    case creationFailed(Int32)
    case configurationFailed(Int32)
    case signingFailed(Int32)
    case unsupportedPlatform
}

#if !canImport(Security)
public final class SecCertificate: @unchecked Sendable {
    public let data: Data
    public init(data: Data = Data()) { self.data = data }
}

public final class SecKey: @unchecked Sendable {
    public let keyData: Data
    public init(keyData: Data = Data()) { self.keyData = keyData }
}
#endif

public enum CMSSigner {
    public static func signCodeDirectory(codeDirectoryData: Data, cert: SecCertificate, key: SecKey) throws -> Data {
        #if canImport(Security) && os(macOS)
        var encoder: CMSEncoder?
        var status = CMSEncoderCreate(&encoder)
        guard status == errSecSuccess, let encoder else {
            throw CMSSignerError.creationFailed(status)
        }

        status = CMSEncoderSetHasDetachedContent(encoder, true)
        guard status == errSecSuccess else { throw CMSSignerError.configurationFailed(status) }

        status = codeDirectoryData.withUnsafeBytes { raw in
            CMSEncoderUpdateContent(encoder, raw.baseAddress!, codeDirectoryData.count)
        }
        guard status == errSecSuccess else { throw CMSSignerError.configurationFailed(status) }

        // Set certificate and key
        status = CMSEncoderAddSigners(encoder, cert)
        guard status == errSecSuccess else { throw CMSSignerError.configurationFailed(status) }

        var signatureData: CFData?
        status = CMSEncoderCopyEncodedData(encoder, &signatureData)
        guard status == errSecSuccess, let cfData = signatureData else {
            throw CMSSignerError.signingFailed(status)
        }
        return cfData as Data
        #else
        // Mock detached CMS signature for Linux / cross-platform test environments
        return mockDetachedCMS(for: codeDirectoryData)
        #endif
    }

    public static func mockDetachedCMS(for data: Data) -> Data {
        let hash = CryptoHelpers.sha256(data)
        var mock = Data("CMS_DETACHED_SIGNATURE".utf8)
        mock.append(hash)
        return mock
    }
}

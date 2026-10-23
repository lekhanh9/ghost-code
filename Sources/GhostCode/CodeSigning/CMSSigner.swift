import Foundation

#if canImport(Security)
import Security
#endif

public enum CMSSignerError: Swift.Error, Equatable {
    case missingCertificate
    case signingFailed(String)
    case keyLoadingFailed(String)
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

/// The private-key half of the code signature. The CMS itself is assembled by `PKCS7Builder`;
/// this only produces the signature over the authenticated attributes, so the DER work stays
/// testable without a key.
public enum CMSSigner {
    public static func certificateDER(from certificate: SecCertificate) -> Data {
        #if canImport(Security)
        SecCertificateCopyData(certificate) as Data
        #else
        certificate.data
        #endif
    }

    /// Signs with an in-memory `SecKey`. Both algorithms hash the input themselves, so they are
    /// handed the raw authenticated attributes.
    public static func contentSigner(key: SecKey, usesRSA: Bool) -> PKCS7ContentSigner {
        #if canImport(Security)
        return { attributes in
            let algorithm: SecKeyAlgorithm = usesRSA
                ? .rsaSignatureMessagePKCS1v15SHA256
                : .ecdsaSignatureMessageX962SHA256
            var secError: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(key, algorithm, attributes as CFData, &secError) else {
                let description = (secError?.takeRetainedValue() as Error?)?.localizedDescription ?? "unknown SecKey failure"
                throw CMSSignerError.signingFailed(description)
            }
            return signature as Data
        }
        #else
        _ = key
        _ = usesRSA
        return { _ in throw CMSSignerError.unsupportedPlatform }
        #endif
    }

    #if canImport(Security)
    /// Wraps a DER private key in a `SecKey` without involving the Keychain.
    public static func secKey(fromPrivateKeyDER privateKeyDER: Data, usesRSA: Bool) throws -> SecKey {
        let attributes: [String: Any] = [
            (kSecAttrKeyType as String): usesRSA ? (kSecAttrKeyTypeRSA as String) : (kSecAttrKeyTypeECSECPrimeRandom as String),
            (kSecAttrKeyClass as String): (kSecAttrKeyClassPrivate as String)
        ]
        var secError: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(privateKeyDER as CFData, attributes as CFDictionary, &secError) else {
            let description = (secError?.takeRetainedValue() as Error?)?.localizedDescription ?? "unknown SecKey failure"
            throw CMSSignerError.keyLoadingFailed(description)
        }
        return key
    }
    #endif
}

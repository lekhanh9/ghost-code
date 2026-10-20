import Foundation

#if canImport(Security) && os(macOS)
import Security
#endif

/// Zero-dependency parser and converter for PEM and DER encoded certificates and private keys.
public enum PEMHelper {

    /// Extracts all DER-encoded Data blocks matching an optional tag (e.g. "CERTIFICATE", "PRIVATE KEY") from a PEM string.
    public static func decode(pemString: String, tag: String? = nil) -> [Data] {
        var results: [Data] = []
        let lines = pemString.components(separatedBy: .newlines)
        var currentBase64 = ""
        var inBlock = false

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("-----BEGIN ") && trimmed.hasSuffix("-----") {
                if let tag = tag {
                    if trimmed.uppercased().contains(tag.uppercased()) {
                        inBlock = true
                        currentBase64 = ""
                    }
                } else {
                    inBlock = true
                    currentBase64 = ""
                }
            } else if trimmed.hasPrefix("-----END ") && trimmed.hasSuffix("-----") {
                if inBlock {
                    if let data = Data(base64Encoded: currentBase64, options: .ignoreUnknownCharacters) {
                        results.append(data)
                    }
                    currentBase64 = ""
                    inBlock = false
                }
            } else if inBlock {
                currentBase64.append(trimmed)
            }
        }
        return results
    }

    /// Extracts the first matching DER-encoded Data block from PEM or DER data.
    public static func decodeFirst(from data: Data, tag: String? = nil) -> Data? {
        if let string = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1),
           string.contains("-----BEGIN ") {
            return decode(pemString: string, tag: tag).first
        }
        // If not PEM formatted, assume already DER
        return data
    }

    /// Loads a SecCertificate from either PEM text or raw DER data.
    public static func loadCertificate(from data: Data) -> SecCertificate? {
        guard let der = decodeFirst(from: data, tag: "CERTIFICATE") else {
            return nil
        }
        #if canImport(Security) && os(macOS)
        if let cert = SecCertificateCreateWithData(nil, der as CFData) {
            return cert
        }
        return nil
        #else
        return SecCertificate(data: der)
        #endif
    }

    /// Loads a SecKey private key from either PEM text (PKCS#1 / PKCS#8) or raw DER data.
    public static func loadPrivateKey(from data: Data) -> SecKey? {
        guard let der = decodeFirst(from: data, tag: "KEY") else {
            return nil
        }
        #if canImport(Security) && os(macOS)
        let keyDict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]
        var error: Unmanaged<CFError>?
        if let key = SecKeyCreateWithData(der as CFData, keyDict as CFDictionary, &error) {
            return key
        }
        return nil
        #else
        return SecKey(keyData: der)
        #endif
    }
}

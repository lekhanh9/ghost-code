import Foundation

public enum DEREncoderError: Swift.Error, Equatable {
    case unsupportedType(String)
}

/// Apple's DER representation of an entitlements dictionary. It is not a plain `SEQUENCE`: the
/// payload is an application tag wrapping an explicit version number and a context tag holding the
/// sorted key/value pairs, and the whole thing sits behind the `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS`
/// blob header (see `CodeSigningSlot.derEntitlements`).
public enum DEREncoder {
    /// The bytes that follow the code-signing blob header: `0x70 <len> <version> <0xB0 <entries>>`.
    public static func encode(entitlements: [String: Any]) throws -> Data {
        var payload = DER.integer(1)
        payload.append(try encodeDictionary(entitlements))
        return DER.element(tag: 0x70, content: payload)
    }

    public static func encodeValue(_ value: Any) throws -> Data {
        switch value {
        case let boolVal as Bool:
            return DER.boolean(boolVal)
        case let stringVal as String:
            return DER.element(tag: DER.tagUTF8String, content: Data(stringVal.utf8))
        case let dictVal as [String: Any]:
            return try encodeDictionary(dictVal, tag: 0xB0)
        case let arrayVal as [Any]:
            var content = Data()
            for element in arrayVal {
                content.append(try encodeValue(element))
            }
            return DER.sequence(content)
        case let intVal as Int:
            return DER.integer(intVal)
        case let dataVal as Data:
            return DER.octetString(dataVal)
        default:
            throw DEREncoderError.unsupportedType(String(describing: type(of: value)))
        }
    }

    private static func encodeDictionary(_ dictionary: [String: Any], tag: UInt8 = 0xB0) throws -> Data {
        var content = Data()
        for key in dictionary.keys.sorted() {
            guard let value = dictionary[key] else { continue }
            var entry = DER.element(tag: DER.tagUTF8String, content: Data(key.utf8))
            entry.append(try encodeValue(value))
            content.append(DER.element(tag: DER.tagSequence, content: entry))
        }
        return DER.element(tag: tag, content: content)
    }
}

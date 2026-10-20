import Foundation

public enum DEREncoderError: Swift.Error, Equatable {
    case unsupportedType(String)
}

public enum DEREncoder {
    public static func encode(entitlements: [String: Any]) throws -> Data {
        try encodeDictionary(entitlements)
    }

    public static func encodeValue(_ value: Any) throws -> Data {
        switch value {
        case let boolVal as Bool:
            return encodeBoolean(boolVal)
        case let stringVal as String:
            return encodeString(stringVal)
        case let dictVal as [String: Any]:
            return try encodeDictionary(dictVal)
        case let arrayVal as [Any]:
            return try encodeArray(arrayVal)
        case let intVal as Int:
            return encodeInteger(intVal)
        case let dataVal as Data:
            return encodeOctetString(dataVal)
        default:
            throw DEREncoderError.unsupportedType(String(describing: type(of: value)))
        }
    }

    public static func encodeBoolean(_ value: Bool) -> Data {
        // Tag 0x01: true -> 0x01 0x01 0xFF, false -> 0x01 0x01 0x00
        Data([0x01, 0x01, value ? 0xFF : 0x00])
    }

    public static func encodeString(_ value: String) -> Data {
        // Tag 0x0C: UTF8String
        let utf8 = Data(value.utf8)
        var result = Data([0x0C])
        result.append(encodeLength(utf8.count))
        result.append(utf8)
        return result
    }

    public static func encodeDictionary(_ dict: [String: Any]) throws -> Data {
        // Tag 0x30: Sequence of key-value pairs (each pair is also Sequence 0x30)
        var content = Data()
        for key in dict.keys.sorted() {
            guard let val = dict[key] else { continue }
            let keyBytes = encodeString(key)
            let valBytes = try encodeValue(val)
            
            var pairContent = Data()
            pairContent.append(keyBytes)
            pairContent.append(valBytes)
            
            var pair = Data([0x30])
            pair.append(encodeLength(pairContent.count))
            pair.append(pairContent)
            
            content.append(pair)
        }

        var sequence = Data([0x30])
        sequence.append(encodeLength(content.count))
        sequence.append(content)
        return sequence
    }

    public static func encodeArray(_ array: [Any]) throws -> Data {
        // Tag 0x31: Set/Array
        var content = Data()
        for element in array {
            let elemBytes = try encodeValue(element)
            content.append(elemBytes)
        }

        var setSequence = Data([0x31])
        setSequence.append(encodeLength(content.count))
        setSequence.append(content)
        return setSequence
    }

    public static func encodeInteger(_ value: Int) -> Data {
        // Tag 0x02: INTEGER
        var val = value
        var bytes = [UInt8]()
        if val == 0 {
            bytes = [0x00]
        } else {
            let isNegative = val < 0
            while val != 0 && val != -1 {
                bytes.insert(UInt8(truncatingIfNeeded: val), at: 0)
                val >>= 8
            }
            if !isNegative && (bytes.first! & 0x80) != 0 {
                bytes.insert(0x00, at: 0)
            } else if isNegative && (bytes.first! & 0x80) == 0 {
                bytes.insert(0xFF, at: 0)
            }
        }

        var result = Data([0x02])
        result.append(encodeLength(bytes.count))
        result.append(contentsOf: bytes)
        return result
    }

    public static func encodeOctetString(_ data: Data) -> Data {
        // Tag 0x04: OCTET STRING
        var result = Data([0x04])
        result.append(encodeLength(data.count))
        result.append(data)
        return result
    }

    public static func encodeLength(_ length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        } else if length <= 0xFF {
            return Data([0x81, UInt8(length)])
        } else if length <= 0xFFFF {
            return Data([0x82, UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
        } else if length <= 0xFFFFFF {
            return Data([
                0x83,
                UInt8((length >> 16) & 0xFF),
                UInt8((length >> 8) & 0xFF),
                UInt8(length & 0xFF)
            ])
        } else {
            return Data([
                0x84,
                UInt8((length >> 24) & 0xFF),
                UInt8((length >> 16) & 0xFF),
                UInt8((length >> 8) & 0xFF),
                UInt8(length & 0xFF)
            ])
        }
    }
}

public func encode(entitlements: [String: Any]) throws -> Data {
    try DEREncoder.encode(entitlements: entitlements)
}

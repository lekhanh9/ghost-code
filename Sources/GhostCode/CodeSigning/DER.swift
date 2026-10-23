import Foundation

public enum DERError: Swift.Error, Equatable {
    case truncated
    case invalidLength
    case unexpectedTag(expected: UInt8, actual: UInt8)
    case malformedCertificate(String)
}

/// A decoded DER element that keeps the exact bytes it was parsed from, so certificate fields
/// (issuer name, serial number) can be re-embedded in CMS without re-encoding them.
public struct DERTLV: Sendable, Equatable {
    public let tag: UInt8
    public let content: Data
    public let encoded: Data

    public var isConstructed: Bool { tag & 0x20 != 0 }
    public var tagNumber: Int { Int(tag & 0x1F) }

    /// Decoded children, empty when this element is primitive or its content is not valid DER.
    public var children: [DERTLV] { (try? DERTLV.parseAll(content)) ?? [] }

    public init(tag: UInt8, content: Data, encoded: Data) {
        self.tag = tag
        self.content = content
        self.encoded = encoded
    }

    public static func parseAll(_ data: Data) throws -> [DERTLV] {
        let bytes = [UInt8](data)
        var result: [DERTLV] = []
        var index = 0
        while index < bytes.count {
            let (element, next) = try parse(bytes, at: index)
            result.append(element)
            index = next
        }
        return result
    }

    /// Parses the single element that consumes all of `data`, rejecting trailing garbage.
    public static func parseSingle(_ data: Data) throws -> DERTLV {
        let elements = try parseAll(data)
        guard elements.count == 1 else {
            throw DERError.malformedCertificate("expected one DER element, found \(elements.count)")
        }
        return elements[0]
    }

    public func requiring(tag expectedTag: UInt8) throws -> DERTLV {
        guard tag == expectedTag else {
            throw DERError.unexpectedTag(expected: expectedTag, actual: tag)
        }
        return self
    }

    /// Value bytes of an OBJECT IDENTIFIER child, or nil when absent.
    public var objectIdentifierValue: [UInt8]? {
        children.first { $0.tag == DER.tagOID }?.content.map { $0 }
    }

    private static func parse(_ bytes: [UInt8], at start: Int) throws -> (DERTLV, Int) {
        guard start < bytes.count else { throw DERError.truncated }
        let tag = bytes[start]
        var index = start + 1
        guard index < bytes.count else { throw DERError.truncated }

        let firstLengthByte = bytes[index]
        index += 1
        let length: Int
        if firstLengthByte < 0x80 {
            length = Int(firstLengthByte)
        } else {
            let lengthBytes = Int(firstLengthByte & 0x7F)
            guard lengthBytes > 0, lengthBytes <= 4, index + lengthBytes <= bytes.count else {
                throw DERError.invalidLength
            }
            var accumulated = 0
            for _ in 0..<lengthBytes {
                accumulated = (accumulated << 8) | Int(bytes[index])
                index += 1
            }
            length = accumulated
        }

        guard index + length <= bytes.count else { throw DERError.truncated }
        let end = index + length
        return (
            DERTLV(
                tag: tag,
                content: Data(bytes[index..<end]),
                encoded: Data(bytes[start..<end])
            ),
            end
        )
    }
}

/// Minimal DER writing primitives: canonical, definite-length only.
public enum DER {
    public static let tagBoolean: UInt8 = 0x01
    public static let tagInteger: UInt8 = 0x02
    public static let tagBitString: UInt8 = 0x03
    public static let tagOctetString: UInt8 = 0x04
    public static let tagOID: UInt8 = 0x06
    public static let tagUTF8String: UInt8 = 0x0C
    public static let tagSequence: UInt8 = 0x30
    public static let tagSet: UInt8 = 0x31
    public static let tagUTCTime: UInt8 = 0x17

    public static func element(tag: UInt8, content: Data) -> Data {
        var result = Data([tag])
        result.append(length(content.count))
        result.append(content)
        return result
    }

    public static func sequence(_ content: Data) -> Data {
        element(tag: tagSequence, content: content)
    }

    public static func set(_ content: Data) -> Data {
        element(tag: tagSet, content: content)
    }

    public static func octetString(_ content: Data) -> Data {
        element(tag: tagOctetString, content: content)
    }

    public static func integer(_ value: Int) -> Data {
        element(tag: tagInteger, content: integerContent(value))
    }

    public static func utcTime(_ content: Data) -> Data {
        element(tag: tagUTCTime, content: content)
    }

    public static func boolean(_ value: Bool) -> Data {
        element(tag: tagBoolean, content: Data([value ? 0xFF : 0x00]))
    }

    /// Implicit constructed context tag, valid for tag numbers below 31.
    public static func contextConstructed(_ number: Int, _ content: Data) -> Data {
        element(tag: 0xA0 | UInt8(number), content: content)
    }

    public static func objectIdentifier(_ dotted: String) -> Data {
        element(tag: tagOID, content: objectIdentifierContent(dotted))
    }

    public static func objectIdentifierContent(_ dotted: String) -> Data {
        let components = dotted.split(separator: ".").compactMap { UInt64($0) }
        guard components.count >= 2 else { return Data() }

        var content = [UInt8]()
        content.append(UInt8(components[0] * 40 + components[1]))
        for component in components.dropFirst(2) {
            var stack: [UInt8] = []
            var remaining = component
            stack.append(UInt8(remaining & 0x7F))
            remaining >>= 7
            while remaining > 0 {
                stack.append(UInt8(remaining & 0x7F) | 0x80)
                remaining >>= 7
            }
            content.append(contentsOf: stack.reversed())
        }
        return Data(content)
    }

    /// Dotted form of a decoded OBJECT IDENTIFIER value, or nil when it is not well formed.
    public static func objectIdentifierValue(_ content: Data) -> String? {
        let bytes = [UInt8](content)
        guard let first = bytes.first else { return nil }
        var components: [UInt64] = [UInt64(first / 40), UInt64(first % 40)]
        var accumulator: UInt64 = 0
        var started = false
        for byte in bytes.dropFirst() {
            accumulator = (accumulator << 7) | UInt64(byte & 0x7F)
            started = true
            if byte & 0x80 == 0 {
                components.append(accumulator)
                accumulator = 0
                started = false
            }
        }
        guard !started else { return nil }
        return components.map { String($0) }.joined(separator: ".")
    }

    public static func integerContent(_ value: Int) -> Data {
        if value == 0 { return Data([0x00]) }
        var magnitude = value
        var bytes = [UInt8]()
        let isNegative = magnitude < 0
        while magnitude != 0 && magnitude != -1 {
            bytes.insert(UInt8(truncatingIfNeeded: magnitude), at: 0)
            magnitude >>= 8
        }
        if bytes.isEmpty { bytes = isNegative ? [0xFF] : [0x00] }
        if !isNegative, let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0x00, at: 0)
        } else if isNegative, let first = bytes.first, first & 0x80 == 0 {
            bytes.insert(0xFF, at: 0)
        }
        return Data(bytes)
    }

    public static func length(_ value: Int) -> Data {
        if value < 0x80 {
            return Data([UInt8(value)])
        }
        var bytes = [UInt8]()
        var remaining = value
        while remaining > 0 {
            bytes.insert(UInt8(truncatingIfNeeded: remaining), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}

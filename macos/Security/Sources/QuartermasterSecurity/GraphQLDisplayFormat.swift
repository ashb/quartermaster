import Foundation

enum GraphQLDisplayFormat {
    static func readable(_ source: String) -> String? {
        format(source)?.text
    }

    static func operationSummary(_ source: String, operationName: String?) -> String? {
        guard let formatted = format(source) else { return nil }
        var operations: [(kind: String, name: String?)] = []
        for header in formatted.headers {
            if header.first == "fragment" { continue }
            let kind = header.first ?? "query"
            guard ["query", "mutation", "subscription"].contains(kind) else { return nil }
            let name = header.dropFirst().first.flatMap { token -> String? in
                guard let first = token.utf8.first,
                    [65...90, 97...122].contains(where: { $0.contains(Int(first)) }) || first == 95,
                    token.utf8.allSatisfy(nameByte)
                else { return nil }
                return token
            }
            operations.append((kind, name))
        }
        let selected = operationName.map { name in operations.filter { $0.name == name } } ?? operations
        guard selected.count == 1, let operation = selected.first else { return nil }
        return [operation.kind, operation.name].compactMap { $0 }.joined(separator: " ")
    }

    private static func format(_ source: String) -> (text: String, headers: [[String]])? {
        guard source.utf8.count <= BrokerLimits.reviewBytes else { return nil }
        let bytes = Array(source.utf8)
        var output = Output()
        var closing: [UInt8] = []
        var hasBraces = false
        var headers: [[String]] = []
        var header: [String] = []
        var index = 0
        while index < bytes.count {
            let start = index
            let byte = bytes[index]
            index += 1
            switch byte {
            case 9, 10, 13, 32:
                output.spacePending = true
            case 35:
                while index < bytes.count && bytes[index] != 10 && bytes[index] != 13 { index += 1 }
                guard output.write(bytes[start..<index]), output.newline() else { return nil }
            case 34:
                guard let end = stringEnd(bytes, from: start), output.write(bytes[start..<end]) else { return nil }
                if closing.isEmpty && header.count < 2 { header.append("\"") }
                index = end
            case 123, 40, 91:
                if closing.isEmpty {
                    if byte == 123 {
                        headers.append(header)
                        header = []
                    } else if header.count < 2 {
                        header.append(String(UnicodeScalar(byte)))
                    }
                }
                guard closing.count < 64 else { return nil }
                closing.append(byte == 123 ? 125 : byte == 40 ? 41 : 93)
                if byte == 123 {
                    hasBraces = true
                    output.spacePending = !output.bytes.isEmpty
                }
                guard output.write(bytes[start..<index]) else { return nil }
                if byte == 123 {
                    output.depth += 1
                    guard output.newline() else { return nil }
                }
            case 125, 41, 93:
                guard closing.popLast() == byte else { return nil }
                if byte == 125 {
                    output.depth -= 1
                    guard output.newline() else { return nil }
                }
                guard output.write(bytes[start..<index]) else { return nil }
            case 46:
                guard start + 3 <= bytes.count, bytes[start..<start + 3].allSatisfy({ $0 == 46 }),
                    output.write(bytes[start..<start + 3])
                else { return nil }
                index = start + 3
            case 45, 48...57:
                guard let end = numberEnd(bytes, from: start), output.write(bytes[start..<end]) else { return nil }
                if closing.isEmpty && header.count < 2 {
                    header.append(String(decoding: bytes[start..<end], as: UTF8.self))
                }
                index = end
            case 65...90, 95, 97...122:
                while index < bytes.count && nameByte(bytes[index]) { index += 1 }
                if closing.isEmpty && header.count < 2 {
                    header.append(String(decoding: bytes[start..<index], as: UTF8.self))
                }
                guard output.write(bytes[start..<index]) else { return nil }
            case 33, 36, 38, 44, 58, 61, 64, 124:
                if closing.isEmpty && byte != 44 && header.count < 2 { header.append(String(UnicodeScalar(byte))) }
                guard output.write(bytes[start..<index]) else { return nil }
            default: return nil
            }
        }
        guard closing.isEmpty, hasBraces else { return nil }
        if output.bytes.last == 10 { output.bytes.removeLast() }
        return (String(decoding: output.bytes, as: UTF8.self), headers)
    }

    private static func nameByte(_ byte: UInt8) -> Bool {
        switch byte {
        case 48...57, 65...90, 95, 97...122: true
        default: false
        }
    }

    private static func numberEnd(_ bytes: [UInt8], from start: Int) -> Int? {
        var index = start
        if bytes[index] == 45 { index += 1 }
        guard index < bytes.count, (48...57).contains(bytes[index]) else { return nil }
        if bytes[index] == 48 {
            index += 1
        } else {
            while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
        }
        if index < bytes.count && bytes[index] == 46 {
            index += 1
            let digits = index
            while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
            guard index > digits else { return nil }
        }
        if index < bytes.count && (bytes[index] == 69 || bytes[index] == 101) {
            index += 1
            if index < bytes.count && (bytes[index] == 43 || bytes[index] == 45) { index += 1 }
            let digits = index
            while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
            guard index > digits else { return nil }
        }
        guard index == bytes.count || (!nameByte(bytes[index]) && bytes[index] != 46) else { return nil }
        return index
    }

    private static func stringEnd(_ bytes: [UInt8], from start: Int) -> Int? {
        let block = start + 3 <= bytes.count && bytes[start..<start + 3].allSatisfy { $0 == 34 }
        var index = start + (block ? 3 : 1)
        while index < bytes.count {
            if block {
                if index + 4 <= bytes.count && bytes[index] == 92
                    && bytes[index + 1..<index + 4].allSatisfy({ $0 == 34 })
                {
                    index += 4
                } else if index + 3 <= bytes.count && bytes[index..<index + 3].allSatisfy({ $0 == 34 }) {
                    return index + 3
                } else {
                    index += 1
                }
            } else if bytes[index] == 92 {
                index += 2
            } else if bytes[index] == 34 {
                let end = index + 1
                guard (try? JSONDecoder().decode(String.self, from: Data(bytes[start..<end]))) != nil else {
                    return nil
                }
                return end
            } else {
                index += 1
            }
        }
        return nil
    }

    private struct Output {
        var bytes: [UInt8] = []
        var depth = 0
        var spacePending = false
        private var atLineStart = true

        mutating func write(_ token: ArraySlice<UInt8>) -> Bool {
            let spaces = atLineStart ? depth * 2 : spacePending ? 1 : 0
            guard bytes.count + spaces + token.count <= BrokerLimits.reviewBytes else { return false }
            bytes.append(contentsOf: repeatElement(32, count: spaces))
            bytes.append(contentsOf: token)
            atLineStart = token.last == 10
            spacePending = false
            return true
        }

        mutating func newline() -> Bool {
            if bytes.last != 10 {
                guard bytes.count < BrokerLimits.reviewBytes else { return false }
                bytes.append(10)
            }
            atLineStart = true
            spacePending = false
            return true
        }
    }
}

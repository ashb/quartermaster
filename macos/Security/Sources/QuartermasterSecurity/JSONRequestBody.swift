import Foundation

enum JSONRequestBody {
    private enum Token {
        case mark(UInt8)
        case string(raw: String, decoded: String)
        case atom(String)

        var mark: UInt8? {
            if case .mark(let byte) = self { return byte }
            return nil
        }

        var raw: String {
            switch self {
            case .mark(let byte): String(UnicodeScalar(byte))
            case .string(let raw, _), .atom(let raw): raw
            }
        }
    }

    private struct Container {
        let closing: UInt8
        var keys: Set<String> = []
    }

    static func readable(_ data: Data) -> String? {
        guard String(data: data, encoding: .utf8) != nil, let tokens = tokenize(data),
            (try? JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed)) != nil
        else { return nil }
        guard tokens.first?.mark == 123, tokens.count > 2 else { return pretty(tokens[...]) }
        var fields: [String] = []
        var index = 1
        while index < tokens.count - 1 {
            guard case .string(let key, let name) = tokens[index],
                index + 2 < tokens.count,
                let end = valueEnd(tokens, from: index + 2)
            else { return nil }
            let value = tokens[(index + 2)..<end]
            let text: String
            let label: String
            if name == "query", value.count == 1,
                case .string(_, let query) = value.first, !query.isEmpty
            {
                label = "\(key) (decoded string)"
                text = query
            } else {
                guard let formatted = pretty(value) else { return nil }
                label = key
                text = formatted
            }
            fields.append("\(label):\n" + text.components(separatedBy: "\n").map { "  " + $0 }.joined(separator: "\n"))
            index = end + 1
        }
        let text = fields.joined(separator: "\n\n")
        return text.utf8.count <= BrokerLimits.reviewBytes ? text : nil
    }

    private static func valueEnd(_ tokens: [Token], from start: Int) -> Int? {
        guard tokens[start].mark == 123 || tokens[start].mark == 91 else { return start + 1 }
        var depth = 0
        for index in start..<tokens.count {
            switch tokens[index].mark {
            case 123, 91: depth += 1
            case 125, 93:
                depth -= 1
                if depth == 0 { return index + 1 }
            default: break
            }
        }
        return nil
    }

    private static func tokenize(_ data: Data) -> [Token]? {
        let bytes = Array(data)
        let decoder = JSONDecoder()
        var tokens: [Token] = []
        var containers: [Container] = []
        var index = 0
        while index < bytes.count {
            let start = index
            let byte = bytes[index]
            index += 1
            switch byte {
            case 9, 10, 13, 32: continue
            case 123, 91:
                guard containers.count < 64 else { return nil }
                containers.append(Container(closing: byte == 123 ? 125 : 93))
                tokens.append(.mark(byte))
            case 125, 93:
                guard containers.popLast()?.closing == byte else { return nil }
                tokens.append(.mark(byte))
            case 44, 58: tokens.append(.mark(byte))
            case 34:
                var escaped = false
                while index < bytes.count {
                    let next = bytes[index]
                    index += 1
                    if !escaped && next == 34 { break }
                    if !escaped && next == 92 { escaped = true } else { escaped = false }
                }
                let raw = Data(bytes[start..<index])
                guard let decoded = try? decoder.decode(String.self, from: raw) else { return nil }
                var following = index
                while following < bytes.count && [9, 10, 13, 32].contains(bytes[following]) { following += 1 }
                if following < bytes.count && bytes[following] == 58 {
                    guard let container = containers.indices.last,
                        containers[container].closing == 125,
                        containers[container].keys.insert(decoded).inserted
                    else { return nil }
                }
                tokens.append(.string(raw: String(decoding: raw, as: UTF8.self), decoded: decoded))
            default:
                while index < bytes.count && ![9, 10, 13, 32, 44, 58, 91, 93, 123, 125, 34].contains(bytes[index]) {
                    index += 1
                }
                tokens.append(.atom(String(decoding: bytes[start..<index], as: UTF8.self)))
            }
        }
        return containers.isEmpty && !tokens.isEmpty ? tokens : nil
    }

    private static func pretty(_ tokens: ArraySlice<Token>) -> String? {
        var output = ""
        var depth = 0
        var previous: UInt8?
        for index in tokens.indices {
            let token = tokens[index]
            switch token.mark {
            case 123, 91:
                output += token.raw
                depth += 1
                let next = tokens.index(after: index)
                if next < tokens.endIndex && ![125, 93].contains(tokens[next].mark) {
                    output += "\n" + String(repeating: "  ", count: depth)
                }
            case 125, 93:
                depth -= 1
                if previous != 123 && previous != 91 {
                    output += "\n" + String(repeating: "  ", count: depth)
                }
                output += token.raw
            case 44: output += ",\n" + String(repeating: "  ", count: depth)
            case 58: output += ": "
            default: output += token.raw
            }
            guard output.utf8.count <= BrokerLimits.reviewBytes else { return nil }
            previous = token.mark
        }
        return output
    }
}

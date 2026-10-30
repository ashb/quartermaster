import Foundation

public struct APIRequestReview: Sendable {
    public let text: String
    public let readableText: String?

    private struct Envelope: Decodable {
        struct Capture: Decodable { let request: Data }
        let application: Capture?
    }

    public static func parse(request: Data) throws -> Self? {
        guard let capture = try JSONDecoder().decode(Envelope.self, from: request).application else { return nil }
        return Self(text: escaped(capture.request), readableText: readable(capture.request))
    }

    private static func readable(_ data: Data) -> String? {
        guard let boundary = data.range(of: Data("\r\n\r\n".utf8)),
            let head = String(data: data[..<boundary.lowerBound], encoding: .utf8)
        else { return nil }
        let types = head.components(separatedBy: "\r\n").dropFirst().compactMap { line -> String? in
            let field = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard field.count == 2, field[0].lowercased() == "content-type" else { return nil }
            return field[1].prefix { $0 != ";" }.trimmingCharacters(in: .whitespaces).lowercased()
        }
        guard types.count == 1, types[0] == "application/json" || types[0].hasSuffix("+json"),
            let body = JSONRequestBody.readable(Data(data[boundary.upperBound...]))
        else { return nil }
        let text = escaped(Data(data[..<boundary.lowerBound])) + "\n\n" + escaped(Data(body.utf8), tabs: true)
        return text.utf8.count <= BrokerLimits.reviewBytes ? text : nil
    }

    private static func escaped(_ data: Data, tabs: Bool = false) -> String {
        let hex = Array("0123456789abcdef".utf8)
        var bytes: [UInt8] = []
        bytes.reserveCapacity(data.count)
        for index in data.indices {
            let byte = data[index]
            switch byte {
            case 32...126:
                if byte == 92 { bytes.append(92) }
                bytes.append(byte)
            case 10: bytes.append(10)
            case 9 where tabs: bytes.append(9)
            case 13:
                let next = data.index(after: index)
                if next == data.endIndex || data[next] != 10 { bytes.append(contentsOf: [92, 114]) }
            default: bytes.append(contentsOf: [92, 120, hex[Int(byte >> 4)], hex[Int(byte & 15)]])
            }
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}

import Foundation

public struct APIRequestReview: Sendable {
    public enum Failure: Error { case invalidRequest }
    public let complete: Bool
    public let effects: [String]
    public let text: String
    public let requestedRepository: String?

    private struct Envelope: Decodable {
        let method: String
        let path: String
        let origin: String
        let application: Capture?
    }

    private struct Capture: Decodable {
        let version: String
        let request: Data
        let originalDigest: Data
        let complete: Bool
        let effects: [String]
        let requestedRepository: String?
    }

    public static func parse(request: Data) throws -> Self? {
        guard request.count <= BrokerLimits.reviewBytes,
            let envelope = try? JSONDecoder().decode(Envelope.self, from: request)
        else { throw Failure.invalidRequest }
        guard let capture = envelope.application else { return nil }
        guard envelope.origin == "https://api.github.com",
            capture.version == "quartermaster.github-request.v1",
            capture.originalDigest.count == 32,
            capture.request.count <= 262_400,
            !envelope.method.isEmpty, envelope.method.utf8.allSatisfy({ (33...126).contains($0) }),
            envelope.path.hasPrefix("/"), envelope.path.utf8.allSatisfy({ (33...126).contains($0) }),
            capture.request.starts(with: Data("\(envelope.method) \(envelope.path) HTTP/1.1\r\n".utf8)),
            capture.effects.count <= 4096, capture.effects.allSatisfy({ $0.utf8.count <= 64 })
        else { throw Failure.invalidRequest }
        if let repository = capture.requestedRepository {
            guard capture.complete, RepositoryName(fullName: repository) != nil else { throw Failure.invalidRequest }
        }
        return Self(
            complete: capture.complete, effects: capture.effects, text: escaped(capture.request),
            requestedRepository: capture.requestedRepository)
    }

    private static func escaped(_ data: Data) -> String {
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
            case 13:
                let next = data.index(after: index)
                if next == data.endIndex || data[next] != 10 { bytes.append(contentsOf: [92, 114]) }
            default: bytes.append(contentsOf: [92, 120, hex[Int(byte >> 4)], hex[Int(byte & 15)]])
            }
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}

import Foundation

public struct RepositoryName: Codable, Equatable, Sendable, Identifiable {
    public let owner: String
    public let name: String
    public var fullName: String { "\(owner)/\(name)" }
    public var id: String { fullName.lowercased() }

    public init?(fullName: String) {
        let parts = fullName.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        let owner = String(parts[0])
        let name = String(parts[1])
        let alphanumeric: (UInt8) -> Bool = {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
        }
        guard !owner.isEmpty, owner.utf8.count <= 39,
            owner.utf8.allSatisfy({ alphanumeric($0) || $0 == 45 }),
            owner.utf8.first.map(alphanumeric) == true, owner.utf8.last.map(alphanumeric) == true,
            !name.isEmpty, name.utf8.count <= 100, name != ".", name != "..",
            name.utf8.allSatisfy({ alphanumeric($0) || [45, 46, 95].contains($0) })
        else { return nil }
        self.owner = owner
        self.name = name
    }
}

import Foundation

public struct SettingsMigrationSource: Codable, Equatable, Sendable {
    public enum Format: String, Codable, Sendable { case unsignedV1, signedV1 }
    public let id: String
    public let fromFormat: Format
    public let toFormat: Format

    var supported: Bool {
        Data(base64Encoded: id)?.count == 32 && fromFormat == .unsignedV1 && toFormat == .signedV1
    }
}

public struct SettingsMigration: Decodable, Equatable, Sendable {
    public let source: SettingsMigrationSource
    public let revision: UInt64
    public let settings: BrokerSettings
    public let provider: SettingsProvider?
}

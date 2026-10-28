import Foundation

public struct VaultUnlockReview: Decodable, Sendable {
    public enum Failure: Error { case invalidReview, invalidResult }
    public let id: String
    public let created: MonotonicTimestamp
    public let revision: UInt64
    public let session: Data
    public let provider: SettingsProvider

    public func validate(snapshot: SettingsSnapshot, now: MonotonicTimestamp) throws {
        guard Data(base64Encoded: id)?.count == 16, !created.isZero,
            let age = try? now.duration(since: created), age < .seconds(120),
            session.count == 16, session == snapshot.session, revision == snapshot.revision,
            snapshot.state == "configured", snapshot.settings != nil, snapshot.migration == nil,
            snapshot.provider == provider
        else { throw Failure.invalidReview }
    }

    public func validate(result: BrokerVaultStatus) throws {
        guard result.error == nil, result.state == .onlineUnlocked,
            result.binding == provider.binding, result.lastSync != nil
        else { throw Failure.invalidResult }
    }
}

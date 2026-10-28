import Foundation
import Testing

@testable import QuartermasterSecurity

private func unlockFixture() throws -> [String: Any] {
    let url = try #require(
        Bundle.module.url(forResource: "broker-protocol", withExtension: "json", subdirectory: "Fixtures"))
    let fixture = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    let replies = try #require(fixture["replies"] as? [[String: Any]])
    return try #require(replies.first { ($0["kind"] as? String) == "vaultUnlockReview" }?["review"] as? [String: Any])
}

private func decodeUnlock<T: Decodable>(_ type: T.Type, _ object: [String: Any]) throws -> T {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .secondsSince1970
    return try decoder.decode(type, from: JSONSerialization.data(withJSONObject: object))
}

private func unlockSnapshot(_ fixture: [String: Any]) throws -> SettingsSnapshot {
    try decodeUnlock(
        SettingsSnapshot.self,
        [
            "state": "configured", "revision": fixture["revision"]!, "session": fixture["session"]!,
            "settings": ["github": NSNull(), "mutations": "requireApproval"], "provider": fixture["provider"]!,
        ])
}

@Test func unlockReviewAndResultMatchTheApprovedVaultWithoutChangingSettings() throws {
    let fixture = try unlockFixture()
    let review = try decodeUnlock(VaultUnlockReview.self, fixture)
    let snapshot = try unlockSnapshot(fixture)
    try review.validate(snapshot: snapshot, now: review.created.advanced(by: .seconds(119)))
    let status = try decodeUnlock(
        BrokerVaultStatus.self,
        [
            "state": "online_unlocked", "binding": (fixture["provider"] as! [String: Any])["binding"]!, "lastSync": 123,
        ])
    try review.validate(result: status)
}

@Test(arguments: ["id", "session", "revision", "slot", "scope", "deviceKey", "binding", "zero", "future", "expired"])
func unlockReviewRejectsChangedIdentityAndInvalidTimes(_ field: String) throws {
    var fixture = try unlockFixture()
    let snapshot = try unlockSnapshot(fixture)
    switch field {
    case "id": fixture["id"] = "invalid"
    case "session": fixture["session"] = Data(repeating: 9, count: 16).base64EncodedString()
    case "revision": fixture["revision"] = 5
    case "zero": fixture["created"] = 0
    case "future": fixture["created"] = 221_000_000_000 as UInt64
    case "expired": break
    default:
        var provider = fixture["provider"] as! [String: Any]
        if field == "deviceKey" {
            provider[field] = Array(repeating: 8, count: 32)
        } else if field == "binding" {
            var binding = provider[field] as! [String: Any]
            binding["item_id"] = "33333333-3333-4333-8333-333333333333"
            provider[field] = binding
        } else {
            provider[field] = String(repeating: "c", count: 32)
        }
        fixture["provider"] = provider
    }
    let review = try decodeUnlock(VaultUnlockReview.self, fixture)
    let now = try JSONDecoder().decode(
        MonotonicTimestamp.self, from: Data((field == "expired" ? "220000000000" : "101000000000").utf8))
    #expect(throws: VaultUnlockReview.Failure.invalidReview) { try review.validate(snapshot: snapshot, now: now) }
}

@Test(arguments: ["error", "locked", "binding", "missingBinding", "missingSync"])
func unlockResultsRequireTheExactUnlockedVault(_ field: String) throws {
    let fixture = try unlockFixture()
    let review = try decodeUnlock(VaultUnlockReview.self, fixture)
    var binding = (fixture["provider"] as! [String: Any])["binding"] as! [String: Any]
    if field == "binding" { binding["email"] = "other@example.invalid" }
    var status: [String: Any] = ["state": "online_unlocked", "binding": binding, "lastSync": 123]
    switch field {
    case "error": status["error"] = "KeychainIssue"
    case "locked": status["state"] = "locked"
    case "missingBinding": status.removeValue(forKey: "binding")
    case "missingSync": status.removeValue(forKey: "lastSync")
    default: break
    }
    let result = try decodeUnlock(BrokerVaultStatus.self, status)
    #expect(throws: VaultUnlockReview.Failure.invalidResult) { try review.validate(result: result) }
}

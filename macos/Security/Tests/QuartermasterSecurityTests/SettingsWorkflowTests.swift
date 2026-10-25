import Foundation
import Testing

@testable import QuartermasterSecurity

@Test func disabledGitHubSettingsEncodeTheSharedRustCommand() throws {
    let url = try #require(
        Bundle.module.url(forResource: "settings-disabled-command", withExtension: "json", subdirectory: "Fixtures"))
    let expected = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    var settings = BrokerSettings()
    settings.mutations = .deny
    let command = BrokerCommand.prepareSettings(revision: 4, settings: settings, provider: .keep)
    let encoded = try #require(JSONSerialization.jsonObject(with: command.encoded()) as? [String: Any])
    #expect(NSDictionary(dictionary: encoded).isEqual(to: expected))
}

@Test func retainedEnrollmentCommandsEncodeTheCompleteSharedRustSelection() throws {
    let url = try #require(
        Bundle.module.url(forResource: "settings-existing-command", withExtension: "json", subdirectory: "Fixtures"))
    let expected = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    let selection = try #require(expected["provider"] as? [String: Any])
    let provider = try JSONDecoder().decode(
        SettingsProvider.self, from: JSONSerialization.data(withJSONObject: selection["provider"]!))
    var settings = BrokerSettings()
    settings.mutations = .deny
    let command = BrokerCommand.prepareSettings(revision: 4, settings: settings, provider: .existing(provider))
    let encoded = try #require(JSONSerialization.jsonObject(with: command.encoded()) as? [String: Any])
    #expect(NSDictionary(dictionary: encoded).isEqual(to: expected))
}

private func settingsFixture(_ change: (inout [String: Any]) -> Void = { _ in }) throws -> SettingsChallenge {
    let url = try #require(
        Bundle.module.url(forResource: "settings-review", withExtension: "json", subdirectory: "Fixtures"))
    var value = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    change(&value)
    return try JSONDecoder().decode(SettingsChallenge.self, from: JSONSerialization.data(withJSONObject: value))
}

@Test func settingsApprovalBindsTheSharedRustReviewAndOriginalAuthenticationDeadline() throws {
    let challenge = try settingsFixture()
    let authenticated = challenge.authenticated
    var workflow = try SettingsWorkflow(
        review: challenge.review, expectedKey: challenge.review.approvalKey, now: authenticated)
    #expect(workflow.document.proposed.settings?.github?.repositories.first?.name == "one")
    try workflow.recordAuthentication(at: authenticated, now: authenticated)
    #expect(try workflow.validate(challenge, now: authenticated) == challenge.bytes)
    try workflow.checkSubmission(now: authenticated)
    #expect(throws: SettingsWorkflow.Failure.self) { try workflow.checkSubmission(now: authenticated) }
    #expect(throws: SettingsWorkflow.Failure.self) { try workflow.validate(challenge, now: authenticated) }
}

@Test(arguments: ["revision", "document", "digest", "approvalKey", "session", "nonce", "created"])
func settingsApprovalRejectsEveryChangedFrozenReviewField(_ field: String) throws {
    let challenge = try settingsFixture()
    var workflow = try SettingsWorkflow(
        review: challenge.review, expectedKey: challenge.review.approvalKey, now: challenge.authenticated)
    try workflow.recordAuthentication(at: challenge.authenticated, now: challenge.authenticated)
    let changed = try settingsFixture { value in
        var review = value["review"] as! [String: Any]
        switch field {
        case "revision": review[field] = 1
        case "created": review[field] = 101_000_000_000 as UInt64
        default: review[field] = Data(repeating: 7, count: 32).base64EncodedString()
        }
        value["review"] = review
    }
    #expect(throws: SettingsWorkflow.Failure.self) { try workflow.validate(changed, now: challenge.authenticated) }
}

@Test(arguments: ["bytes", "authenticated", "expires"])
func settingsApprovalRejectsChangedChallengeBindings(_ field: String) throws {
    let challenge = try settingsFixture()
    var workflow = try SettingsWorkflow(
        review: challenge.review, expectedKey: challenge.review.approvalKey, now: challenge.authenticated)
    try workflow.recordAuthentication(at: challenge.authenticated, now: challenge.authenticated)
    let changed = try settingsFixture { value in
        value[field] =
            field == "bytes" ? Data("different domain".utf8).base64EncodedString() : 106_000_000_000 as UInt64
    }
    #expect(throws: SettingsWorkflow.Failure.self) { try workflow.validate(changed, now: challenge.authenticated) }
}

@Test func settingsApprovalRejectsKeyReplacementCancellationAndLateSubmission() throws {
    let challenge = try settingsFixture()
    #expect(throws: SettingsWorkflow.Failure.self) {
        try SettingsWorkflow(
            review: challenge.review, expectedKey: Data(repeating: 4, count: 65), now: challenge.authenticated)
    }
    var canceled = try SettingsWorkflow(
        review: challenge.review, expectedKey: challenge.review.approvalKey, now: challenge.authenticated)
    canceled.cancel()
    #expect(throws: SettingsWorkflow.Failure.self) {
        try canceled.recordAuthentication(at: challenge.authenticated, now: challenge.authenticated)
    }
    var expired = try SettingsWorkflow(
        review: challenge.review, expectedKey: challenge.review.approvalKey, now: challenge.authenticated)
    try expired.recordAuthentication(at: challenge.authenticated, now: challenge.authenticated)
    _ = try expired.validate(challenge, now: challenge.authenticated)
    #expect(throws: SettingsWorkflow.Failure.self) { try expired.checkSubmission(now: challenge.expires) }
}

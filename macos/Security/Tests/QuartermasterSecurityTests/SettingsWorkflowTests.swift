import CryptoKit
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

private func replacingDocument(_ review: SettingsReview, _ document: [String: Any]) throws -> SettingsReview {
    let bytes = try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys])
    return SettingsReview(
        id: review.id, created: review.created, session: review.session, nonce: review.nonce,
        revision: review.revision, document: bytes, digest: Data(SHA256.hash(data: bytes)),
        approvalKey: review.approvalKey)
}

private func challengeForReview(_ review: SettingsReview, authenticated: MonotonicTimestamp) throws -> SettingsChallenge
{
    var bytes = Data("quartermaster.settings-approval.v1\0".utf8) + review.session + review.nonce
    var revision = review.revision.bigEndian
    var timestamp = authenticated.serializedNanoseconds.bigEndian
    withUnsafeBytes(of: &revision) { bytes.append(contentsOf: $0) }
    bytes.append(review.digest)
    withUnsafeBytes(of: &timestamp) { bytes.append(contentsOf: $0) }
    return SettingsChallenge(
        review: review, authenticated: authenticated, expires: try authenticated.advanced(by: .seconds(30)),
        bytes: bytes)
}

private func namedSettingsFixture() throws -> (SettingsReview, SettingsChallenge) {
    let final = try settingsFixture()
    var document = try #require(JSONSerialization.jsonObject(with: final.review.document) as? [String: Any])
    var proposed = document["proposed"] as! [String: Any]
    var settings = proposed["settings"] as! [String: Any]
    var github = settings["github"] as! [String: Any]
    github["repositories"] = [] as [String]
    settings["github"] = github
    proposed["settings"] = settings
    document["proposed"] = proposed
    document["additions"] = [["owner": "example", "name": "one"]]
    return (try replacingDocument(final.review, document), final)
}

@Test func repositoryLookupCompletesTheReviewedNamesWithoutRenewingAuthentication() throws {
    let (review, challenge) = try namedSettingsFixture()
    var workflow = try SettingsWorkflow(review: review, expectedKey: review.approvalKey, now: challenge.authenticated)
    #expect(workflow.document.additions?.first?.fullName == "example/one")
    try workflow.recordAuthentication(at: challenge.authenticated, now: challenge.authenticated)
    let delayed = try challenge.authenticated.advanced(by: .seconds(29))
    #expect(try workflow.validate(challenge, now: delayed) == challenge.bytes)
    #expect(throws: SettingsWorkflow.Failure.self) { try workflow.checkSubmission(now: challenge.expires) }
}

@Test func authenticationNearTheReviewDeadlineStillHasItsFullOriginalSaveWindow() throws {
    let (review, original) = try namedSettingsFixture()
    let authenticated = try review.created.advanced(by: .seconds(119))
    let completed = try authenticated.advanced(by: .seconds(29))
    let challenge = try challengeForReview(original.review, authenticated: authenticated)
    var workflow = try SettingsWorkflow(review: review, expectedKey: review.approvalKey, now: authenticated)
    try workflow.recordAuthentication(at: authenticated, now: authenticated)
    #expect(try workflow.validate(challenge, now: completed) == challenge.bytes)
    try workflow.checkSubmission(now: completed)
}

@Test(arguments: ["mutations", "scope", "writes", "extra", "unknown", "previous", "existingID"])
func resolvedSettingsCannotAlterAnythingExceptIdentitiesForTheReviewedNames(_ field: String) throws {
    var (review, challenge) = try namedSettingsFixture()
    if field == "existingID" {
        var initial = try #require(JSONSerialization.jsonObject(with: review.document) as? [String: Any])
        var proposed = initial["proposed"] as! [String: Any]
        var settings = proposed["settings"] as! [String: Any]
        var github = settings["github"] as! [String: Any]
        github["repositories"] = [["id": 456, "owner": "example", "name": "two", "writes": false]]
        settings["github"] = github
        proposed["settings"] = settings
        initial["proposed"] = proposed
        review = try replacingDocument(review, initial)
    }
    var final = try #require(JSONSerialization.jsonObject(with: challenge.review.document) as? [String: Any])
    var proposed = final["proposed"] as! [String: Any]
    var settings = proposed["settings"] as! [String: Any]
    var github = settings["github"] as! [String: Any]
    var repositories = github["repositories"] as! [[String: Any]]
    switch field {
    case "mutations": settings["mutations"] = "deny"
    case "scope": repositories[0]["owner"] = "another"
    case "writes": repositories[0]["writes"] = true
    case "extra": repositories.append(["id": 456, "owner": "example", "name": "two", "writes": false])
    case "existingID": repositories.append(["id": 789, "owner": "example", "name": "two", "writes": false])
    case "previous":
        var previous = final["previous"] as! [String: Any]
        previous["provider"] = ["unknown": true]
        final["previous"] = previous
    default: settings["futureAllowAll"] = true
    }
    github["repositories"] = repositories
    settings["github"] = github
    proposed["settings"] = settings
    final["proposed"] = proposed
    challenge = try challengeForReview(
        replacingDocument(challenge.review, final), authenticated: challenge.authenticated)
    var workflow = try SettingsWorkflow(review: review, expectedKey: review.approvalKey, now: challenge.authenticated)
    try workflow.recordAuthentication(at: challenge.authenticated, now: challenge.authenticated)
    #expect(throws: (any Error).self) { try workflow.validate(challenge, now: challenge.authenticated) }
}

@Test(arguments: ["", "owner", "owner/repo/extra", "-owner/repo", "owner/..", "owner/repo?x=1", "owner/répo"])
func repositoryNamesRejectInvalidAndAmbiguousInputs(_ value: String) { #expect(RepositoryName(fullName: value) == nil) }

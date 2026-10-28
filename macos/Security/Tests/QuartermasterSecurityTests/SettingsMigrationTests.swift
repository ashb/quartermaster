import CryptoKit
import Foundation
import Testing

@testable import QuartermasterSecurity

private func importFixture() throws -> (SettingsSnapshot, SettingsReview) {
    let url = try #require(
        Bundle.module.url(forResource: "settings-review", withExtension: "json", subdirectory: "Fixtures"))
    let original = try JSONDecoder().decode(SettingsChallenge.self, from: Data(contentsOf: url)).review
    let document = try JSONDecoder().decode(SettingsDocument.self, from: original.document)
    let migration = SettingsMigration(
        source: SettingsMigrationSource(
            id: Data(repeating: 1, count: 32).base64EncodedString(), fromFormat: .unsignedV1, toFormat: .signedV1),
        revision: document.previous.revision, settings: try #require(document.proposed.settings),
        provider: document.proposed.provider)
    var json = try #require(JSONSerialization.jsonObject(with: original.document) as? [String: Any])
    json["migration"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(migration.source))
    let bytes = try JSONSerialization.data(withJSONObject: json)
    let review = SettingsReview(
        id: original.id, created: original.created, session: original.session,
        nonce: original.nonce, revision: original.revision, document: bytes, digest: Data(SHA256.hash(data: bytes)),
        approvalKey: original.approvalKey)
    return (
        SettingsSnapshot(
            state: "migrationRequired", revision: original.revision, session: original.session,
            settings: nil, provider: nil, migration: migration), review
    )
}

private func discardedReview(_ review: SettingsReview) throws -> SettingsReview {
    var document = try #require(JSONSerialization.jsonObject(with: review.document) as? [String: Any])
    var proposed = try #require(document["proposed"] as? [String: Any])
    proposed["settings"] = ["github": NSNull(), "mutations": "requireApproval"]
    proposed["provider"] = NSNull()
    document["proposed"] = proposed
    let bytes = try JSONSerialization.data(withJSONObject: document)
    return SettingsReview(
        id: review.id, created: review.created, session: review.session, nonce: review.nonce,
        revision: review.revision, document: bytes, digest: Data(SHA256.hash(data: bytes)),
        approvalKey: review.approvalKey)
}

@Test @MainActor func discardingRequiresAReviewOfTheEmptyReplacementAndPreservesTheCandidateUntilApproval() async throws
{
    let (snapshot, importing) = try importFixture()
    let discarded = try discardedReview(importing)
    var requests = 0
    let editor = SettingsEditor { command in
        switch command {
        case .prepareSettingsDiscard(let id):
            #expect(id == snapshot.migration?.source.id)
            requests += 1
            return .settingsReview(discarded)
        case .settingsCancel: return .canceled
        default: return .settingsStatus(snapshot)
        }
    }
    await editor.load()
    #expect(requests == 0)
    #expect(try await editor.reviewMigration(.discard) == discarded)
    #expect(requests == 1)
    await editor.cancel()
    #expect(editor.snapshot?.migration == snapshot.migration)
    #expect(!editor.canReview)
    #expect(editor.canImport)
}

@Test(arguments: [SettingsMigrationAction.importSettings, .discard]) @MainActor
func migrationReviewsCannotSubstituteTheOtherChoicesResult(_ action: SettingsMigrationAction) async throws {
    let (snapshot, importing) = try importFixture()
    let unexpected = try action == .discard ? importing : discardedReview(importing)
    var canceled: [String] = []
    let editor = SettingsEditor { command in
        switch command {
        case .prepareSettingsImport, .prepareSettingsDiscard: return .settingsReview(unexpected)
        case .settingsCancel(let id):
            canceled.append(try #require(id))
            return .canceled
        default: return .settingsStatus(snapshot)
        }
    }
    await editor.load()
    await #expect(throws: (any Error).self) { try await editor.reviewMigration(action) }
    #expect(canceled == [unexpected.id])
    #expect(editor.snapshot?.migration == snapshot.migration)
    #expect(!editor.canReview)
}

@Test @MainActor func migrationOffersAnExplicitImportWithoutActivatingOrAutomaticallyPreparingOldSettings() async throws
{
    let (snapshot, review) = try importFixture()
    var imports: [String] = []
    let editor = SettingsEditor { command in
        switch command {
        case .prepareSettingsImport(let id):
            imports.append(id)
            return .settingsReview(review)
        case .settingsCancel: return .canceled
        default: return .settingsStatus(snapshot)
        }
    }
    await editor.load()
    #expect(editor.canImport)
    #expect(!editor.canReview)
    #expect(imports.isEmpty)
    #expect(editor.snapshot?.settings == nil)
    #expect(editor.draft.github == nil)
    #expect(editor.snapshot?.migration?.settings.github?.repositories.first?.name == "one")
    let prepared = try await editor.reviewMigration()
    #expect(prepared == review)
    #expect(imports == [try #require(snapshot.migration?.source.id)])
    await editor.cancel()
    #expect(editor.canImport)
    #expect(editor.snapshot?.settings == nil)
}

@Test(
    arguments: ["source", "settings", "missing", "revision", "additions"],
    [SettingsMigrationAction.importSettings, .discard])
@MainActor func migrationReviewRejectsChangesToTheOfferedSourceAndResult(
    _ field: String, _ action: SettingsMigrationAction
) async throws {
    let (snapshot, importing) = try importFixture()
    let review = try action == .discard ? discardedReview(importing) : importing
    var document = try #require(JSONSerialization.jsonObject(with: review.document) as? [String: Any])
    switch field {
    case "source":
        var source = try #require(document["migration"] as? [String: Any])
        source["id"] = Data(repeating: 7, count: 32).base64EncodedString()
        document["migration"] = source
    case "settings":
        var proposed = try #require(document["proposed"] as? [String: Any])
        proposed["settings"] = ["github": NSNull(), "mutations": "deny"]
        document["proposed"] = proposed
    case "revision":
        var previous = try #require(document["previous"] as? [String: Any])
        previous["revision"] = 99
        document["previous"] = previous
    case "additions": document["additions"] = [["owner": "example", "name": "extra"]]
    default: document.removeValue(forKey: "migration")
    }
    let bytes = try JSONSerialization.data(withJSONObject: document)
    let changed = SettingsReview(
        id: review.id, created: review.created, session: review.session, nonce: review.nonce,
        revision: review.revision, document: bytes, digest: Data(SHA256.hash(data: bytes)),
        approvalKey: review.approvalKey)
    let editor = SettingsEditor { command in
        switch command {
        case .prepareSettingsImport, .prepareSettingsDiscard: return .settingsReview(changed)
        default: return .settingsStatus(snapshot)
        }
    }
    await editor.load()
    await #expect(throws: (any Error).self) { try await editor.reviewMigration(action) }
    #expect(editor.snapshot?.settings == nil)
}

@Test(arguments: [SettingsMigrationAction.importSettings, .discard]) @MainActor
func closingSettingsCancelsALateMigrationReviewWithoutDismissingIt(_ action: SettingsMigrationAction) async throws {
    let (snapshot, review) = try importFixture()
    var prepared: CheckedContinuation<BrokerReply, Never>?
    var canceled: [String] = []
    let editor = SettingsEditor { command in
        switch command {
        case .prepareSettingsImport, .prepareSettingsDiscard: return await withCheckedContinuation { prepared = $0 }
        case .settingsCancel(let id):
            canceled.append(try #require(id))
            return .canceled
        default: return .settingsStatus(snapshot)
        }
    }
    await editor.load()
    let pending = Task { try await editor.reviewMigration(action) }
    while prepared == nil { await Task.yield() }
    editor.discardDraft()
    prepared?.resume(returning: .settingsReview(review))
    await #expect(throws: CancellationError.self) { try await pending.value }
    #expect(canceled == [review.id])
    #expect(editor.canImport)
}

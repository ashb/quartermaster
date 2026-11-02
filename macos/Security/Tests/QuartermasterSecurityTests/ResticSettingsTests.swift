import Foundation
import Testing

@testable import QuartermasterSecurity

private let resticSettingsJSON =
    #"{"github":{"version":1,"mode":"github","repositories":[{"id":123,"owner":"acme","name":"tools","writes":false}],"approveUnverifiedRequests":true},"mutations":"deny","restic":{"enabled":true,"executable":"/nix/store/example/bin/.restic-wrapped","itemId":"22222222-2222-4222-8222-222222222222"}}"#

@Test func resticSettingsRoundTripPreservesGitHubAndTheExactCredentialSelection() throws {
    let data = Data(resticSettingsJSON.utf8)
    let settings = try JSONDecoder().decode(BrokerSettings.self, from: data)
    let encoded = try JSONEncoder().encode(settings)
    let original = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    let restored = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    #expect(NSDictionary(dictionary: restored).isEqual(to: original))
}

@Test func legacySettingsEncodingDoesNotIntroduceRestic() throws {
    let data = Data(
        #"{"github":{"version":1,"mode":"github","repositories":[],"approveUnverifiedRequests":false},"mutations":"requireApproval"}"#
            .utf8)
    let settings = try JSONDecoder().decode(BrokerSettings.self, from: data)
    let encoded = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(settings)) as? [String: Any])
    #expect(encoded["restic"] == nil)
    #expect(
        NSDictionary(dictionary: encoded).isEqual(
            to: try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])))
}

@Test(arguments: ["enabled", "executable", "itemId"])
func incompleteResticSettingsAreRejected(_ field: String) throws {
    var fields = try #require(JSONSerialization.jsonObject(with: Data(resticSettingsJSON.utf8)) as? [String: Any])
    var restic = try #require(fields["restic"] as? [String: Any])
    restic.removeValue(forKey: field)
    fields["restic"] = restic
    let encoded = try JSONSerialization.data(withJSONObject: fields)
    #expect(throws: DecodingError.self) { try JSONDecoder().decode(BrokerSettings.self, from: encoded) }
}

@Test @MainActor func togglingResticPreservesGitHubAndItsCredentialSelection() async throws {
    let settings = try JSONDecoder().decode(BrokerSettings.self, from: Data(resticSettingsJSON.utf8))
    let snapshot = SettingsSnapshot(
        state: "configured", revision: 4, session: Data(repeating: 1, count: 16), settings: settings, provider: nil,
        migration: nil)
    let editor = SettingsEditor { _ in .settingsStatus(snapshot) }
    await editor.load()
    editor.resticEnabled = false
    #expect(editor.draft.github == settings.github)
    #expect(editor.draft.mutations == .deny)
    #expect(editor.draft.restic?.executable == "/nix/store/example/bin/.restic-wrapped")
    #expect(editor.draft.restic?.itemId == "22222222-2222-4222-8222-222222222222")
    #expect(editor.canReview)
    editor.discardDraft()
    #expect(editor.draft == settings)
}

@Test(arguments: ["relative", "missingItem", "nilItem"], [true, false])
@MainActor func invalidResticSelectionCannotBeReviewed(_ problem: String, _ enabled: Bool) async throws {
    let snapshot = SettingsSnapshot(
        state: "configured", revision: 4, session: Data(repeating: 1, count: 16), settings: BrokerSettings(),
        provider: nil, migration: nil)
    let editor = SettingsEditor { _ in .settingsStatus(snapshot) }
    await editor.load()
    editor.draft.restic = ResticSettings(
        enabled: enabled, executable: problem == "relative" ? "restic" : "/bin/restic",
        itemId: problem == "missingItem"
            ? ""
            : problem == "nilItem" ? "00000000-0000-0000-0000-000000000000" : "22222222-2222-4222-8222-222222222222")
    #expect(!editor.canReview)
    await #expect(throws: (any Error).self) { try await editor.review() }
}

@MainActor private func lookupSnapshot() throws -> SettingsSnapshot {
    try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: Data(
            """
            {"state":"configured","revision":4,"session":"AQEBAQEBAQEBAQEBAQ==","settings":\(resticSettingsJSON),"provider":{"slot":"dummy","binding":{"server":"https://vault.example.invalid","email":"dummy@example.invalid","account_id":"11111111-1111-4111-8111-111111111111","item_id":"22222222-2222-4222-8222-222222222222","field":"LoginPassword","role":"github-write"},"scope":"dummy","deviceKey":[1]}}
            """.utf8))
}

@Test @MainActor func choosingAVaultItemChangesOnlyTheResticItemInTheUnsignedDraft() async throws {
    let snapshot = try lookupSnapshot()
    let item = VaultItemSummary(id: "33333333-3333-4333-8333-333333333333", name: "Restic backup")
    var lookupCalls = 0
    let editor = SettingsEditor { command in
        if case .vaultItems = command {
            lookupCalls += 1
            return .vaultItems(items: [item])
        }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    let previous = editor.draft
    let items = try await editor.loadVaultItems()
    #expect(editor.draft == previous)
    editor.selectResticItem(try #require(items.first))
    #expect(editor.draft.github == previous.github)
    #expect(editor.draft.mutations == previous.mutations)
    #expect(editor.draft.restic?.executable == previous.restic?.executable)
    #expect(editor.draft.restic?.enabled == previous.restic?.enabled)
    #expect(editor.draft.restic?.itemId == item.id)
    #expect(editor.draft.restic?.itemName == item.name)
    #expect(editor.snapshot?.settings == previous)
    #expect(editor.canReview)
    #expect(lookupCalls == 1)
}

@Test func resticItemNameSurvivesEncodingWithoutChangingItsIdentity() throws {
    var settings = try JSONDecoder().decode(BrokerSettings.self, from: Data(resticSettingsJSON.utf8))
    settings.restic?.itemName = "Restic backup"
    let restored = try JSONDecoder().decode(BrokerSettings.self, from: JSONEncoder().encode(settings))
    #expect(restored.restic?.itemName == "Restic backup")
    #expect(restored.restic?.itemId == settings.restic?.itemId)
}

@Test @MainActor func githubItemSelectionPreservesResticConfiguration() async throws {
    let snapshot = try lookupSnapshot()
    let editor = SettingsEditor { _ in .settingsStatus(snapshot) }
    await editor.load()
    let restic = editor.draft.restic
    let item = VaultItemSummary(id: "44444444-4444-4444-8444-444444444444", name: "GitHub token")
    editor.selectGitHubItem(item)
    #expect(editor.draft.githubCredential == GitHubCredential(itemId: item.id, itemName: item.name))
    #expect(editor.draft.restic == restic)
}

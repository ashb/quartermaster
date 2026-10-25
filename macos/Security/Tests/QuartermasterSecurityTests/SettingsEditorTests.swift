import Foundation
import Testing

@testable import QuartermasterSecurity

private func editorSnapshot(provider: SettingsProvider? = nil, retained: [SettingsProvider] = []) -> SettingsSnapshot {
    var settings = BrokerSettings()
    settings.mutations = .deny
    return SettingsSnapshot(
        state: "configured", revision: 4, session: Data(repeating: 1, count: 16),
        settings: settings, provider: provider, retained: retained)
}

private func editorProvider(
    itemID: String = "22222222-2222-4222-8222-222222222222",
    email: String = "dummy@example.invalid"
) -> SettingsProvider {
    SettingsProvider(
        slot: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        binding: VaultBinding(
            server: "https://vault.example.invalid", email: email,
            accountID: "11111111-1111-4111-8111-111111111111", itemID: itemID,
            field: "LoginPassword", role: "github-write"),
        scope: "0123456789abcdef0123456789abcdef", deviceKey: Array(repeating: 7, count: 32))
}

@Test @MainActor func editingPreferencesAndCancelingNeverSendsProofOrChangesApprovedSettings() async throws {
    var calls: [String] = []
    let snapshot = editorSnapshot()
    let editor = SettingsEditor { command in
        switch command {
        case .settingsStatus:
            calls.append("settingsStatus")
            return .settingsStatus(snapshot)
        case .settingsCancel:
            calls.append("settingsCancel")
            return .canceled
        default:
            Issue.record("Editing or cancelling sent an unexpected command: \(command)")
            throw BrokerControlError.invalidMessage
        }
    }
    await editor.load()
    editor.draft.mutations = .requireApproval
    editor.draft.github = GitHubSettings()
    #expect(editor.snapshot?.settings?.mutations == .deny)
    #expect(calls == ["settingsStatus"])
    await editor.cancel()
    #expect(editor.draft.mutations == .deny)
    #expect(editor.draft.github == nil)
    #expect(calls == ["settingsStatus", "settingsCancel"])
}

@Test @MainActor func failedEnrollmentPreservesApprovedSelectionAndDoesNotAutomaticallyPrepareOrSign() async throws {
    let snapshot = editorSnapshot()
    var calls: [String] = []
    let editor = SettingsEditor { command in
        switch command {
        case .settingsStatus:
            calls.append("settingsStatus")
            return .settingsStatus(snapshot)
        case .stageEnrollment(let server, let email, let password, let itemID):
            calls.append("stageEnrollment")
            #expect(server == "https://vault.example.invalid")
            #expect(email == "dummy@example.invalid")
            #expect(password == "dummy-password")
            #expect(itemID == nil)
            throw BrokerControlError.unavailable
        default:
            Issue.record("Failed enrolment sent an unexpected command: \(command)")
            throw BrokerControlError.invalidMessage
        }
    }
    await editor.load()
    editor.enrollment.server = "https://vault.example.invalid"
    editor.enrollment.email = "dummy@example.invalid"
    await editor.enroll(password: "dummy-password")
    #expect(calls == ["settingsStatus", "stageEnrollment"])
    #expect(editor.snapshot?.revision == 4)
    #expect(editor.stagedProvider == nil)
    #expect(!editor.busy)
    #expect(!editor.message.contains("dummy-password"))
}

@Test @MainActor func unverifiedTokenSourceEditsCannotPrepareTheOldSelection() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    var preparations = 0
    let editor = SettingsEditor { command in
        if case .prepareSettings = command { preparations += 1 }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    #expect(editor.canReview)
    editor.enrollment.itemID = "a-different-item"
    #expect(!editor.canReview)
    await #expect(throws: (any Error).self) { try await editor.review() }
    #expect(preparations == 0)
    #expect(editor.snapshot?.provider == snapshot.provider)
}

@Test(arguments: ["server", "email", "itemID"])
@MainActor func editingVerifiedEnrollmentInvalidatesItsTicket(_ field: String) async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let provider = try #require(snapshot.provider)
    var preparations = 0
    let editor = SettingsEditor { command in
        if case .stageEnrollment = command { return .enrollmentStaged(ticket: "verified", provider: provider) }
        if case .prepareSettings = command { preparations += 1 }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    await editor.enroll(password: "dummy-password")
    #expect(editor.canReview)
    #expect(editor.stagedProvider == provider)
    switch field {
    case "server": editor.enrollment.server = "https://other.example.invalid"
    case "email": editor.enrollment.email = "other@example.invalid"
    default: editor.enrollment.itemID = "a-different-item"
    }
    #expect(editor.stagedProvider == nil)
    #expect(!editor.canReview)
    await #expect(throws: (any Error).self) { try await editor.review() }
    #expect(preparations == 0)
}

@Test @MainActor func discardAndReloadRestoreApprovedEnrollmentInputs() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let editor = SettingsEditor { command in
        if case .settingsCancel = command { return .canceled }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    let approved = editor.enrollment
    editor.enrollment.itemID = "edited-item"
    await editor.cancel()
    #expect(editor.enrollment == approved)
    #expect(editor.canReview)
    editor.enrollment.server = "https://other.example.invalid"
    await editor.load()
    #expect(editor.enrollment == approved)
    #expect(editor.canReview)
}

@Test @MainActor func unchangedVerifiedEnrollmentSubmitsTheExactStagedTicket() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let provider = editorProvider(itemID: "33333333-3333-4333-8333-333333333333")
    let url = try #require(
        Bundle.module.url(forResource: "settings-review", withExtension: "json", subdirectory: "Fixtures"))
    let review = try JSONDecoder().decode(SettingsChallenge.self, from: Data(contentsOf: url)).review
    var submitted: SettingsProviderChoice?
    let editor = SettingsEditor { command in
        switch command {
        case .stageEnrollment: return .enrollmentStaged(ticket: "verified-ticket", provider: provider)
        case .prepareSettings(_, _, let selection):
            submitted = selection
            return .settingsReview(review)
        default: return .settingsStatus(snapshot)
        }
    }
    await editor.load()
    editor.enrollment.itemID = provider.binding.itemID
    await editor.enroll(password: "dummy-password")
    #expect(editor.canReview)
    _ = try await editor.review()
    guard case .staged(let ticket) = submitted else {
        Issue.record("Review did not submit the staged selection")
        return
    }
    #expect(ticket == "verified-ticket")
    #expect(editor.snapshot?.provider == snapshot.provider)
}

@Test @MainActor func anEnrollmentReplyForChangedInputsCannotRestoreItsTicket() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let provider = try #require(snapshot.provider)
    var reply: CheckedContinuation<BrokerReply, Never>?
    let editor = SettingsEditor { command in
        if case .stageEnrollment = command { return await withCheckedContinuation { reply = $0 } }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    let verification = Task { await editor.enroll(password: "dummy-password") }
    while reply == nil { await Task.yield() }
    editor.enrollment.itemID = "changed-while-verifying"
    reply?.resume(returning: .enrollmentStaged(ticket: "obsolete", provider: provider))
    await verification.value
    #expect(editor.stagedProvider == nil)
    #expect(!editor.canReview)
}

@Test @MainActor func failedReverificationCannotReuseThePreviousTicket() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let provider = editorProvider(email: "changed@example.invalid")
    var attempts = 0
    let editor = SettingsEditor { command in
        if case .stageEnrollment = command {
            attempts += 1
            if attempts == 1 { return .enrollmentStaged(ticket: "obsolete", provider: provider) }
            throw BrokerControlError.unavailable
        }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    editor.enrollment.email = "changed@example.invalid"
    await editor.enroll(password: "dummy-password")
    #expect(editor.canReview)
    await editor.enroll(password: "dummy-password")
    #expect(editor.stagedProvider == nil)
    #expect(!editor.canReview)
}

@Test @MainActor func retainedEnrollmentSelectionIsExplicitAndEditingInvalidatesIt() async throws {
    let snapshot = editorSnapshot(retained: [editorProvider()])
    let retained = try #require(snapshot.retained.first)
    let editor = SettingsEditor { command in
        if case .settingsCancel = command { return .canceled }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    #expect(editor.retainedProvider == nil)
    #expect(editor.enrollment.itemID.isEmpty)
    editor.useExisting(retained)
    #expect(editor.enrollment.itemID == retained.binding.itemID)
    #expect(editor.retainedProvider == retained)
    #expect(editor.canReview)
    #expect(editor.snapshot?.provider == nil)
    editor.enrollment.email = "another@example.invalid"
    #expect(editor.retainedProvider == nil)
    #expect(!editor.canReview)
    await editor.cancel()
    #expect(editor.enrollment.itemID.isEmpty)
}

@Test @MainActor func cancelAfterAdmissionInspectsTheCommittedRevisionBeforeReportingAnOutcome() async throws {
    let snapshot = editorSnapshot()
    let editor = SettingsEditor { command in
        if case .settingsCancel = command { return .alreadyAdmitted }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    editor.draft.mutations = .requireApproval
    await editor.cancel()
    #expect(editor.snapshot?.revision == 4)
    #expect(editor.draft.mutations == .deny)
    #expect(!editor.message.contains("discarded"))
    #expect(editor.message.contains("already admitted"))
}

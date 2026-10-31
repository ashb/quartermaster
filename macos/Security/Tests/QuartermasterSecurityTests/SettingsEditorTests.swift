import Foundation
import Testing

@testable import QuartermasterSecurity

private func editorSnapshot(provider: SettingsProvider? = nil) -> SettingsSnapshot {
    var settings = BrokerSettings()
    settings.mutations = .deny
    return SettingsSnapshot(
        state: "configured", revision: 4, session: Data(repeating: 1, count: 16),
        settings: settings, provider: provider, migration: nil)
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

@Test @MainActor func initialVaultLoginFailureDoesNotClaimThereAreApprovedSettingsToRecover() async {
    let snapshot = SettingsSnapshot(
        state: "unconfigured", revision: 0, session: Data(repeating: 1, count: 16),
        settings: nil, provider: nil, migration: nil)
    let editor = SettingsEditor { command in
        if case .stageEnrollment = command { throw BrokerControlError.denied }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    await editor.enroll(password: "dummy-password")
    #expect(editor.vaultLoginError?.contains("log in") == true)
    #expect(editor.message.isEmpty)
    #expect(editor.vaultLoginError?.contains("dummy-password") == false)
    #expect(editor.snapshot?.provider == nil)
    #expect(editor.stagedProvider == nil)
    #expect(!editor.busy)
}

@Test @MainActor func failedVaultLoginCanBeRetriedWithoutDiscardingTheDraft() async {
    let snapshot = editorSnapshot()
    let provider = editorProvider()
    var attempts = 0
    let editor = SettingsEditor { command in
        if case .stageEnrollment(_, _, let password, _) = command {
            #expect(password == "dummy-password")
            attempts += 1
            if attempts == 1 { throw BrokerControlError.denied }
            return .enrollmentStaged(ticket: "retry-ticket", provider: provider)
        }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    editor.draft.mutations = .requireApproval
    await editor.enroll(password: "dummy-password")
    #expect(editor.vaultLoginError != nil)
    #expect(!editor.busy)
    await editor.enroll(password: "dummy-password")
    #expect(attempts == 2)
    #expect(editor.vaultLoginState == .ready)
    #expect(editor.vaultLoginError == nil)
    #expect(editor.message.isEmpty)
    #expect(editor.stagedProvider == provider)
    #expect(editor.draft.mutations == .requireApproval)
    #expect(!editor.busy)
}

@Test(arguments: ["settings", "enrolment", "whitespace", "forget", "staged"])
@MainActor func discardIsAvailableOnlyWhileThereAreDraftChanges(_ change: String) async throws {
    let provider = editorProvider()
    let snapshot = editorSnapshot(provider: provider)
    let editor = SettingsEditor { command in
        if case .stageEnrollment = command { return .enrollmentStaged(ticket: "verified", provider: provider) }
        return .settingsStatus(snapshot)
    }
    #expect(!editor.canDiscard)
    await editor.load()
    #expect(!editor.canDiscard)
    switch change {
    case "settings": editor.draft.mutations = .requireApproval
    case "enrolment": editor.enrollment.email = "edited@example.invalid"
    case "whitespace": editor.enrollment.email += " "
    case "forget": editor.forget()
    default: await editor.enroll(password: "dummy-password")
    }
    #expect(editor.canDiscard)
    editor.discardDraft()
    #expect(!editor.canDiscard)
    #expect(editor.draft == snapshot.settings)
    #expect(editor.enrollment.email == provider.binding.email)
    #expect(editor.pendingRepositories.isEmpty)
    #expect(editor.stagedProvider == nil)
}

@Test @MainActor func unchangedPreferencesCannotBeReviewed() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    var preparations = 0
    let editor = SettingsEditor { command in
        if case .prepareSettings = command { preparations += 1 }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    #expect(!editor.canReview)
    await #expect(throws: (any Error).self) { try await editor.review() }
    #expect(preparations == 0)
}

@Test @MainActor func reviewRequiresAPendingSettingsOrProviderChange() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let editor = SettingsEditor { command in
        if case .settingsCancel = command { return .canceled }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    #expect(!editor.canReview)
    editor.draft.mutations = .requireApproval
    #expect(editor.canReview)
    editor.draft.mutations = .deny
    #expect(!editor.canReview)
    editor.draft.github = GitHubSettings()
    #expect(editor.canReview)
    editor.draft.github = nil
    #expect(!editor.canReview)
    editor.forget()
    #expect(editor.canReview)
    await editor.cancel()
    #expect(!editor.canReview)
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
    editor.draft.mutations = .requireApproval
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
    #expect(!editor.canReview)
    editor.enrollment.server = "https://other.example.invalid"
    await editor.load()
    #expect(editor.enrollment == approved)
    #expect(!editor.canReview)
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
        case .prepareSettings(_, _, let selection, _):
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

@Test(arguments: [Optional<String>.none, "replacement-item"])
@MainActor func anEnrollmentReplyForChangedInputsCannotRestoreItsTicket(_ itemID: String?) async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let provider = try #require(snapshot.provider)
    var reply: CheckedContinuation<BrokerReply, Never>?
    let editor = SettingsEditor { command in
        if case .stageEnrollment = command { return await withCheckedContinuation { reply = $0 } }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    var candidate = editor.enrollment
    if let itemID { candidate.itemID = itemID }
    let verification = Task { await editor.enroll(password: "dummy-password", replacement: candidate) }
    while reply == nil { await Task.yield() }
    editor.enrollment.itemID = "changed-while-verifying"
    #expect(!editor.canDiscard)
    reply?.resume(returning: .enrollmentStaged(ticket: "obsolete", provider: provider))
    await verification.value
    #expect(editor.stagedProvider == nil)
    #expect(!editor.canReview)
    #expect(editor.canDiscard)
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

@Test @MainActor func repositoryNamesRemainDraftsUntilReviewedAndAreClearedOnDiscardOrDisable() async throws {
    var settings = BrokerSettings()
    settings.github = GitHubSettings()
    let snapshot = SettingsSnapshot(
        state: "configured", revision: 4, session: Data(repeating: 1, count: 16), settings: settings,
        provider: editorProvider(), migration: nil)
    let editor = SettingsEditor { command in
        if case .settingsCancel = command { return .canceled }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    #expect(!editor.canReview)
    #expect(editor.addRepository("example/one"))
    #expect(editor.canReview)
    #expect(editor.canDiscard)
    #expect(!editor.addRepository("EXAMPLE/ONE"))
    #expect(!editor.addRepository("example/../two"))
    #expect(editor.snapshot?.settings?.github?.repositories.isEmpty == true)
    editor.removeRepository(try #require(editor.pendingRepositories.first))
    #expect(!editor.canReview)
    #expect(!editor.canDiscard)
    editor.addRepository("example/one")
    await editor.cancel()
    #expect(editor.pendingRepositories.isEmpty)
    #expect(!editor.canReview)
    editor.addRepository("example/one")
    editor.draft.github = nil
    #expect(editor.pendingRepositories.isEmpty)
}

@Test @MainActor func losingTheConnectionDisablesReviewDespiteACachedSnapshot() async throws {
    let provider = editorProvider()
    let snapshot = editorSnapshot(provider: provider)
    var preparations = 0
    let editor = SettingsEditor { command in
        if case .prepareSettings = command { preparations += 1 }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    editor.draft.mutations = .requireApproval
    #expect(editor.canReview)
    editor.connectionLost(BrokerControlError.unavailable)
    #expect(!editor.available)
    #expect(!editor.canReview)
    let failure = editor.message
    editor.draft.mutations = .deny
    #expect(editor.message == failure)
    await #expect(throws: (any Error).self) { try await editor.review() }
    #expect(preparations == 0)
    await editor.load()
    #expect(editor.available)
}

@Test @MainActor func discardingADraftRestoresApprovedFieldsWithoutChangingApprovedState() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let editor = SettingsEditor { _ in .settingsStatus(snapshot) }
    await editor.load()
    editor.draft.github = GitHubSettings()
    editor.addRepository("example/one")
    editor.enrollment.email = "unsaved@example.invalid"
    editor.discardDraft()
    #expect(editor.draft == snapshot.settings)
    #expect(editor.enrollment.email == snapshot.provider?.binding.email)
    #expect(editor.pendingRepositories.isEmpty)
    #expect(!editor.canReview)
    #expect(editor.snapshot?.revision == snapshot.revision)
}

@Test @MainActor func closingDuringReviewPreparationCancelsTheLateReviewInsteadOfPresentingIt() async throws {
    let snapshot = editorSnapshot()
    let url = try #require(
        Bundle.module.url(forResource: "settings-review", withExtension: "json", subdirectory: "Fixtures"))
    let review = try JSONDecoder().decode(SettingsChallenge.self, from: Data(contentsOf: url)).review
    var prepared: CheckedContinuation<BrokerReply, Never>?
    var canceled: [String] = []
    let editor = SettingsEditor { command in
        switch command {
        case .prepareSettings: return await withCheckedContinuation { prepared = $0 }
        case .settingsCancel(let id):
            canceled.append(try #require(id))
            return .canceled
        default: return .settingsStatus(snapshot)
        }
    }
    await editor.load()
    editor.draft.mutations = .requireApproval
    let pending = Task { try await editor.review() }
    while prepared == nil { await Task.yield() }
    editor.discardDraft()
    prepared?.resume(returning: .settingsReview(review))
    await #expect(throws: CancellationError.self) { try await pending.value }
    #expect(canceled == [review.id])
    #expect(editor.draft == snapshot.settings)
    #expect(!editor.canReview)
}

@Test @MainActor func closingDuringEnrollmentPreventsALateTicketEvenWhenInputsMatchApprovedValues() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let provider = try #require(snapshot.provider)
    var staged: CheckedContinuation<BrokerReply, Never>?
    var cancellations = 0
    let editor = SettingsEditor { command in
        switch command {
        case .stageEnrollment: return await withCheckedContinuation { staged = $0 }
        case .settingsCancel:
            cancellations += 1
            return .canceled
        default: return .settingsStatus(snapshot)
        }
    }
    await editor.load()
    let pending = Task { await editor.enroll(password: "dummy-password") }
    while staged == nil { await Task.yield() }
    editor.discardDraft()
    staged?.resume(returning: .enrollmentStaged(ticket: "obsolete", provider: provider))
    await pending.value
    #expect(editor.stagedProvider == nil)
    #expect(cancellations == 1)
    #expect(!editor.canReview)
    #expect(editor.message.isEmpty)
}

@Test @MainActor func aDelayedStatusReplyCannotRestoreADisconnectedSession() async throws {
    let snapshot = editorSnapshot()
    var reads = 0
    var reply: CheckedContinuation<BrokerReply, Never>?
    let editor = SettingsEditor { _ in
        reads += 1
        if reads > 1 { return await withCheckedContinuation { reply = $0 } }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    let pending = Task { await editor.load() }
    while reply == nil { await Task.yield() }
    editor.connectionLost(BrokerControlError.unavailable)
    let failure = editor.message
    reply?.resume(returning: .settingsStatus(snapshot))
    await pending.value
    #expect(!editor.available)
    #expect(editor.message == failure)
}

@Test(arguments: [false, true]) @MainActor
func lateCancellationRepliesCannotRestoreASessionOrEraseItsConnectionError(_ alreadyAdmitted: Bool) async throws {
    let snapshot = editorSnapshot()
    var reads = 0
    var reply: CheckedContinuation<BrokerReply, Never>?
    let editor = SettingsEditor { command in
        if case .settingsCancel = command {
            if alreadyAdmitted { return .alreadyAdmitted }
            return await withCheckedContinuation { reply = $0 }
        }
        reads += 1
        if reads > 1 { return await withCheckedContinuation { reply = $0 } }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    editor.draft.mutations = .requireApproval
    let pending = Task { await editor.cancel() }
    while reply == nil { await Task.yield() }
    editor.connectionLost(BrokerControlError.unavailable)
    let failure = editor.message
    reply?.resume(returning: alreadyAdmitted ? .settingsStatus(snapshot) : .canceled)
    await pending.value
    #expect(!editor.available)
    #expect(editor.message == failure)
}

@Test(arguments: [true, false])
@MainActor func credentialEditsAreStagedOnlyAfterSuccessfulVerification(_ succeeds: Bool) async throws {
    let approved = editorProvider()
    let replacement = editorProvider(itemID: "replacement-item")
    let snapshot = editorSnapshot(provider: approved)
    var requestedItem: String?
    let editor = SettingsEditor { command in
        if case .stageEnrollment(let server, let email, _, let itemID) = command {
            #expect(server == approved.binding.server)
            #expect(email == approved.binding.email)
            requestedItem = itemID
            if succeeds { return .enrollmentStaged(ticket: "replacement-ticket", provider: replacement) }
            throw BrokerControlError.unavailable
        }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    editor.draft.mutations = .requireApproval
    var candidate = editor.enrollment
    candidate.itemID = " replacement-item "
    await editor.enroll(password: "dummy-password", replacement: candidate)

    #expect(requestedItem == "replacement-item")
    #expect(editor.snapshot?.provider == approved)
    #expect(editor.draft.mutations == .requireApproval)
    #expect(editor.enrollment.itemID == (succeeds ? replacement.binding.itemID : approved.binding.itemID))
    #expect(editor.stagedProvider == (succeeds ? replacement : nil))
    #expect(!editor.enrollmentNeedsVerification)
    if !succeeds { #expect(editor.vaultLoginError?.contains("Could not log in") == true) }
}

@Test @MainActor func disablingGitHubPreservesRulesAndPendingRepositoriesAcrossToggles() async throws {
    var settings = BrokerSettings()
    var github = GitHubSettings()
    github.repositories = [RepositorySetting(id: 123, owner: "example", name: "project")]
    github.approveUnverifiedRequests = true
    settings.github = github
    settings.mutations = .deny
    let snapshot = SettingsSnapshot(
        state: "configured", revision: 4, session: Data(repeating: 1, count: 16),
        settings: settings, provider: nil, migration: nil)
    let editor = SettingsEditor { _ in .settingsStatus(snapshot) }
    await editor.load()
    #expect(editor.addRepository("example/pending"))
    editor.githubEnabled = false
    #expect(!editor.githubEnabled)
    #expect(editor.pendingRepositories.map(\.fullName) == ["example/pending"])
    let persisted = try JSONDecoder().decode(BrokerSettings.self, from: JSONEncoder().encode(editor.draft))
    #expect(persisted.github?.enabled == false)
    #expect(persisted.github?.repositories == github.repositories)
    #expect(persisted.github?.approveUnverifiedRequests == true)
    #expect(persisted.mutations == .deny)
    editor.githubEnabled = true
    #expect(editor.draft == settings)
    #expect(editor.pendingRepositories.map(\.fullName) == ["example/pending"])
}

@Test func olderGitHubSettingsStayEnabledAndKeepTheirSerializedShape() throws {
    let original = Data(#"{"version":1,"mode":"github","repositories":[],"approveUnverifiedRequests":true}"#.utf8)
    let settings = try JSONDecoder().decode(GitHubSettings.self, from: original)
    #expect(settings.enabled)
    let encoded = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(settings)) as? NSDictionary)
    #expect(encoded == (try JSONSerialization.jsonObject(with: original) as? NSDictionary))
}

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
    email: String = "dummy@example.invalid"
) -> SettingsProvider {
    SettingsProvider(
        slot: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        binding: VaultBinding(
            server: "https://vault.example.invalid", email: email,
            accountID: "11111111-1111-4111-8111-111111111111"),
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
        if case .stageEnrollment(_, _, let password) = command {
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

@Test(arguments: ["invalidCredentials", "mfaRequired", "serverUnavailable"])
@MainActor func vaultLoginFailuresExplainWhatTheUserCanCorrect(_ reason: String) async {
    let snapshot = editorSnapshot()
    let editor = SettingsEditor { command in
        if case .stageEnrollment = command { throw BrokerControlError(rawValue: reason) ?? .unavailable }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    await editor.enroll(password: "dummy-password")
    switch reason {
    case "invalidCredentials": #expect(editor.vaultLoginError?.contains("password") == true)
    case "mfaRequired": #expect(editor.vaultLoginError?.contains("additional authentication") == true)
    default: #expect(editor.vaultLoginError?.contains("reach") == true)
    }
    #expect(editor.message.isEmpty)
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
        case .stageEnrollment(let server, let email, let password):
            calls.append("stageEnrollment")
            #expect(server == "https://vault.example.invalid")
            #expect(email == "dummy@example.invalid")
            #expect(password == "dummy-password")
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

@Test @MainActor func unverifiedAccountEditsCannotPrepareTheOldSelection() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    var preparations = 0
    let editor = SettingsEditor { command in
        if case .prepareSettings = command { preparations += 1 }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    editor.draft.mutations = .requireApproval
    #expect(editor.canReview)
    editor.enrollment.email = "a-different-item"
    #expect(!editor.canReview)
    await #expect(throws: (any Error).self) { try await editor.review() }
    #expect(preparations == 0)
    #expect(editor.snapshot?.provider == snapshot.provider)
}

@Test(arguments: ["server", "email"])
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
    default: editor.enrollment.email = "other@example.invalid"
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
    editor.enrollment.email = "edited-item"
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
    let provider = editorProvider(email: "replacement@example.invalid")
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
    editor.enrollment.email = provider.binding.email
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

@Test(arguments: [Optional<String>.none, "replacement@example.invalid"])
@MainActor func anEnrollmentReplyForChangedInputsCannotRestoreItsTicket(_ email: String?) async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let provider = try #require(snapshot.provider)
    var reply: CheckedContinuation<BrokerReply, Never>?
    let editor = SettingsEditor { command in
        if case .stageEnrollment = command { return await withCheckedContinuation { reply = $0 } }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    var candidate = editor.enrollment
    if let email { candidate.email = email }
    let verification = Task { await editor.enroll(password: "dummy-password", replacement: candidate) }
    while reply == nil { await Task.yield() }
    editor.enrollment.email = "changed-while-verifying"
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

@Test(arguments: [true, false]) @MainActor
func cancelDuringEnrollmentRevokesTheReservationBeforeTheLoginReturns(_ succeeds: Bool) async {
    let snapshot = editorSnapshot(provider: editorProvider())
    var login: CheckedContinuation<BrokerReply, any Error>?
    var cancellations = 0
    let editor = SettingsEditor { command in
        switch command {
        case .stageEnrollment: return try await withCheckedThrowingContinuation { login = $0 }
        case .settingsCancel:
            cancellations += 1
            return .canceled
        default: return .settingsStatus(snapshot)
        }
    }
    await editor.load()
    let pending = Task { await editor.enroll(password: "dummy-password") }
    while login == nil { await Task.yield() }
    await editor.cancel()
    #expect(cancellations == 1)
    #expect(editor.busy)
    if succeeds {
        login?.resume(returning: .enrollmentStaged(ticket: "obsolete", provider: editorProvider()))
    } else {
        login?.resume(throwing: BrokerControlError.invalidCredentials)
    }
    await pending.value
    #expect(!editor.busy)
    #expect(editor.stagedProvider == nil)
    #expect(editor.vaultLoginError == nil)
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
@MainActor func accountEditsAreStagedOnlyAfterSuccessfulVerification(_ succeeds: Bool) async throws {
    let approved = editorProvider()
    let replacement = editorProvider(email: "replacement@example.invalid")
    let snapshot = editorSnapshot(provider: approved)
    var requestedEmail: String?
    let editor = SettingsEditor { command in
        if case .stageEnrollment(let server, let email, _) = command {
            #expect(server == approved.binding.server)
            #expect(email == replacement.binding.email)
            requestedEmail = email
            if succeeds { return .enrollmentStaged(ticket: "replacement-ticket", provider: replacement) }
            throw BrokerControlError.unavailable
        }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    editor.draft.mutations = .requireApproval
    var candidate = editor.enrollment
    candidate.email = " replacement@example.invalid "
    await editor.enroll(password: "dummy-password", replacement: candidate)

    #expect(requestedEmail == "replacement@example.invalid")
    #expect(editor.snapshot?.provider == approved)
    #expect(editor.draft.mutations == .requireApproval)
    #expect(editor.enrollment.email == (succeeds ? replacement.binding.email : approved.binding.email))
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

@Test @MainActor func pendingVaultAccountListsItemsBeforeItsFirstSettingsSave() async throws {
    let provider = editorProvider()
    let item = VaultItemSummary(id: "33333333-3333-4333-8333-333333333333", name: "GitHub token")
    let editor = SettingsEditor { command in
        switch command {
        case .stageEnrollment:
            return .enrollmentStaged(ticket: "pending", provider: provider, catalogue: .available([item]))
        case .settingsStatus:
            return .settingsStatus(
                SettingsSnapshot(
                    state: "unconfigured", revision: 0, session: Data(repeating: 1, count: 16),
                    settings: BrokerSettings(), provider: nil, migration: nil))
        default: throw BrokerControlError.denied
        }
    }
    await editor.load()
    await editor.enroll(password: "dummy")
    let items = try await editor.loadVaultItems()
    #expect(items == [item])
    editor.selectGitHubItem(item)
    #expect(editor.draft.githubCredential?.itemId == item.id)
    #expect(editor.snapshot?.provider == nil)
    #expect(editor.canReview)
    editor.discardDraft()
    await #expect(throws: (any Error).self) { try await editor.loadVaultItems() }
}

@Test(arguments: ["edit", "forget", "discard", "disconnect", "replacementFailure", "replacementSuccess"])
@MainActor func stagedVaultItemMetadataCannotOutliveItsAccountDraft(_ change: String) async throws {
    let provider = editorProvider()
    let first = VaultItemSummary(id: "33333333-3333-4333-8333-333333333333", name: "First account")
    let second = VaultItemSummary(id: "44444444-4444-4444-8444-444444444444", name: "Replacement account")
    var logins = 0
    let editor = SettingsEditor { command in
        switch command {
        case .stageEnrollment:
            logins += 1
            if logins > 1 && change == "replacementFailure" { throw BrokerControlError.invalidCredentials }
            return .enrollmentStaged(
                ticket: "ticket-\(logins)", provider: provider, catalogue: .available([logins == 1 ? first : second]))
        case .settingsStatus: return .settingsStatus(editorSnapshot())
        default: throw BrokerControlError.denied
        }
    }
    await editor.load()
    await editor.enroll(password: "dummy")
    let originalSource = editor.vaultItemSource
    #expect(try await editor.loadVaultItems() == [first])
    switch change {
    case "edit": editor.enrollment.email = "other@example.invalid"
    case "forget": editor.forget()
    case "discard": editor.discardDraft()
    case "disconnect": editor.connectionLost(BrokerControlError.unavailable)
    default: await editor.enroll(password: "replacement")
    }
    #expect(editor.vaultItemSource != originalSource)
    let previous = editor.draft
    editor.selectGitHubItem(first)
    #expect(editor.draft == previous)
    if change == "replacementSuccess" {
        #expect(try await editor.loadVaultItems() == [second])
        #expect(editor.draft.githubCredential == nil)
    } else {
        await #expect(throws: (any Error).self) { try await editor.loadVaultItems() }
    }
}

@Test @MainActor func lateEnrollmentReplyCannotRestoreDiscardedItemMetadata() async throws {
    var resume: CheckedContinuation<BrokerReply, Never>?
    let editor = SettingsEditor { command in
        switch command {
        case .stageEnrollment: return await withCheckedContinuation { resume = $0 }
        case .settingsStatus: return .settingsStatus(editorSnapshot())
        case .settingsCancel: return .canceled
        default: throw BrokerControlError.denied
        }
    }
    await editor.load()
    let login = Task { await editor.enroll(password: "dummy") }
    for _ in 0..<100 where resume == nil { await Task.yield() }
    let continuation = try #require(resume)
    editor.discardDraft()
    continuation.resume(
        returning: .enrollmentStaged(
            ticket: "obsolete", provider: editorProvider(),
            catalogue: .available([VaultItemSummary(id: "33333333-3333-4333-8333-333333333333", name: "Late item")])))
    await login.value
    #expect(editor.stagedProvider == nil)
    #expect(!editor.canChooseVaultItems)
    await #expect(throws: (any Error).self) { try await editor.loadVaultItems() }
}

@Test func stagedEnrollmentReplyRequiresItsBoundItemMetadata() throws {
    let provider = try JSONEncoder().encode(editorProvider())
    let prefix =
        "{\"kind\":\"enrollmentStaged\",\"ticket\":\"pending\",\"provider\":\(String(decoding: provider, as: UTF8.self))"
    let data = Data(
        (prefix
            + ",\"catalogue\":{\"state\":\"available\",\"items\":[{\"id\":\"33333333-3333-4333-8333-333333333333\",\"name\":\"Token\"}]}}")
            .utf8)
    guard
        case .enrollmentStaged(let ticket, let account, .available(let items)) = try JSONDecoder().decode(
            BrokerReply.self, from: data)
    else {
        Issue.record("Expected staged enrolment")
        return
    }
    #expect(ticket == "pending")
    #expect(account == editorProvider())
    #expect(items.first?.name == "Token")
    #expect(throws: DecodingError.self) { try JSONDecoder().decode(BrokerReply.self, from: Data((prefix + "}").utf8)) }
}

@Test @MainActor func unavailableStagedMetadataDoesNotPreventSavingTheAccount() async throws {
    let editor = SettingsEditor { command in
        switch command {
        case .stageEnrollment:
            return .enrollmentStaged(ticket: "large-account", provider: editorProvider(), catalogue: .unavailable)
        case .settingsStatus: return .settingsStatus(editorSnapshot())
        default: throw BrokerControlError.denied
        }
    }
    await editor.load()
    await editor.enroll(password: "dummy")
    #expect(editor.vaultLoginState == .ready)
    #expect(editor.stagedProvider == editorProvider())
    #expect(editor.canReview)
    await #expect(throws: SettingsEditor.Failure.self) { try await editor.loadVaultItems() }
    #expect(editor.canReview)
    editor.discardDraft()
    #expect(editor.stagedProvider == nil)
}

@Test(arguments: ["{}", "{\"state\":\"available\"}", "{\"state\":\"unknown\"}"])
func stagedCatalogueRejectsMissingOrUnknownStates(_ json: String) {
    #expect(throws: DecodingError.self) { try JSONDecoder().decode(StagedVaultCatalogue.self, from: Data(json.utf8)) }
}

@Test func vaultAccountDoesNotRequireACredentialItem() throws {
    let bytes = Data(
        #"{"server":"https://vault.example.invalid","email":"dummy@example.invalid","account_id":"11111111-1111-4111-8111-111111111111"}"#
            .utf8)
    let account = try JSONDecoder().decode(VaultBinding.self, from: bytes)
    let encoded = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(account)) as? [String: Any])
    #expect(Set(encoded.keys) == ["server", "email", "account_id"])
}

@Test(arguments: [true, false]) @MainActor
func failedVaultItemLookupPreservesTheDraftAndClearsBusy(_ failure: Bool) async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    let editor = SettingsEditor { command in
        if case .vaultItems = command {
            if failure { throw BrokerControlError.denied }
            return .idle
        }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    let previous = editor.draft
    await #expect(throws: (any Error).self) { try await editor.loadVaultItems() }
    #expect(editor.draft == previous)
    #expect(!editor.busy)
}

@Test @MainActor func vaultItemLookupRejectsAReplyAfterSettingsAreDiscarded() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    var resume: CheckedContinuation<BrokerReply, Never>?
    let editor = SettingsEditor { command in
        if case .vaultItems = command { return await withCheckedContinuation { resume = $0 } }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    let lookup = Task { try await editor.loadVaultItems() }
    for _ in 0..<100 where resume == nil { await Task.yield() }
    let continuation = try #require(resume)
    editor.discardDraft()
    continuation.resume(returning: .vaultItems(items: []))
    await #expect(throws: CancellationError.self) { try await lookup.value }
    #expect(!editor.busy)
}

@Test @MainActor func githubItemSelectionDoesNotChangeVaultEnrolment() async throws {
    let snapshot = editorSnapshot(provider: editorProvider())
    var enrolments = 0
    let editor = SettingsEditor { command in
        if case .stageEnrollment = command { enrolments += 1 }
        return .settingsStatus(snapshot)
    }
    await editor.load()
    let enrolment = editor.enrollment
    let item = VaultItemSummary(id: "44444444-4444-4444-8444-444444444444", name: "GitHub token")
    editor.selectGitHubItem(item)
    #expect(editor.draft.githubCredential == GitHubCredential(itemId: item.id, itemName: item.name))
    #expect(editor.enrollment == enrolment)
    #expect(!editor.enrollmentNeedsVerification)
    #expect(editor.canReview)
    #expect(enrolments == 0)
    editor.githubEnabled = false
    #expect(editor.draft.githubCredential?.itemId == item.id)
    editor.discardDraft()
    #expect(editor.draft.githubCredential == snapshot.settings?.githubCredential)
}

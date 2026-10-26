import AppKit
import Foundation
import QuartermasterSecurity
import Testing

@testable import Quartermaster

@MainActor private func preferencesEditor() throws -> SettingsEditor {
    let snapshot = try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: Data(
            """
            {"state":"configured","revision":4,"session":"AQEBAQEBAQEBAQEBAQEBAQ==","settings":{"mutations":"deny"},"provider":null,"migration":null}
            """.utf8))
    return SettingsEditor { command in
        if case .settingsCancel = command { return .canceled }
        return .settingsStatus(snapshot)
    }
}

@Test @MainActor func theRealReviewActionRejectsACachedSessionWhenItsConnectionIsGone() async throws {
    let application = BrokerApplication()
    let editor = try preferencesEditor()
    application.preferences = editor
    await editor.load()
    editor.draft.mutations = .requireApproval
    #expect(editor.canReview)
    application.reviewPreferences()
    #expect(!editor.canReview)
    #expect(editor.message.contains("disconnected"))
}

@Test @MainActor func closingTheNativeSettingsWindowDiscardsItsDraft() async throws {
    _ = NSApplication.shared
    let application = BrokerApplication()
    let editor = try preferencesEditor()
    application.preferences = editor
    await editor.load()
    editor.draft.mutations = .requireApproval
    let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 100, height: 100), styleMask: [.titled], backing: .buffered, defer: false
    )
    window.isReleasedWhenClosed = false
    window.contentView = PreferencesWindowObserver(opened: {}, closed: application.settingsClosed)
    #expect(editor.canReview)
    window.close()
    #expect(editor.draft.mutations == .deny)
    #expect(!editor.canReview)
    #expect(NSApplication.shared.activationPolicy() == .accessory)
}

@Test @MainActor func completingAnImportRefreshesTheApplicationsMigrationStatus() async throws {
    let pending = try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: Data(
            #"{"state":"migrationRequired","revision":4,"session":"AQEBAQEBAQEBAQEBAQEBAQ==","settings":null,"provider":null,"migration":{"source":{"id":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","fromFormat":"unsignedV1","toFormat":"signedV1"},"revision":4,"settings":{"github":null,"mutations":"deny"},"provider":null}}"#
                .utf8))
    let applied = try JSONDecoder().decode(
        SettingsSnapshot.self,
        from: Data(
            #"{"state":"configured","revision":5,"session":"AQEBAQEBAQEBAQEBAQEBAQ==","settings":{"github":null,"mutations":"deny"},"provider":null,"migration":null}"#
                .utf8))
    var reads = 0
    let application = BrokerApplication()
    application.preferences = SettingsEditor { _ in
        reads += 1
        return .settingsStatus(reads == 1 ? pending : applied)
    }
    await application.reloadPreferences()
    #expect(application.preferences.canImport)
    #expect(application.status.contains("Settings import required"))
    await application.reloadPreferences()
    #expect(application.preferences.snapshot?.revision == 5)
    #expect(!application.preferences.canImport)
    #expect(application.status == "Connected")
}

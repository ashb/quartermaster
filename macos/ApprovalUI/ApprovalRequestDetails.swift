import AppKit
import Luminare
import QuartermasterSecurity
import SwiftUI

extension ApprovalPresentation {
    var isReadOnly: Bool { readGrant != nil || readScope != nil }

    var accessLabel: String {
        if isReadOnly { return "Read only" }
        if understandingNotice != nil { return "Review request" }
        if case .issue = display.intent { return "Write access" }
        return "This request"
    }

    var callerName: String {
        guard let peer = request.peer else { return "GitHub request" }
        let name = URL(fileURLWithPath: peer.executable).lastPathComponent
        return name == "gh" || name == ".gh-wrapped" ? "GitHub CLI" : name
    }

    var requestLine: String { "\(request.method) \(request.origin ?? "")\(request.path)" }
    var requestSummary: String {
        [requestLine, apiRequest?.graphQLSummary].compactMap { $0 }.joined(separator: "\n")
    }

    var scopeDetails: String {
        if let grant = readGrant {
            return """
                Permission: \(grant.scopeName)
                Repository: \(grant.repository)\(display.resourceTitle.map { "\nResource: \($0)" } ?? "")
                Root: \(URL(fileURLWithPath: grant.root.executable).lastPathComponent) · PID \(grant.root.pid)
                Scope: \(grant.processScopeName)
                Lifetime: \(grant.lifetimeDescription)

                \(grant.summary)

                Vault
                \(vaultDetails)
                """
        }
        return
            ([
                "Operation: \(operationTitle)", repository.map { "Repository: \($0)" }, display.resourceTitle,
                "Scope: This request only.",
            ].compactMap { $0 }
            + additionalEffects + [understandingNotice].compactMap { $0 }
            + ["Vault\n\(vaultDetails)"]).joined(separator: "\n\n")
    }

    var callerDetails: String {
        guard let peer = request.peer else { return request.processChain.joined(separator: "\n") }
        let ancestry =
            peer.processes?.map {
                "\($0.name) · PID \($0.pid)\($0.limited ? " · limited information" : "")\n\($0.executable ?? "Executable unavailable")\nStarted: \(processStarted($0.startedUnixMicros))"
            }.joined(separator: "\n\n") ?? request.processChain.joined(separator: "\n")
        return [
            "Command\n\(peer.commandLine ?? "Command arguments unavailable")",
            "Working directory\n\(peer.workingDirectory ?? "Unavailable")",
            "Executable\n\(peer.executable)",
            "Socket peer\nPID \(peer.pid)",
            "Started\n\(processStarted(peer.startedUnixMicros))",
            "Signature\n\(peer.adHoc ? "Ad-hoc" : "Team ID: \(peer.teamIdentifier ?? "None")")\nSigning identifier: \(peer.signingIdentifier)\nCDHash: \(peer.cdHash)",
            "Process ancestry\n\(ancestry)", ancestryNotice,
        ].compactMap { $0 }.joined(separator: "\n\n")
    }

    var vaultDetails: String {
        [
            provider.email, provider.server, "Account: \(provider.account)", "Item: \(provider.item)",
            "Field: \(provider.field)", "Role: \(provider.role)",
            "Enrolment: \(provider.enrollment) · generation \(provider.generation)",
        ].joined(separator: "\n")
    }

    var rawRequestDetails: String { apiRequest?.text ?? "\(requestLine)\n\n\(request.body ?? "")" }

    var fullDetails: String {
        [scopeDetails, callerDetails, rawRequestDetails].joined(separator: "\n\n")
    }
}

func processStarted(_ micros: UInt64?) -> String {
    guard let micros else { return "Unavailable" }
    return Date(timeIntervalSince1970: Double(micros) / 1_000_000)
        .formatted(.dateTime.year().month(.abbreviated).day().hour().minute().second().timeZone())
}

struct ApprovalRequestDetails: View {
    let presentation: ApprovalPresentation
    @State var tab = Tab.scope
    @State private var raw = false

    enum Tab: CaseIterable {
        case scope, caller, request
    }

    private func title(for tab: Tab) -> String {
        switch tab {
        case .scope: "Approval"
        case .caller: "Caller & ancestry"
        case .request:
            presentation.request.path.split(separator: "?", maxSplits: 1).first == "/graphql"
                ? "GraphQL request" : "HTTP request"
        }
    }

    private var text: String {
        switch tab {
        case .request:
            raw
                ? presentation.rawRequestDetails
                : presentation.apiRequest?.readableText ?? presentation.rawRequestDetails
        case .scope: presentation.scopeDetails
        case .caller: presentation.callerDetails
        }
    }

    var body: some View {
        ApprovalDetailsSheet(
            subtitle: presentation.repository ?? presentation.callerName,
            text: text, fullDetails: presentation.fullDetails
        ) {
            Picker("Details", selection: $tab) {
                ForEach(Tab.allCases, id: \.self) { Text(title(for: $0)).tag($0) }
            }.pickerStyle(.segmented).labelsHidden()
            if tab == .request, presentation.apiRequest?.readableText != nil {
                Toggle("Raw HTTP", isOn: $raw).toggleStyle(.checkbox)
            }
        }
    }
}

struct ApprovalDetailsSheet<Controls: View>: View {
    let subtitle: String
    let text: String
    let fullDetails: String
    @ViewBuilder let controls: Controls
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Full request").font(.system(size: 22, weight: .semibold))
                    Text(verbatim: subtitle).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer()
                Button(copied ? "Copied" : "Copy all") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(fullDetails, forType: .string)
                    copied = true
                }.fixedSize()
            }
            controls
            ScrollView(.vertical) {
                Text(verbatim: text).font(.system(size: 12, design: .monospaced))
                    .lineSpacing(5).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true).padding(16)
            }
            .background(.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
            HStack {
                Text("Full values are selectable and wrap without truncation.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).fixedSize()
            }
        }.padding(24).frame(width: 660, height: 520)
    }
}

struct ApprovalInlineDetails: View {
    let presentation: ApprovalPresentation

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let peer = presentation.request.peer {
                row("Process", "\(URL(fileURLWithPath: peer.executable).lastPathComponent) · PID \(peer.pid)")
                row("Executable", peer.executable, monospaced: true)
                row("Signature", peer.adHoc ? "Ad-hoc" : peer.teamIdentifier.map { "Team ID: \($0)" } ?? "No Team ID")
            }
            if let grant = presentation.readGrant { row("Lifetime", grant.lifetimeDescription) }
            if let notice = presentation.ancestryNotice { row("Ancestry", notice) }
            Divider()
            Text(verbatim: presentation.requestSummary)
                .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                .lineLimit(3).truncationMode(.middle).help(presentation.requestSummary)
        }.padding(14).frame(maxWidth: .infinity, alignment: .leading).luminareSurface()
    }

    private func row(_ title: String, _ value: String, monospaced: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(title).foregroundStyle(.secondary).frame(width: 70, alignment: .leading)
            Text(verbatim: value)
                .font(.system(size: 11, design: monospaced ? .monospaced : .default))
                .lineLimit(monospaced ? 2 : nil).truncationMode(.middle).help(value)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }.font(.system(size: 11)).textSelection(.enabled)
    }
}

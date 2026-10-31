import AppKit
import QuartermasterSecurity
import SwiftUI

struct DialogProcess: Codable, Equatable {
    let pid: UInt32
    let name: String
    let executable: String?
    let limited: Bool
    var startedUnixMicros: UInt64? = nil
}

enum ProcessChoice: Equatable {
    case request
    case root(String)

    var rootID: String? {
        if case .root(let id) = self { return id }
        return nil
    }
}

struct ProcessTreeRow: Identifiable {
    let process: DialogProcess
    let choice: ProcessChoice?
    let label: String
    let duration: String
    let scopeOffered: Bool
    var id: UInt32 { process.pid }
    var dimmed: Bool { process.limited || (scopeOffered && choice == nil) }

    static func make(
        processes: [DialogProcess], peerPID: UInt32, roots: [ReadRootChoice], allowsSelection: Bool,
        shimExecutable: String? = Bundle.main.url(forAuxiliaryExecutable: "qm")?.path
    ) -> [Self] {
        processes.compactMap { process in
            let root = roots.first { $0.pid == process.pid && $0.executable == process.executable }
            if let executable = process.executable,
                executable == "/usr/bin/login" || executable == shimExecutable,
                process.pid != peerPID, root == nil
            {
                return nil
            }
            let choice: ProcessChoice?
            let label: String
            let duration: String
            if allowsSelection, !process.limited, let root {
                choice = .root(root.id)
                switch root.scope {
                case .process:
                    label = "This process"
                    duration = "until it exits"
                case .descendants:
                    label =
                        root.id == roots.first(where: { $0.scope == .descendants })?.id ? "This shell" : "Parent shell"
                    duration = "up to 1 hour"
                }
            } else if allowsSelection, process.pid == peerPID, !process.limited {
                choice = .request
                label = "This request"
                duration = ""
            } else {
                choice = nil
                label = ""
                duration = ""
            }
            return Self(
                process: process, choice: choice, label: label, duration: duration, scopeOffered: allowsSelection)
        }
    }

    var help: String {
        [
            process.limited ? "Limited process information." : nil,
            scopeOffered && choice == nil ? "This process cannot receive a read grant." : nil, process.executable,
        ]
        .compactMap { $0 }.joined(separator: "\n")
    }
}

struct ProcessApplication {
    let url: URL
    let name: String

    init?(executable: String?) {
        guard let executable else { return nil }
        var directory = URL(fileURLWithPath: executable).resolvingSymlinksInPath().deletingLastPathComponent()
        while directory.path != "/" {
            if directory.pathExtension == "app", let bundle = Bundle(url: directory),
                bundle.object(forInfoDictionaryKey: "CFBundlePackageType") as? String == "APPL"
            {
                url = directory
                name = directory.deletingPathExtension().lastPathComponent
                return
            }
            directory.deleteLastPathComponent()
        }
        return nil
    }

    @MainActor var icon: NSImage { NSWorkspace.shared.icon(forFile: url.path) }
}

struct ProcessScopeTree: View {
    let rows: [ProcessTreeRow]
    let selection: ProcessChoice
    let enabled: Bool
    var ancestryNote: String? = nil
    let choose: (ProcessChoice) -> Void
    @FocusState private var focusedRow: UInt32?

    var body: some View {
        ScrollViewReader { proxy in
            ContentSizedScrollView(maxHeight: 148) {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Array(rows.enumerated()), id: \.element.id) { depth, row in
                        let indent = CGFloat(min(depth, 6)) * 18
                        processRow(row, first: depth == 0)
                            .padding(.leading, indent)
                            .overlay(alignment: .topLeading) {
                                if depth > 0 {
                                    ProcessBranch()
                                        .stroke(
                                            .tertiary,
                                            style: StrokeStyle(lineWidth: 1, lineCap: .round, lineJoin: .round)
                                        )
                                        .frame(width: 9, height: 32)
                                        .offset(x: indent - 10)
                                        .allowsHitTesting(false)
                                        .accessibilityHidden(true)
                                }
                            }
                            .id(row.id)
                    }
                }
            }
            .onAppear {
                if let last = rows.last { proxy.scrollTo(last.id, anchor: .bottom) }
            }
            .onMoveCommand { direction in
                guard enabled else { return }
                let choices = rows.filter { $0.choice != nil }
                guard
                    let index = choices.firstIndex(where: {
                        focusedRow == nil ? $0.choice == selection : $0.id == focusedRow
                    })
                else { return }
                let next: Int
                switch direction {
                case .up: next = max(0, index - 1)
                case .down: next = min(choices.count - 1, index + 1)
                default: return
                }
                if let choice = choices[next].choice {
                    focusedRow = choices[next].id
                    proxy.scrollTo(choices[next].id)
                    choose(choice)
                }
            }
        }
    }

    private func processRow(_ row: ProcessTreeRow, first: Bool) -> some View {
        let selected = row.choice == selection
        let application = ProcessApplication(executable: row.process.executable)
        let content = HStack(spacing: 9) {
            if row.process.name == "gh", ApprovalAppearance.githubIcon != nil {
                GitHubIcon(size: 19).foregroundStyle(selected ? ApprovalAppearance.accent : .secondary)
            } else if let application {
                Image(nsImage: application.icon).resizable().renderingMode(.original)
                    .scaledToFit().frame(width: 19, height: 19)
            } else {
                Image(systemName: row.process.name == "login" ? "lock" : "terminal")
                    .font(.system(size: 15)).frame(width: 19)
                    .foregroundStyle(selected ? ApprovalAppearance.accent : .secondary)
            }
            Text(verbatim: application?.name ?? row.process.name)
                .font(.system(size: 13, weight: .medium, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                .foregroundStyle(.primary)
            Text(String(row.id)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
            Spacer(minLength: 4)
            ViewThatFits(in: .horizontal) {
                Text(row.duration.isEmpty ? row.label : "\(row.label) · \(row.duration)")
                Text(row.label)
            }.font(.system(size: 11)).fixedSize(horizontal: false, vertical: true)
                .foregroundStyle(selected ? ApprovalAppearance.accent : .secondary)
            Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                .foregroundStyle(selected ? ApprovalAppearance.accent : .secondary)
                .opacity(row.choice == nil ? 0 : 1).frame(width: 15)
        }
        .padding(.horizontal, 10).frame(maxWidth: .infinity, minHeight: 32)
        .background(background(for: row), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(selected ? ApprovalAppearance.accent : .clear))
        .contentShape(Rectangle())
        return Group {
            if row.scopeOffered {
                Button {
                    if let choice = row.choice { choose(choice) }
                } label: {
                    content
                }
                .buttonStyle(.plain)
                .disabled(row.choice == nil || !enabled)
            } else {
                content.accessibilityElement(children: .combine)
            }
        }
        .opacity(row.dimmed ? 0.5 : 1)
        .help([row.help, first && !row.process.limited ? ancestryNote : nil].compactMap { $0 }.joined(separator: "\n"))
        .focused($focusedRow, equals: row.id)
        .accessibilityLabel("\(application?.name ?? row.process.name), PID \(row.id), \(row.label), \(row.duration)")
        .accessibilityValue(row.scopeOffered ? (selected ? "Selected" : "Not selected") : "")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private func background(for row: ProcessTreeRow) -> Color {
        if row.choice == selection { return ApprovalAppearance.accent.opacity(0.12) }
        guard case .root = selection,
            let selected = rows.firstIndex(where: { $0.choice == selection }),
            let index = rows.firstIndex(where: { $0.id == row.id }), index > selected
        else { return .clear }
        return ApprovalAppearance.accent.opacity(0.035)
    }
}

struct ContentSizedScrollView<Content: View>: View {
    let maxHeight: CGFloat
    @ViewBuilder let content: Content
    @State private var contentHeight: CGFloat?

    var body: some View {
        ScrollView(.vertical) {
            content.onGeometryChange(for: CGFloat.self) { geometry in
                geometry.size.height
            } action: { height in
                contentHeight = height
            }
        }.frame(height: min(contentHeight ?? maxHeight, maxHeight), alignment: .top)
    }
}

private struct ProcessBranch: Shape {
    func path(in rect: CGRect) -> Path {
        Path { path in
            path.move(to: CGPoint(x: 0, y: -6))
            path.addLine(to: CGPoint(x: 0, y: rect.midY - 4))
            path.addQuadCurve(to: CGPoint(x: 4, y: rect.midY), control: CGPoint(x: 0, y: rect.midY))
            path.addLine(to: CGPoint(x: 8, y: rect.midY))
        }
    }
}

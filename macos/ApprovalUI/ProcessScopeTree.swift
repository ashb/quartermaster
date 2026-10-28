import AppKit
import QuartermasterSecurity
import SwiftUI

struct DialogProcess: Codable, Equatable {
    let pid: UInt32
    let name: String
    let executable: String?
    let limited: Bool
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
    var id: UInt32 { process.pid }

    static func make(
        processes: [DialogProcess], peerPID: UInt32, roots: [ReadRootChoice], allowsSelection: Bool
    ) -> [Self] {
        processes.map { process in
            let root = roots.firstIndex { $0.pid == process.pid && $0.executable == process.executable }
            let choice: ProcessChoice?
            let label: String
            if allowsSelection, process.pid == peerPID, !process.limited {
                choice = .request
                label = "This request"
            } else if allowsSelection, !process.limited, let root {
                choice = .root(roots[root].id)
                label = root == 0 ? "This shell" : "Parent shell"
            } else {
                choice = nil
                label = ""
            }
            return Self(process: process, choice: choice, label: label)
        }
    }

    var help: String {
        [
            process.limited ? "Limited process information." : nil,
            choice == nil ? "This process cannot receive a read grant." : nil, process.executable,
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
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(rows.enumerated()), id: \.element.id) { depth, row in
                        let indent = CGFloat(min(depth, 6)) * 32
                        processButton(row, first: depth == 0)
                            .padding(.leading, indent)
                            .overlay(alignment: .topLeading) {
                                if depth > 0 {
                                    ProcessBranch()
                                        .stroke(
                                            .tertiary,
                                            style: StrokeStyle(lineWidth: 1, lineCap: .round, lineJoin: .round)
                                        )
                                        .frame(width: 9, height: 28)
                                        .offset(x: indent - 12.5)
                                        .allowsHitTesting(false)
                                        .accessibilityHidden(true)
                                }
                            }
                            .id(row.id)
                    }
                }
            }
            .onAppear {
                if let selected = rows.first(where: { $0.choice == selection }) { proxy.scrollTo(selected.id) }
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
        .frame(height: 148, alignment: .top)
    }

    private func processButton(_ row: ProcessTreeRow, first: Bool) -> some View {
        let selected = row.choice == selection
        let application = ProcessApplication(executable: row.process.executable)
        return Button {
            if let choice = row.choice { choose(choice) }
        } label: {
            HStack(spacing: 9) {
                if let application {
                    Image(nsImage: application.icon).resizable().renderingMode(.original)
                        .scaledToFit().frame(width: 19, height: 19)
                } else {
                    Image(systemName: row.process.name == "login" ? "lock" : "terminal")
                        .font(.system(size: 15)).frame(width: 19)
                        .foregroundStyle(selected ? Color.accentColor : .secondary)
                }
                Text(verbatim: application?.name ?? row.process.name)
                    .font(.system(.body, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                Text(String(row.id)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                Spacer(minLength: 4)
                Text(row.label).font(.caption).fixedSize()
                    .foregroundStyle(selected ? Color.accentColor : .secondary)
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(selected ? Color.accentColor : .secondary)
                    .opacity(row.choice == nil ? 0 : 1).frame(width: 15)
            }
            .padding(.horizontal, 10).frame(maxWidth: .infinity, minHeight: 28)
            .background(background(for: row), in: RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(selected ? Color.accentColor : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(row.choice == nil || !enabled)
        .opacity(row.choice == nil ? 0.5 : 1)
        .help([row.help, first && !row.process.limited ? ancestryNote : nil].compactMap { $0 }.joined(separator: "\n"))
        .focused($focusedRow, equals: row.id)
        .accessibilityLabel("\(application?.name ?? row.process.name), PID \(row.id), \(row.label)")
        .accessibilityValue(selected ? "Selected" : "Not selected")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private func background(for row: ProcessTreeRow) -> Color {
        if row.choice == selection { return .accentColor.opacity(0.12) }
        guard case .root = selection,
            let selected = rows.firstIndex(where: { $0.choice == selection }),
            let index = rows.firstIndex(where: { $0.id == row.id }), index > selected
        else { return .clear }
        return .accentColor.opacity(0.035)
    }
}

private struct ProcessBranch: Shape {
    func path(in rect: CGRect) -> Path {
        Path { path in
            path.move(to: CGPoint(x: 0, y: rect.midY - 9))
            path.addLine(to: CGPoint(x: 0, y: rect.midY - 4))
            path.addQuadCurve(to: CGPoint(x: 4, y: rect.midY), control: CGPoint(x: 0, y: rect.midY))
            path.addLine(to: CGPoint(x: 8, y: rect.midY))
            path.move(to: CGPoint(x: 5, y: rect.midY - 3))
            path.addLine(to: CGPoint(x: 8, y: rect.midY))
            path.addLine(to: CGPoint(x: 5, y: rect.midY + 3))
        }
    }
}

import SwiftUI
import QuartermasterSecurity

@main
struct QuartermasterApp: App {
    init() {
        if CommandLine.arguments.dropFirst().first == "--vault-enroll", [4, 5].contains(CommandLine.arguments.count) {
            let itemId = CommandLine.arguments.count == 5 ? CommandLine.arguments[4] : nil
            exit(BrokerApplication.run(enrollment: (CommandLine.arguments[2], CommandLine.arguments[3]), itemId: itemId))
        }
        if CommandLine.arguments.dropFirst().first?.hasPrefix("--approval-key-") == true {
            exit(ApprovalKeyCommand.run(Array(CommandLine.arguments.dropFirst())))
        }
        exit(BrokerApplication.run())
    }

    var body: some Scene {
        Settings { EmptyView() }
    }
}

enum ApprovalKeyCommand {
    static func run(_ arguments: [String]) -> Int32 {
        guard arguments.count == 1 else { return 2 }
        let store = ApprovalKeyStore()
        do {
            var report: [String: Any] = ["status": "PASS", "profile": "development"]
            switch arguments[0] {
            case "--approval-key-status":
                report["public_key"] = try store.existingPublicKey()?.base64EncodedString()
                report["enrolled"] = report["public_key"] != nil
            case "--approval-key-reset": try store.reset()
            default: return 2
            }
            let bytes = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
            print(String(decoding: bytes, as: UTF8.self))
            return 0
        } catch {
            print("FAIL: approval_key_\(error)")
            return 1
        }
    }
}

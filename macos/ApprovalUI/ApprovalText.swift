import QuartermasterSecurity

extension ApprovalDisplay {
    var title: String {
        switch intent {
        case .request: "Approve GitHub request"
        case .issue(let action, let number):
            number.map { "\(action.label) #\($0)" } ?? action.label
        case .readGrant(let grant): grant.title
        }
    }

    var authenticationReason: String {
        switch intent {
        case .readGrant(let grant): "\(grant.title) in \(grant.repository)"
        case .request, .issue: "approve this GitHub request once"
        }
    }
}

extension UnderstandingNotice {
    var text: String {
        switch self {
        case .incompleteRequest: "This request isn't fully understood. Review the HTTP details before approving."
        }
    }
}

extension ReadGrantReview {
    public var title: String { permission.title }
    public var summary: String { permission.summary }
    public var scopeName: String { permission.scopeName }
}

extension ReadPermission {
    var title: String {
        switch self {
        case .issueReads: "Allow issue reads"

        }
    }

    var summary: String {
        switch self {
        case .issueReads: "List and read issues from this shell's descendants using the same caller executable."

        }
    }

    var scopeName: String {
        switch self {
        case .issueReads: "Issue reads"

        }
    }
}

extension GitHubEffect {
    var label: String {
        switch self {
        case .readRepository: "Read repository"
        case .listIssues: "List issues"
        case .readIssue: "Read issue"
        case .closeIssue: "Close issue"
        case .deleteIssue: "Delete issue"
        case .deleteRepository: "Delete repository"
        }
    }
}

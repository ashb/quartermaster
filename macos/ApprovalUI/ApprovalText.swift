import Foundation
import QuartermasterSecurity

extension ApprovalDisplay {
    var title: String {
        switch intent {
        case .request: "Approve GitHub request"
        case .issue(let action, let number):
            number.map { "\(action.label) #\($0)?" } ?? "\(action.label)?"
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
        case .unresolvedIssue: "Couldn’t verify which issue this ID identifies."
        }
    }
}

extension ReadGrantReview {
    public var title: String { permission.title }
    public var summary: String {
        permission.summary + " "
            + (root.scope == .process
                ? "Only this running process. Writes need separate approval."
                : "This shell's descendants must use the same caller executable. Writes need separate approval.")
    }
    public var scopeName: String { permission.scopeName }
    public var lifetimeDescription: String {
        let end =
            root.scope == .process
            ? "process exits or replaces its executable" : "shell exits or replaces its executable"
        return "Until this \(end), \(expires.formatted(date: .abbreviated, time: .shortened)), or backend restart"
    }
    public var processScopeName: String {
        root.scope == .process ? "This process" : "Shell descendants"
    }
}

extension ReadPermission {
    var compactSummary: String {
        switch self {
        case .issueReads: "Read issues. Writes need separate approval."
        case .githubCategories(let categories):
            "Read \(categories.map(\.compactName).formatted(.list(type: .and))). Writes need separate approval."
        }
    }

    var title: String {
        switch self {
        case .issueReads: "Allow issue reads"
        case .githubCategories(let categories):
            if Set(categories) == Set(GitHubReadCategory.allCases) {
                "Allow GitHub reads"
            } else {
                categories.count == 1 ? categories[0].title : "Allow selected GitHub reads"
            }
        }
    }

    var summary: String {
        switch self {
        case .issueReads: "List and read issues."
        case .githubCategories(let categories):
            categories.map(\.summary).joined(separator: " ")
        }
    }

    var scopeName: String {
        switch self {
        case .issueReads: "Issue reads"
        case .githubCategories(let categories): categories.map(\.name).joined(separator: ", ")
        }
    }
}

extension GitHubEffect {
    var label: String {
        switch self {
        case .readRepository: "Read repository"
        case .listIssues: "List issues"
        case .readIssue: "Read issue"
        case .readReadme: "Read README contents"
        case .listPullRequests: "List pull requests"
        case .readPullRequest: "Read pull request"
        case .listWorkflows: "List workflows"
        case .readWorkflow: "Read workflow"
        case .listWorkflowRuns: "List workflow runs"
        case .readWorkflowRun: "Read workflow run"
        case .listWorkflowJobs: "List workflow jobs"
        case .readWorkflowJob: "Read workflow job"
        case .listRunArtifacts: "List run artifacts"
        case .readCheckAnnotations: "Read check annotations"
        case .readRunLogs: "Read run logs"
        case .readJobLogs: "Read job logs"
        case .readRelatedSummaries: "Read related actor and fork summaries"
        case .readLinkedIssueSummaries: "Read linked issue summaries across repositories"
        case .readProjectSummaries: "Read linked project summaries"
        case .readCheckSummaries: "Read check summaries"
        case .closeIssue: "Close issue"
        case .reopenIssue: "Reopen issue"
        case .deleteIssue: "Delete issue"
        case .deleteRepository: "Delete repository"
        }
    }
}

extension GitHubReadCategory {
    var compactName: String {
        switch self {
        case .repository: "repository metadata"
        case .issues: "issues and pull requests"
        case .actions: "Actions metadata"
        case .output: "build output"
        }
    }
    var name: String {
        switch self {
        case .repository: "Repository"
        case .issues: "Issues and PRs"
        case .actions: "Actions metadata"
        case .output: "Build output"
        }
    }
    var title: String {
        switch self {
        case .repository: "Allow repository reads"
        case .issues: "Allow issue and PR reads"
        case .actions: "Allow Actions metadata reads"
        case .output: "Allow build output reads"
        }
    }
    var summary: String {
        switch self {
        case .repository: "Read repository metadata and README, including owner summaries."
        case .issues:
            "Read issues and pull requests, including actor, fork, linked issue and project summaries across repositories."
        case .actions:
            "Read Actions workflows, runs, jobs and artifact lists, including related actor, fork and check summaries."
        case .output: "Read build logs and check annotations. Output may contain sensitive values printed by workflows."
        }
    }
}

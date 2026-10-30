use crate::{
    analysis::{Analysis, EffectKind, Repository, Resource, UncoveredReason},
    json::Json,
};

mod details;
#[cfg(test)]
pub(crate) use details::INSPECT_API_REVIEWS as DETAIL_API_REVIEWS;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Context {
    Query,
    Mutation,
    Subscription,
    Repository,
    Issue,
    Issues,
    Edge,
    PageInfo,
    ClosePayload,
    DeletePayload,
    Object(&'static str),
    Connection(&'static str),
    EdgeOf(&'static str),
    Unknown,
}

impl Context {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Query => "Query",
            Self::Mutation => "Mutation",
            Self::Subscription => "Subscription",
            Self::Repository => "Repository",
            Self::Issue => "Issue",
            Self::Issues => "IssueConnection",
            Self::Edge => "IssueEdge",
            Self::PageInfo => "PageInfo",
            Self::ClosePayload => "CloseIssuePayload",
            Self::DeletePayload => "DeleteIssuePayload",
            Self::Object(name) => match name {
                "RelatedIssue" => "Issue",
                "RelatedRepository" => "Repository",
                "RelatedOrganisation" => "Organization",
                "PullRequestReviewRequest" => "ReviewRequest",
                name => name,
            },
            Self::Connection(name) => match name {
                "PullRequest" => "PullRequestConnection",
                "Label" => "LabelConnection",
                "User" => "UserConnection",
                "IssueComment" => "IssueCommentConnection",
                "RelatedIssue" => "IssueConnection",
                "ProjectV2Item" => "ProjectV2ItemConnection",
                "PullRequestReviewRequest" => "ReviewRequestConnection",
                "PullRequestReview" => "PullRequestReviewConnection",
                "PullRequestCommit" => "PullRequestCommitConnection",
                "StatusCheckRollupContext" => "StatusCheckRollupContextConnection",
                _ => "",
            },
            Self::EdgeOf(name) => match name {
                "PullRequest" => "PullRequestEdge",
                "Label" => "LabelEdge",
                "User" => "UserEdge",
                "IssueComment" => "IssueCommentEdge",
                "RelatedIssue" => "IssueEdge",
                "ProjectV2Item" => "ProjectV2ItemEdge",
                "PullRequestReviewRequest" => "ReviewRequestEdge",
                "PullRequestReview" => "PullRequestReviewEdge",
                "PullRequestCommit" => "PullRequestCommitEdge",
                "StatusCheckRollupContext" => "StatusCheckRollupContextEdge",
                _ => "",
            },
            Self::Unknown => "",
        }
    }

    pub(super) fn refine(self, name: &str) -> Option<Self> {
        if self.name() == name {
            return Some(self);
        }
        match (self, name) {
            (Self::Object("IssueOrPullRequest"), "Issue") => Some(Self::Issue),
            (Self::Object("IssueOrPullRequest"), "PullRequest") => {
                Some(Self::Object("PullRequest"))
            }
            (Self::Object("Actor" | "RepositoryOwner" | "RequestedReviewer"), "User") => {
                Some(Self::Object("User"))
            }
            (Self::Object("Actor" | "RequestedReviewer"), "Bot") => Some(Self::Object("Bot")),
            (Self::Object("Actor" | "RepositoryOwner"), "Organization") => {
                Some(Self::Object("RelatedOrganisation"))
            }
            (Self::Object("RequestedReviewer"), "Team") => Some(Self::Object("Team")),
            (Self::Object("StatusCheckRollupContext"), "StatusContext") => {
                Some(Self::Object("StatusContext"))
            }
            (Self::Object("StatusCheckRollupContext"), "CheckRun") => {
                Some(Self::Object("CheckRun"))
            }
            (Self::Object("ProjectV2ItemFieldValue"), "ProjectV2ItemFieldSingleSelectValue") => {
                Some(Self::Object("ProjectV2ItemFieldSingleSelectValue"))
            }
            _ => None,
        }
    }
}

pub(super) fn input_type_matches(name: &str, value: &Json) -> Option<bool> {
    Some(match name {
        "IssueOrder" => details::valid_order(value),
        "PullRequestOrder" => details::valid_pull_request_order(value),
        "IssueFilters" => details::valid_issue_filter(value),
        "IssueOrderField" => matches!(
            value.string(),
            Some("CREATED_AT" | "UPDATED_AT" | "COMMENTS")
        ),
        "PullRequestOrderField" => matches!(value.string(), Some("CREATED_AT" | "UPDATED_AT")),
        "OrderDirection" => matches!(value.string(), Some("ASC" | "DESC")),
        _ => return None,
    })
}

#[qm_api_macros::reviewed]
pub(super) fn inspect(
    analysis: &mut Analysis,
    context: Context,
    name: &str,
    args: &Json,
    path: &[String],
) -> Option<Context> {
    let fields = args.object().unwrap_or(&[]);
    if name == "__typename" {
        if !fields.is_empty() {
            unknown(analysis, path, UncoveredReason::Argument);
        }
        return None;
    }
    let (child, allowed): (Option<Context>, &[&str]) = match (context, name) {
        #[api("GraphQL Query.repository", "Cp_-9h7Fx9s")]
        (Context::Query, "repository") => {
            match (
                args.unique("owner").and_then(Json::string),
                args.unique("name").and_then(Json::string),
            ) {
                (Some(owner), Some(name))
                    if crate::rest::valid_name(owner) && crate::rest::valid_name(name) =>
                {
                    analysis.resource(Resource::Repository(Repository {
                        owner: owner.into(),
                        name: name.into(),
                    }));
                    analysis.effect_graphql(EffectKind::ReadRepository, path);
                }
                _ => unknown(analysis, path, UncoveredReason::Argument),
            }
            (Some(Context::Repository), &["owner", "name"])
        }
        (Context::Query, "node" | "nodes") => {
            unknown(analysis, path, UncoveredReason::ResourceOwnership);
            for (_, value) in fields {
                collect_nodes(value, analysis);
            }
            (Some(Context::Unknown), &["id", "ids"])
        }
        (Context::Repository, "issues") => {
            analysis.effect_graphql(EffectKind::ListIssues, path);
            for (key, value) in fields {
                let valid = match (key.as_str(), value) {
                    ("first" | "last", Json::Number(number)) => {
                        number.as_u64().is_some_and(|n| (1..=100).contains(&n))
                    }
                    ("after" | "before", Json::String(_) | Json::Null) => true,
                    ("states", Json::Null) => true,
                    ("states", Json::String(state)) => matches!(state.as_str(), "OPEN" | "CLOSED"),
                    ("states", Json::Array(states)) => states
                        .iter()
                        .all(|state| matches!(state.string(), Some("OPEN" | "CLOSED"))),
                    ("orderBy", value) => details::valid_order(value),
                    ("filterBy", value) => details::valid_issue_filter(value),
                    _ => false,
                };
                if !valid {
                    unknown(analysis, path, UncoveredReason::Argument);
                }
            }
            if !fields
                .iter()
                .any(|(key, _)| matches!(key.as_str(), "first" | "last"))
            {
                unknown(analysis, path, UncoveredReason::Argument);
            }
            (
                Some(Context::Issues),
                &[
                    "first", "last", "after", "before", "states", "orderBy", "filterBy",
                ],
            )
        }
        (Context::Repository, "issue") => {
            analysis.effect_graphql(EffectKind::ReadIssue, path);
            match args.unique("number") {
                Some(Json::Number(number))
                    if number
                        .as_u64()
                        .is_some_and(|n| n > 0 && n <= i32::MAX as u64) =>
                {
                    if let Some(number) = number.as_u64().and_then(std::num::NonZeroU64::new) {
                        analysis.resource(Resource::IssueNumber(number));
                    }
                }
                _ => unknown(analysis, path, UncoveredReason::Argument),
            };
            (Some(Context::Issue), &["number"])
        }
        #[api("GraphQL Mutation.closeIssue", "5WEeyQese5A")]
        #[api("GraphQL Mutation.reopenIssue", "9N9jFfJiS1I")]
        #[api("GraphQL Mutation.deleteIssue", "lo_KTeZ5N9o")]
        (Context::Mutation, "closeIssue" | "reopenIssue" | "deleteIssue") => {
            analysis.effect_graphql(
                if name == "closeIssue" {
                    EffectKind::CloseIssue
                } else if name == "reopenIssue" {
                    EffectKind::ReopenIssue
                } else {
                    EffectKind::DeleteIssue
                },
                path,
            );
            unknown(analysis, path, UncoveredReason::ResourceOwnership);
            if let Some(input) = args.unique("input") {
                if let Some(id) = input.unique("issueId").and_then(Json::string) {
                    analysis.resource(Resource::NodeId(id.into()));
                } else {
                    unknown(analysis, path, UncoveredReason::Argument);
                }
                if input.object().is_none_or(|fields| {
                    fields.iter().any(|(key, value)| {
                        !matches!(key.as_str(), "issueId" | "clientMutationId")
                            || value.string().is_none()
                    })
                }) {
                    unknown(analysis, path, UncoveredReason::Argument);
                }
            } else {
                unknown(analysis, path, UncoveredReason::Argument);
            }
            (
                Some(if name != "deleteIssue" {
                    Context::ClosePayload
                } else {
                    Context::DeletePayload
                }),
                &["input"],
            )
        }
        #[api("GraphQL Repository.name", "Y--GLPUUapU")]
        (
            Context::Repository,
            "id" | "name" | "nameWithOwner" | "url" | "description" | "isPrivate",
        )
        | (
            Context::Issue,
            "id" | "number" | "title" | "body" | "state" | "url" | "createdAt" | "updatedAt",
        )
        | (Context::Issues, "totalCount")
        | (Context::Edge, "cursor")
        | (Context::PageInfo, "hasNextPage" | "hasPreviousPage" | "startCursor" | "endCursor")
        | (Context::ClosePayload | Context::DeletePayload, "clientMutationId") => (None, &[]),
        (Context::Issue, "repository") => (Some(Context::Repository), &[]),
        (Context::Issues, "nodes") => (Some(Context::Issue), &[]),
        (Context::Issues, "edges") => (Some(Context::Edge), &[]),
        (Context::Issues, "pageInfo") => (Some(Context::PageInfo), &[]),
        (Context::Edge, "node") | (Context::ClosePayload, "issue") => (Some(Context::Issue), &[]),
        #[api_unrecognised(
            "GraphQL Mutation.mergePullRequest",
            "9ac9sTiJy94",
            "Merge mutation semantics are not modelled"
        )]
        #[api_remainder(
            "GraphQL",
            "r7eysSNpr_c",
            "Remaining GraphQL fields, inputs and types require review when they change"
        )]
        _ => {
            if let Some(child) = details::inspect(analysis, context, name, args, path) {
                return child;
            }
            unknown(analysis, path, UncoveredReason::Field);
            (Some(Context::Unknown), &[])
        }
    };
    if fields
        .iter()
        .any(|(key, _)| !allowed.contains(&key.as_str()))
    {
        unknown(analysis, path, UncoveredReason::Argument);
    }
    child
}

fn collect_nodes(value: &Json, analysis: &mut Analysis) {
    match value {
        Json::String(id) => analysis.resource(Resource::NodeId(id.clone())),
        Json::Array(ids) => {
            for id in ids {
                collect_nodes(id, analysis);
            }
        }
        _ => {}
    }
}

fn unknown(analysis: &mut Analysis, path: &[String], reason: UncoveredReason) {
    analysis.unknown_graphql(path, reason);
}

use super::{
    Context::{self, Connection, Object},
    unknown,
};
use crate::{
    analysis::{Analysis, EffectKind, Resource, UncoveredReason},
    json::Json,
};

pub(super) fn valid_order(value: &Json) -> bool {
    if matches!(value, Json::Null) {
        return true;
    }
    value.object().is_some_and(|fields| fields.len() == 2)
        && matches!(
            value.unique("field").and_then(Json::string),
            Some("CREATED_AT" | "UPDATED_AT" | "COMMENTS")
        )
        && matches!(
            value.unique("direction").and_then(Json::string),
            Some("ASC" | "DESC")
        )
}

pub(super) fn valid_pull_request_order(value: &Json) -> bool {
    valid_order(value) && value.unique("field").and_then(Json::string) != Some("COMMENTS")
}

pub(super) fn valid_issue_filter(value: &Json) -> bool {
    if matches!(value, Json::Null) {
        return true;
    }
    value.object().is_some_and(|fields| {
        fields.iter().all(|(name, value)| {
            matches!(name.as_str(), "assignee" | "createdBy" | "mentioned")
                && matches!(value, Json::String(_) | Json::Null)
        })
    })
}

fn pagination(args: &Json, required: bool) -> bool {
    args.object().is_some_and(|fields| {
        (!required
            || fields
                .iter()
                .any(|(name, _)| matches!(name.as_str(), "first" | "last")))
            && fields
                .iter()
                .all(|(name, value)| match (name.as_str(), value) {
                    ("first" | "last", Json::Number(value)) => {
                        value.as_u64().is_some_and(|n| (1..=100).contains(&n))
                    }
                    ("before" | "after", Json::String(_) | Json::Null) => true,
                    _ => false,
                })
    })
}

fn object(name: &'static str) -> Context {
    match name {
        "Issue" => Context::Issue,
        _ => Context::Object(name),
    }
}

pub(super) fn inspect(
    analysis: &mut Analysis,
    context: Context,
    name: &str,
    args: &Json,
    path: &[String],
) -> Option<Option<Context>> {
    let empty = args.object().is_some_and(|fields| fields.is_empty());
    let mut valid = empty;
    let mut related = None;
    let child = match (context, name) {
        (Context::Repository, "hasIssuesEnabled") => None,
        (Context::Repository, "owner") => {
            related = Some(EffectKind::ReadRelatedSummaries);
            Some(Object("RepositoryOwner"))
        }
        (Context::Repository, "issueOrPullRequest" | "pullRequest") => {
            let number = args.unique("number").and_then(|value| match value {
                Json::Number(value) => value
                    .as_u64()
                    .filter(|n| *n <= i32::MAX as u64)
                    .and_then(std::num::NonZeroU64::new),
                _ => None,
            });
            valid = number.is_some() && args.object().is_some_and(|fields| fields.len() == 1);
            if let Some(number) = number {
                analysis.resource(Resource::PullRequestNumber(number));
                if name == "issueOrPullRequest" {
                    analysis.resource(Resource::IssueNumber(number));
                }
            }
            analysis.effect_graphql(EffectKind::ReadPullRequest, path);
            if name == "issueOrPullRequest" {
                analysis.effect_graphql(EffectKind::ReadIssue, path);
                Some(Object("IssueOrPullRequest"))
            } else {
                Some(Object("PullRequest"))
            }
        }
        (Context::Repository, "pullRequests") => {
            analysis.effect_graphql(EffectKind::ListPullRequests, path);
            valid = args.object().is_some_and(|fields| {
                fields
                    .iter()
                    .any(|(name, _)| matches!(name.as_str(), "first" | "last"))
                    && fields.iter().all(|(name, value)| match name.as_str() {
                        "first" | "last" | "before" | "after" => {
                            pagination(&Json::Object(vec![(name.clone(), value.clone())]), false)
                        }
                        "baseRefName" | "headRefName" => {
                            matches!(value, Json::String(_) | Json::Null)
                        }
                        "orderBy" => valid_pull_request_order(value),
                        "states" => match value {
                            Json::Null => true,
                            Json::String(state) => {
                                matches!(state.as_str(), "OPEN" | "CLOSED" | "MERGED")
                            }
                            Json::Array(states) => states.iter().all(|state| {
                                matches!(state.string(), Some("OPEN" | "CLOSED" | "MERGED"))
                            }),
                            _ => false,
                        },
                        _ => false,
                    })
            });
            Some(Connection("PullRequest"))
        }
        (Connection(node), "nodes") => Some(object(node)),
        (Connection(node), "edges") => Some(Context::EdgeOf(node)),
        (Connection(_), "pageInfo") => Some(Context::PageInfo),
        (Connection(_), "totalCount") | (Context::EdgeOf(_), "cursor") => None,
        (Context::EdgeOf(node), "node") => Some(object(node)),
        (Context::Issue | Object("PullRequest"), "author") => {
            related = Some(EffectKind::ReadRelatedSummaries);
            Some(Object("Actor"))
        }
        (Context::Issue | Object("PullRequest"), "assignees") => {
            related = Some(EffectKind::ReadRelatedSummaries);
            valid = pagination(args, true);
            Some(Connection("User"))
        }
        (Context::Issue | Object("PullRequest"), "labels") => {
            valid = pagination(args, true);
            Some(Connection("Label"))
        }
        (Context::Issue | Object("PullRequest"), "comments") => {
            valid = pagination(args, true);
            Some(Connection("IssueComment"))
        }
        (Context::Issue | Object("PullRequest"), "milestone") => Some(Object("Milestone")),
        (
            Context::Issue
            | Object("PullRequest")
            | Object("IssueComment")
            | Object("PullRequestReview"),
            "reactionGroups",
        ) => Some(Object("ReactionGroup")),
        (Object("ReactionGroup"), "content") => None,
        (Object("ReactionGroup"), "users") => Some(Object("ReactionUserCount")),
        (Object("ReactionUserCount"), "totalCount") => None,
        (Object("Label" | "IssueType"), "id" | "name" | "description" | "color") => None,
        (Object("Milestone"), "number" | "title" | "description" | "dueOn") => None,
        (Object("Actor"), "login") => None,
        (Object("RepositoryOwner"), "id" | "login") => None,
        (Object("User"), "id" | "login" | "name" | "databaseId") => None,
        (Object("Bot"), "id" | "login") => None,
        (Object("RelatedOrganisation"), "id" | "login" | "name") => None,
        (
            Object("IssueComment"),
            "id"
            | "url"
            | "authorAssociation"
            | "body"
            | "createdAt"
            | "includesCreatedEdit"
            | "isMinimized"
            | "minimizedReason"
            | "viewerDidAuthor",
        ) => None,
        (Object("IssueComment" | "PullRequestReview"), "author") => {
            related = Some(EffectKind::ReadRelatedSummaries);
            Some(Object("Actor"))
        }
        (Context::Issue, "stateReason") => None,
        (Context::Issue, "issueType") => {
            related = Some(EffectKind::ReadRelatedSummaries);
            Some(Object("IssueType"))
        }
        (Context::Issue, "parent") => {
            related = Some(EffectKind::ReadLinkedIssueSummaries);
            Some(Object("RelatedIssue"))
        }
        (Context::Issue, "subIssues" | "blockedBy" | "blocking") => {
            related = Some(EffectKind::ReadLinkedIssueSummaries);
            valid = pagination(args, true);
            Some(Connection("RelatedIssue"))
        }
        (Context::Issue, "subIssuesSummary") => {
            related = Some(EffectKind::ReadLinkedIssueSummaries);
            Some(Object("SubIssuesSummary"))
        }
        (Object("SubIssuesSummary"), "total" | "completed" | "percentCompleted") => None,
        (Object("RelatedIssue"), "id" | "number" | "title" | "url" | "state") => None,
        (Object("RelatedIssue"), "repository") => Some(Object("RelatedRepository")),
        (Object("RelatedRepository"), "id" | "name" | "nameWithOwner") => None,
        (Object("RelatedRepository"), "owner") => Some(Object("RepositoryOwner")),
        (Context::Issue | Object("PullRequest"), "projectItems") => {
            related = Some(EffectKind::ReadProjectSummaries);
            valid = pagination(args, true);
            Some(Connection("ProjectV2Item"))
        }
        (Object("ProjectV2Item"), "id") => None,
        (Object("ProjectV2Item"), "project") => Some(Object("ProjectV2")),
        (Object("ProjectV2"), "id" | "title") => None,
        (Object("ProjectV2Item"), "fieldValueByName") => {
            valid = args.object().is_some_and(|fields| fields.len() == 1)
                && args.unique("name").and_then(Json::string) == Some("Status");
            Some(Object("ProjectV2ItemFieldValue"))
        }
        (Object("ProjectV2ItemFieldSingleSelectValue"), "optionId" | "name") => None,
        (
            Object("PullRequest"),
            "id"
            | "number"
            | "title"
            | "body"
            | "state"
            | "url"
            | "createdAt"
            | "updatedAt"
            | "isDraft"
            | "maintainerCanModify"
            | "mergeable"
            | "additions"
            | "deletions"
            | "baseRefName"
            | "headRefName"
            | "isCrossRepository",
        ) => None,
        (Object("PullRequest"), "repository") => Some(Context::Repository),
        (Object("PullRequest"), "headRepository") => {
            related = Some(EffectKind::ReadRelatedSummaries);
            Some(Object("RelatedRepository"))
        }
        (Object("PullRequest"), "headRepositoryOwner") => {
            related = Some(EffectKind::ReadRelatedSummaries);
            Some(Object("RepositoryOwner"))
        }
        (Object("PullRequest"), "autoMergeRequest") => Some(Object("AutoMergeRequest")),
        (
            Object("AutoMergeRequest"),
            "authorEmail" | "commitBody" | "commitHeadline" | "mergeMethod" | "enabledAt",
        ) => None,
        (Object("AutoMergeRequest"), "enabledBy") => {
            related = Some(EffectKind::ReadRelatedSummaries);
            Some(Object("Actor"))
        }
        (Object("PullRequest"), "reviewRequests") => {
            valid = pagination(args, true);
            related = Some(EffectKind::ReadRelatedSummaries);
            Some(Connection("PullRequestReviewRequest"))
        }
        (Object("PullRequestReviewRequest"), "requestedReviewer") => {
            Some(Object("RequestedReviewer"))
        }
        (Object("Team"), "name" | "slug") => None,
        (Object("Team"), "organization") => Some(Object("RelatedOrganisation")),
        (Object("PullRequest"), "reviews") => {
            valid = pagination(args, true);
            Some(Connection("PullRequestReview"))
        }
        (
            Object("PullRequestReview"),
            "id" | "authorAssociation" | "submittedAt" | "body" | "state",
        ) => None,
        (Object("PullRequestReview"), "commit") => Some(Object("ReviewCommit")),
        (Object("ReviewCommit"), "oid") => None,
        (Object("PullRequest"), "commits") => {
            valid = pagination(args, false);
            Some(Connection("PullRequestCommit"))
        }
        (Object("PullRequestCommit"), "commit") => Some(Object("Commit")),
        (Object("Commit"), "statusCheckRollup") => {
            related = Some(EffectKind::ReadCheckSummaries);
            Some(Object("StatusCheckRollup"))
        }
        (Object("StatusCheckRollup"), "contexts") => {
            valid = pagination(args, true);
            Some(Connection("StatusCheckRollupContext"))
        }
        (
            Object("StatusContext"),
            "context" | "state" | "targetUrl" | "createdAt" | "description",
        ) => None,
        (
            Object("CheckRun"),
            "name" | "status" | "conclusion" | "startedAt" | "completedAt" | "detailsUrl",
        ) => None,
        (Object("CheckRun"), "checkSuite") => Some(Object("CheckSuite")),
        (Object("CheckSuite"), "workflowRun") => Some(Object("WorkflowRun")),
        (Object("WorkflowRun"), "workflow") => Some(Object("Workflow")),
        (Object("Workflow"), "name") => None,
        _ => return None,
    };
    if let Some(effect) = related {
        analysis.effect_graphql(effect, path);
        analysis.resource(Resource::RelatedSummary);
    }
    if !valid {
        unknown(analysis, path, UncoveredReason::Argument);
    }
    Some(child)
}

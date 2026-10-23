use crate::{
    analysis::{Analysis, EffectKind, Repository, Resource, UncoveredReason},
    json::Json,
};

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
            Self::Unknown => "",
        }
    }
}

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
                &["first", "last", "after", "before", "states"],
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
        (Context::Mutation, "closeIssue" | "deleteIssue") => {
            analysis.effect_graphql(
                if name == "closeIssue" {
                    EffectKind::CloseIssue
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
                Some(if name == "closeIssue" {
                    Context::ClosePayload
                } else {
                    Context::DeletePayload
                }),
                &["input"],
            )
        }
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
        _ => {
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

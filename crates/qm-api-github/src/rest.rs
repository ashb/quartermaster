use crate::{
    CapturedRequest,
    analysis::{
        Analysis, AnalysisError, EffectKind, Location, Repository, Resource, UncoveredReason,
    },
    json::Json,
};
use std::collections::BTreeSet;

pub(crate) fn inspect(
    request: &CapturedRequest,
    analysis: &mut Analysis,
    json_depth: usize,
) -> Result<(), AnalysisError> {
    let (path, query) = request
        .path_and_query()
        .split_once('?')
        .unwrap_or((request.path_and_query(), ""));
    if path.contains('%') || path.split('/').any(|part| matches!(part, "." | "..")) {
        analysis.unknown(Location::Target, UncoveredReason::EncodedPath);
        return Ok(());
    }
    let parts: Vec<_> = path.split('/').collect();
    let repository = match parts.as_slice() {
        ["", "repos", owner, name, ..] if valid_name(owner) && valid_name(name) => {
            let repository = Repository {
                owner: (*owner).into(),
                name: (*name).into(),
            };
            analysis.resource(Resource::Repository(repository));
            true
        }
        ["", "repositories", id, ..] if positive_integer(id).is_some() => {
            analysis.resource(Resource::RepositoryId((*id).into()));
            analysis.unknown(Location::Target, UncoveredReason::ResourceOwnership);
            false
        }
        _ => false,
    };
    if !repository {
        analysis.unknown(Location::Target, UncoveredReason::Endpoint);
        return Ok(());
    }
    if let ["issues", number] = &parts[4..]
        && let Some(number) = positive_integer(number).and_then(std::num::NonZeroU64::new)
    {
        analysis.resource(Resource::IssueNumber(number));
    }
    let kind = match (request.method(), &parts[4..]) {
        ("GET", []) => Some(EffectKind::ReadRepository),
        ("DELETE", []) => Some(EffectKind::DeleteRepository),
        ("GET", ["issues"]) => Some(EffectKind::ListIssues),
        ("GET", ["issues", number]) if positive_integer(number).is_some() => {
            Some(EffectKind::ReadIssue)
        }
        ("PATCH", ["issues", number]) if positive_integer(number).is_some() => {
            inspect_close(request, analysis, json_depth)?;
            None
        }
        _ => {
            analysis.unknown(Location::Target, UncoveredReason::Endpoint);
            None
        }
    };
    if let Some(kind) = kind {
        analysis.effect(kind, Location::Target);
    }
    if !request.body().is_empty() && request.method() != "PATCH" {
        analysis.unknown(Location::Body, UncoveredReason::ApplicationData);
    }
    let mut seen = BTreeSet::new();
    if !query.is_empty() {
        for (index, parameter) in query.split('&').enumerate() {
            let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
            if !seen.insert(name) {
                analysis.unknown(Location::Query(index), UncoveredReason::RepeatedInput);
            }
            let known = kind == Some(EffectKind::ListIssues)
                && match name {
                    "state" => matches!(value, "open" | "closed" | "all"),
                    "page" => positive_integer(value).is_some(),
                    "per_page" => positive_integer(value).is_some_and(|n| n <= 100),
                    _ => false,
                };
            if !known {
                analysis.unknown(Location::Query(index), UncoveredReason::QueryParameter);
            }
        }
    }
    Ok(())
}

fn inspect_close(
    request: &CapturedRequest,
    analysis: &mut Analysis,
    json_depth: usize,
) -> Result<(), AnalysisError> {
    crate::json::check_depth(request.body(), json_depth)?;
    let Ok(value) = serde_json::from_slice::<Json>(request.body()) else {
        if request.has_json_grammar() {
            return Err(AnalysisError::InvalidJson);
        }
        analysis.unknown(Location::Body, UncoveredReason::ApplicationData);
        return Ok(());
    };
    let Some(fields) = value.object() else {
        analysis.unknown(Location::Body, UncoveredReason::ApplicationData);
        return Ok(());
    };
    if value.duplicate_members() {
        analysis.unknown(Location::Body, UncoveredReason::RepeatedInput);
    }
    if fields
        .iter()
        .any(|(key, value)| key == "state" && value.string() == Some("closed"))
    {
        analysis.effect(EffectKind::CloseIssue, Location::Body);
    } else {
        analysis.unknown(Location::Body, UncoveredReason::ApplicationData);
    }
    if fields
        .iter()
        .any(|(key, value)| key != "state" || value.string() != Some("closed"))
    {
        analysis.unknown(Location::Body, UncoveredReason::BodyMember);
    }
    Ok(())
}

pub(crate) fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn positive_integer(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok().filter(|value| *value > 0)
}

use crate::{
    CapturedRequest,
    analysis::{
        Analysis, AnalysisError, EffectKind, Location, Repository, Resource, UncoveredReason,
    },
    json::Json,
};
use std::collections::BTreeSet;

#[qm_api_macros::reviewed]
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
        #[api("REST GET /repos/{owner}/{repo}", "5oRtEjt_vvA")]
        ("GET", []) => Some(EffectKind::ReadRepository),
        #[api("REST DELETE /repos/{owner}/{repo}", "lV8OND053e8")]
        ("DELETE", []) => Some(EffectKind::DeleteRepository),
        #[api("REST GET /repos/{owner}/{repo}/issues", "_QySwn1sNTM")]
        ("GET", ["issues"]) => Some(EffectKind::ListIssues),
        #[api("REST GET /repos/{owner}/{repo}/issues/{issue_number}", "gVssCz9GLCc")]
        ("GET", ["issues", number]) if positive_integer(number).is_some() => {
            Some(EffectKind::ReadIssue)
        }
        #[api(
            "REST PATCH /repos/{owner}/{repo}/issues/{issue_number}",
            "KcqMdMcr0w4"
        )]
        ("PATCH", ["issues", number]) if positive_integer(number).is_some() => {
            inspect_close(request, analysis, json_depth)?;
            None
        }
        ("GET", suffix) => match read_endpoint(suffix) {
            Some((kind, resources)) => {
                for resource in resources {
                    analysis.resource(resource);
                }
                Some(kind)
            }
            None => {
                analysis.unknown(Location::Target, UncoveredReason::Endpoint);
                None
            }
        },
        #[api_unrecognised(
            "REST POST /repos/{owner}/{repo}/merges",
            "4serHaXvH4Y",
            "Merge semantics are not modelled"
        )]
        #[api_remainder(
            "REST",
            "OUSIhTaShFY",
            "Remaining REST operations and shared schemas require review when they change"
        )]
        _ => {
            analysis.unknown(Location::Target, UncoveredReason::Endpoint);
            None
        }
    };
    if let Some(kind) = kind {
        analysis.effect(kind, Location::Target);
        if matches!(
            kind,
            EffectKind::ListPullRequests
                | EffectKind::ReadPullRequest
                | EffectKind::ListWorkflowRuns
                | EffectKind::ReadWorkflowRun
        ) {
            analysis.effect(EffectKind::ReadRelatedSummaries, Location::Target);
            analysis.resource(Resource::RelatedSummary);
        }
    }
    if !request.body().is_empty() && request.method() != "PATCH" {
        analysis.unknown(Location::Body, UncoveredReason::ApplicationData);
    }
    let mut seen = BTreeSet::new();
    let mut cursor = false;
    if !query.is_empty() {
        for (index, parameter) in query.split('&').enumerate() {
            let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
            if !seen.insert(name) {
                analysis.unknown(Location::Query(index), UncoveredReason::RepeatedInput);
            }
            let paginated = matches!(
                kind,
                Some(
                    EffectKind::ListIssues
                        | EffectKind::ListPullRequests
                        | EffectKind::ListWorkflows
                        | EffectKind::ListWorkflowRuns
                        | EffectKind::ListWorkflowJobs
                        | EffectKind::ListRunArtifacts
                        | EffectKind::ReadCheckAnnotations
                )
            );
            let known = match name {
                "state"
                    if matches!(
                        kind,
                        Some(EffectKind::ListIssues | EffectKind::ListPullRequests)
                    ) =>
                {
                    matches!(value, "open" | "closed" | "all")
                }
                "page" if paginated => positive_integer(value).is_some(),
                "per_page" if paginated => positive_integer(value).is_some_and(|n| n <= 100),
                "exclude_pull_requests"
                    if matches!(
                        kind,
                        Some(EffectKind::ListWorkflowRuns | EffectKind::ReadWorkflowRun)
                    ) =>
                {
                    matches!(value, "true" | "false")
                }
                "before" | "after" if kind == Some(EffectKind::ListIssues) => {
                    !std::mem::replace(&mut cursor, true) && valid_cursor(parameter)
                }
                _ => false,
            };
            if !known {
                analysis.unknown(Location::Query(index), UncoveredReason::QueryParameter);
            }
        }
    }
    Ok(())
}

#[qm_api_macros::reviewed]
fn read_endpoint(parts: &[&str]) -> Option<(EffectKind, Vec<Resource>)> {
    let id = |value: &str| positive_integer(value).and_then(std::num::NonZeroU64::new);
    let (kind, resources) = match parts {
        #[api("REST GET /repos/{owner}/{repo}/readme", "REexC1UfjUs")]
        ["readme"] => (EffectKind::ReadReadme, vec![]),
        #[api("REST GET /repos/{owner}/{repo}/pulls", "qcomvcmkmLQ")]
        ["pulls"] => (EffectKind::ListPullRequests, vec![]),
        #[api("REST GET /repos/{owner}/{repo}/pulls/{pull_number}", "0Oa4sHxxRpQ")]
        ["pulls", number] => (
            EffectKind::ReadPullRequest,
            vec![Resource::PullRequestNumber(id(number)?)],
        ),
        ["actions", "workflows"] => (EffectKind::ListWorkflows, vec![]),
        ["actions", "workflows", workflow] => (
            EffectKind::ReadWorkflow,
            vec![Resource::Workflow(id(workflow)?)],
        ),
        ["actions", "runs"] => (EffectKind::ListWorkflowRuns, vec![]),
        ["actions", "runs", run, tail @ ..] => {
            let mut resources = vec![Resource::WorkflowRun(id(run)?)];
            let tail = if let ["attempts", attempt, tail @ ..] = tail {
                resources.push(Resource::RunAttempt(id(attempt)?));
                tail
            } else {
                tail
            };
            let kind = match tail {
                [] => EffectKind::ReadWorkflowRun,
                ["jobs"] => EffectKind::ListWorkflowJobs,
                ["logs"] => EffectKind::ReadRunLogs,
                ["artifacts"] if resources.len() == 1 => EffectKind::ListRunArtifacts,
                _ => return None,
            };
            (kind, resources)
        }
        ["actions", "jobs", job] => (
            EffectKind::ReadWorkflowJob,
            vec![Resource::WorkflowJob(id(job)?)],
        ),
        ["actions", "jobs", job, "logs"] => (
            EffectKind::ReadJobLogs,
            vec![Resource::WorkflowJob(id(job)?)],
        ),
        ["check-runs", check, "annotations"] => (
            EffectKind::ReadCheckAnnotations,
            vec![Resource::CheckRun(id(check)?)],
        ),
        _ => return None,
    };
    Some((kind, resources))
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

fn valid_cursor(parameter: &str) -> bool {
    let Some((_, value)) = form_urlencoded::parse(parameter.as_bytes()).next() else {
        return false;
    };
    let unpadded = value.trim_end_matches('=');
    !unpadded.is_empty()
        && value.len() <= 512
        && value.len() - unpadded.len() <= 2
        && unpadded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/-_".contains(&byte))
}

#[cfg(test)]
mod tests {
    use crate::{
        EffectKind, Pattern, PatternSet, Predicate, Repository, Resource, analyze,
        test_support::request,
    };

    #[test]
    fn pull_and_run_representations_require_scope_for_embedded_foreign_metadata() {
        for suffix in [
            "pulls",
            "pulls/42",
            "actions/runs",
            "actions/runs/101",
            "actions/runs/101/attempts/2",
        ] {
            let request = request("GET", &format!("/repos/scope/repository/{suffix}"), "", "");
            let repository = Repository {
                owner: "scope".into(),
                name: "repository".into(),
            };
            let effects = vec![
                EffectKind::ListPullRequests,
                EffectKind::ReadPullRequest,
                EffectKind::ListWorkflowRuns,
                EffectKind::ReadWorkflowRun,
                EffectKind::ReadRelatedSummaries,
            ];
            let patterns = PatternSet::new(vec![
                Pattern {
                    id: "contained".into(),
                    predicates: vec![
                        Predicate::OnlyEffects(effects.clone()),
                        Predicate::AllResourcesInRepository(repository.clone()),
                    ],
                },
                Pattern {
                    id: "related".into(),
                    predicates: vec![
                        Predicate::OnlyEffects(effects),
                        Predicate::AllResourcesInRepositoryWithRelatedSummaries(repository),
                    ],
                },
            ])
            .unwrap();
            let analysis = analyze(&request, &patterns).unwrap();
            assert!(analysis.complete());
            assert!(
                analysis
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::ReadRelatedSummaries)
            );
            assert!(analysis.resources.contains(&Resource::RelatedSummary));
            assert_eq!(
                analysis
                    .matches
                    .iter()
                    .map(|matched| matched.id.as_str())
                    .collect::<Vec<_>>(),
                vec!["related"]
            );
        }
    }

    #[test]
    fn ordinary_gh_rest_reads_report_distinct_effects_and_scoped_identifiers() {
        for (suffix, effect, resources) in [
            ("readme", "ReadReadme", vec![]),
            (
                "pulls?state=open&per_page=20&page=2",
                "ListPullRequests",
                vec![],
            ),
            ("pulls/42", "ReadPullRequest", vec!["PullRequestNumber(42)"]),
            (
                "actions/runs?exclude_pull_requests=true&per_page=20&page=2",
                "ListWorkflowRuns",
                vec![],
            ),
            (
                "actions/runs/101?exclude_pull_requests=true",
                "ReadWorkflowRun",
                vec!["WorkflowRun(101)"],
            ),
            (
                "actions/runs/101/attempts/2?exclude_pull_requests=true",
                "ReadWorkflowRun",
                vec!["WorkflowRun(101)", "RunAttempt(2)"],
            ),
            (
                "actions/workflows?per_page=100&page=1",
                "ListWorkflows",
                vec![],
            ),
            (
                "actions/workflows/201",
                "ReadWorkflow",
                vec!["Workflow(201)"],
            ),
            (
                "actions/runs/101/jobs?per_page=100",
                "ListWorkflowJobs",
                vec!["WorkflowRun(101)"],
            ),
            (
                "actions/runs/101/attempts/2/jobs?per_page=100",
                "ListWorkflowJobs",
                vec!["WorkflowRun(101)", "RunAttempt(2)"],
            ),
            (
                "actions/jobs/301",
                "ReadWorkflowJob",
                vec!["WorkflowJob(301)"],
            ),
            (
                "actions/runs/101/artifacts?per_page=100",
                "ListRunArtifacts",
                vec!["WorkflowRun(101)"],
            ),
            (
                "check-runs/401/annotations",
                "ReadCheckAnnotations",
                vec!["CheckRun(401)"],
            ),
            (
                "actions/runs/101/logs",
                "ReadRunLogs",
                vec!["WorkflowRun(101)"],
            ),
            (
                "actions/runs/101/attempts/2/logs",
                "ReadRunLogs",
                vec!["WorkflowRun(101)", "RunAttempt(2)"],
            ),
            (
                "actions/jobs/301/logs",
                "ReadJobLogs",
                vec!["WorkflowJob(301)"],
            ),
        ] {
            let request = request("GET", &format!("/repos/fixture/demo/{suffix}"), "", "");
            let analysis = analyze(&request, &PatternSet::default()).unwrap();
            assert!(analysis.complete(), "{suffix}: {:?}", analysis.uncovered);
            assert!(
                analysis
                    .effects
                    .iter()
                    .skip(1)
                    .all(|effect| effect.kind == crate::EffectKind::ReadRelatedSummaries),
                "{suffix}"
            );
            assert_eq!(
                format!("{:?}", analysis.effects[0].kind),
                effect,
                "{suffix}"
            );
            assert_eq!(
                analysis
                    .resources
                    .iter()
                    .skip(1)
                    .filter(|resource| **resource != crate::Resource::RelatedSummary)
                    .map(|resource| format!("{resource:?}"))
                    .collect::<Vec<_>>(),
                resources,
                "{suffix}"
            );
        }
    }

    #[test]
    fn actions_reads_do_not_cover_writes_artifact_downloads_or_unknown_parameters() {
        for suffix in [
            "actions/runs/101/rerun",
            "actions/runs/101/cancel",
            "actions/artifacts/501/zip",
            "contents/private.txt",
            "readme?ref=other",
            "actions/runs/0",
            "actions/jobs/0/logs",
            "actions/runs/101/attempts/0/logs",
            "actions/runs/101/attempts/2/logs/extra",
            "actions/runs/%31/logs",
            "actions/runs/101/logs?url=https://outside.invalid",
            "actions/runs/101/jobs?per_page=101",
            "actions/runs?page=0",
            "actions/runs?per_page=1&per_page=2",
            "actions/runs?exclude_pull_requests=maybe",
            "actions/runs?exclude_pull_requests=true&future=1",
            "actions/jobs/301?run_id=101",
            "check-runs/401/annotations?future=1",
        ] {
            let request = request("GET", &format!("/repos/fixture/demo/{suffix}"), "", "");
            assert!(
                !analyze(&request, &PatternSet::default())
                    .unwrap()
                    .complete(),
                "{suffix}"
            );
        }
        for method in ["POST", "PATCH", "PUT", "DELETE"] {
            let request = request(method, "/repos/fixture/demo/actions/runs/101/logs", "", "");
            assert!(
                !analyze(&request, &PatternSet::default())
                    .unwrap()
                    .complete(),
                "{method}"
            );
        }
    }

    #[test]
    fn issue_pagination_recognizes_one_bounded_cursor_without_changing_its_bytes() {
        for cursor in ["after=abc%2Bdef%2Fghi%3D%3D", "before=opaque_cursor-123"] {
            let target = format!("/repos/a/b/issues?{cursor}&per_page=10");
            let request = request("GET", &target, "", "");
            assert!(
                analyze(&request, &PatternSet::default())
                    .unwrap()
                    .complete()
            );
            assert_eq!(request.path_and_query(), target);
        }
        for cursor in [
            "after=",
            "after=abc&before=def",
            "after=abc&after=def",
            "after=abc+def",
            "after=%26page%3D2",
        ] {
            let request = request("GET", &format!("/repos/a/b/issues?{cursor}"), "", "");
            assert!(
                !analyze(&request, &PatternSet::default())
                    .unwrap()
                    .complete()
            );
        }
    }
}

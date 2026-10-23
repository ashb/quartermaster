use crate::CapturedRequest;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Repository {
    pub owner: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    Repository(Repository),
    RepositoryId(String),
    NodeId(String),
    IssueNumber(std::num::NonZeroU64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectKind {
    ReadRepository,
    ListIssues,
    ReadIssue,
    CloseIssue,
    DeleteIssue,
    DeleteRepository,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    Target,
    Header(usize),
    Query(usize),
    Body,
    Graphql(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effect {
    pub kind: EffectKind,
    pub location: Location,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphqlOperation {
    Query,
    Mutation,
    Subscription,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UncoveredReason {
    Endpoint,
    Header,
    ApiVersion,
    MediaType,
    EncodedPath,
    QueryParameter,
    RepeatedInput,
    BodyMember,
    ApplicationData,
    Field,
    Argument,
    Directive,
    Variable,
    ResourceOwnership,
    Schema,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uncovered {
    pub location: Location,
    pub reason: UncoveredReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Predicate {
    Method(String),
    Path(String),
    Effect(EffectKind),
    /// Explicit universal coverage, required for a complete positive match.
    OnlyEffects(Vec<EffectKind>),
    GraphqlRoot {
        operation: GraphqlOperation,
        field: String,
    },
    /// Matches only complete resource coverage; ownership still needs a trusted mapping.
    AllResourcesInRepository(Repository),
}

#[derive(Clone, Debug)]
pub struct Pattern {
    pub id: String,
    pub predicates: Vec<Predicate>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("patterns require unique nonempty identifiers and nonempty predicates")]
pub struct PatternError;

#[derive(Default)]
pub struct PatternSet(Vec<Pattern>);

impl PatternSet {
    pub fn new(patterns: Vec<Pattern>) -> Result<Self, PatternError> {
        let mut ids = BTreeSet::new();
        if patterns.iter().any(|pattern| {
            pattern.id.is_empty() || pattern.predicates.is_empty() || !ids.insert(&pattern.id)
                || pattern.predicates.iter().any(|predicate| matches!(predicate, Predicate::OnlyEffects(kinds) if kinds.is_empty()))
        }) {
            return Err(PatternError);
        }
        Ok(Self(patterns))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternMatch {
    pub id: String,
    /// Complete input and universal effect coverage; never execution authority.
    pub complete: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct AnalysisLimits {
    pub json_depth: usize,
    pub graphql_tokens: usize,
    pub graphql_depth: usize,
    pub expanded_selections: usize,
    pub expanded_value_bytes: usize,
    pub output_bytes: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            json_depth: 64,
            graphql_tokens: 16000,
            graphql_depth: 32,
            expanded_selections: 4096,
            expanded_value_bytes: 1048576,
            output_bytes: 1048576,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnalysisError {
    #[error("analysis resource limit exceeded")]
    Limit,
    #[error("invalid GraphQL document")]
    InvalidGraphql,
    #[error("invalid JSON for the recognized application grammar")]
    InvalidJson,
    #[error("GraphQL operation selection is ambiguous or missing")]
    OperationSelection,
    #[error("GraphQL fragments contain a cycle or missing reference")]
    Fragment,
}

#[derive(Debug)]
pub struct Analysis {
    pub effects: Vec<Effect>,
    pub resources: Vec<Resource>,
    pub graphql_roots: Vec<(GraphqlOperation, String)>,
    pub uncovered: Vec<Uncovered>,
    pub matches: Vec<PatternMatch>,
    remaining_output: usize,
    pub(crate) exhausted: bool,
}

impl Analysis {
    fn new(output_bytes: usize) -> Self {
        Self {
            effects: Vec::new(),
            resources: Vec::new(),
            graphql_roots: Vec::new(),
            uncovered: Vec::new(),
            matches: Vec::new(),
            remaining_output: output_bytes,
            exhausted: false,
        }
    }

    fn reserve(&mut self, bytes: usize) -> bool {
        if self.exhausted {
            return false;
        }
        if let Some(remaining) = self.remaining_output.checked_sub(bytes) {
            self.remaining_output = remaining;
            true
        } else {
            self.exhausted = true;
            false
        }
    }

    pub fn complete(&self) -> bool {
        !self.exhausted && self.uncovered.is_empty()
    }

    pub(crate) fn unknown(&mut self, location: Location, reason: UncoveredReason) {
        if self.reserve(std::mem::size_of::<Uncovered>()) {
            self.uncovered.push(Uncovered { location, reason });
        }
    }

    pub(crate) fn effect(&mut self, kind: EffectKind, location: Location) {
        if self.reserve(std::mem::size_of::<Effect>()) {
            self.effects.push(Effect { kind, location });
        }
    }

    pub(crate) fn unknown_graphql(&mut self, path: &[String], reason: UncoveredReason) {
        if self.reserve(std::mem::size_of::<Uncovered>().saturating_add(path_bytes(path))) {
            self.uncovered.push(Uncovered {
                location: Location::Graphql(path.to_vec()),
                reason,
            });
        }
    }

    pub(crate) fn effect_graphql(&mut self, kind: EffectKind, path: &[String]) {
        if self.reserve(std::mem::size_of::<Effect>().saturating_add(path_bytes(path))) {
            self.effects.push(Effect {
                kind,
                location: Location::Graphql(path.to_vec()),
            });
        }
    }

    pub(crate) fn resource(&mut self, resource: Resource) {
        let bytes = match &resource {
            Resource::Repository(repository) => {
                repository.owner.len().saturating_add(repository.name.len())
            }
            Resource::RepositoryId(id) | Resource::NodeId(id) => id.len(),
            Resource::IssueNumber(_) => 0,
        };
        if self.reserve(std::mem::size_of::<Resource>().saturating_add(bytes)) {
            self.resources.push(resource);
        }
    }

    pub(crate) fn root(&mut self, kind: GraphqlOperation, name: &str) {
        if self
            .reserve(std::mem::size_of::<(GraphqlOperation, String)>().saturating_add(name.len()))
        {
            self.graphql_roots.push((kind, name.into()));
        }
    }
}

pub(crate) fn path_bytes(path: &[String]) -> usize {
    path.iter().fold(0usize, |size, part| {
        size.saturating_add(std::mem::size_of::<String>())
            .saturating_add(part.len())
    })
}

pub fn analyze(
    request: &CapturedRequest,
    patterns: &PatternSet,
) -> Result<Analysis, AnalysisError> {
    analyze_with_limits(request, patterns, AnalysisLimits::default())
}

pub fn analyze_with_limits(
    request: &CapturedRequest,
    patterns: &PatternSet,
    limits: AnalysisLimits,
) -> Result<Analysis, AnalysisError> {
    let mut analysis = Analysis::new(limits.output_bytes);
    inspect_headers(request, &mut analysis);
    if request.path_and_query().split('?').next() == Some("/graphql") {
        crate::graphql::inspect(request, &mut analysis, limits)?;
    } else {
        crate::rest::inspect(request, &mut analysis, limits.json_depth)?;
    }
    if analysis.exhausted {
        return Err(AnalysisError::Limit);
    }
    let path = request.path_and_query().split('?').next().unwrap_or("");
    for pattern in &patterns.0 {
        if pattern.predicates.iter().all(|predicate| match predicate {
            Predicate::Method(method) => request.method() == method,
            Predicate::Path(expected) => path == expected,
            Predicate::Effect(kind) => analysis.effects.iter().any(|effect| effect.kind == *kind),
            Predicate::OnlyEffects(kinds) => {
                analysis.complete()
                    && !analysis.effects.is_empty()
                    && analysis
                        .effects
                        .iter()
                        .all(|effect| kinds.contains(&effect.kind))
            }
            Predicate::GraphqlRoot { operation, field } => analysis
                .graphql_roots
                .iter()
                .any(|(kind, name)| kind == operation && name == field),
            Predicate::AllResourcesInRepository(expected) => {
                analysis.complete()
                    && !analysis.resources.is_empty()
                    && analysis
                        .resources
                        .iter()
                        .any(|resource| matches!(resource, Resource::Repository(_)))
                    && analysis.resources.iter().all(|resource| match resource {
                        Resource::Repository(repository) => repository == expected,
                        Resource::IssueNumber(_) => true,
                        Resource::RepositoryId(_) | Resource::NodeId(_) => false,
                    })
            }
        }) {
            let complete = analysis.complete()
                && pattern
                    .predicates
                    .iter()
                    .any(|predicate| matches!(predicate, Predicate::OnlyEffects(_)));
            if analysis
                .reserve(std::mem::size_of::<PatternMatch>().saturating_add(pattern.id.len()))
            {
                analysis.matches.push(PatternMatch {
                    id: pattern.id.clone(),
                    complete,
                });
            }
        }
    }
    if analysis.exhausted {
        Err(AnalysisError::Limit)
    } else {
        Ok(analysis)
    }
}

fn inspect_headers(request: &CapturedRequest, analysis: &mut Analysis) {
    let mut seen = BTreeSet::new();
    for (index, header) in request.headers().iter().enumerate() {
        let name = header.name().to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            analysis.unknown(Location::Header(index), UncoveredReason::RepeatedInput);
        }
        let value = std::str::from_utf8(header.value()).unwrap_or("");
        let reason = match name.as_str() {
            "host" | "content-length" | "authorization" | "connection" | "keep-alive"
            | "user-agent" => None,
            "accept" if matches!(value, "application/vnd.github+json" | "application/json") => None,
            "accept" => Some(UncoveredReason::MediaType),
            "content-type"
                if matches!(
                    value.to_ascii_lowercase().as_str(),
                    "application/json" | "application/json; charset=utf-8"
                ) =>
            {
                None
            }
            "content-type" => Some(UncoveredReason::MediaType),
            "x-github-api-version" if value == "2022-11-28" => None,
            "x-github-api-version" => Some(UncoveredReason::ApiVersion),
            _ => Some(UncoveredReason::Header),
        };
        if let Some(reason) = reason {
            analysis.unknown(Location::Header(index), reason);
        }
    }
    if !seen.contains("x-github-api-version") {
        analysis.unknown(Location::Target, UncoveredReason::ApiVersion);
    }
    if !seen.contains("accept") || (!request.body().is_empty() && !seen.contains("content-type")) {
        analysis.unknown(Location::Target, UncoveredReason::MediaType);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{raw_request, request};
    use hegel::{TestCase, generators as gs};

    #[hegel::test(test_cases = 500, database = None, derandomize = false)]
    fn rest_restrictions_survive_unknown_and_duplicate_companion_inputs(tc: TestCase) {
        let close = tc.draw(gs::booleans());
        let unknown_body = tc.draw(gs::booleans());
        let duplicate_state = close && tc.draw(gs::booleans());
        let unknown_header = tc.draw(gs::booleans());
        let unknown_query = tc.draw(gs::booleans());
        let unknown_version = tc.draw(gs::booleans());
        let escaped = tc.draw(gs::booleans());
        let reverse = tc.draw(gs::booleans());
        let owner = format!("owner{}", tc.draw(gs::integers::<u8>().max_value(3)));
        let name = format!("repo{}", tc.draw(gs::integers::<u8>().max_value(3)));
        let (method, effect) = if close {
            ("PATCH", EffectKind::CloseIssue)
        } else {
            ("DELETE", EffectKind::DeleteRepository)
        };
        let mut target = format!("/repos/{owner}/{name}");
        if close {
            target.push_str(&format!(
                "/issues/{}",
                tc.draw(gs::integers::<u16>().min_value(1).max_value(1000))
            ));
        }
        if unknown_query {
            target.push_str("?future=%2F&future=other");
        }
        let mut members = Vec::new();
        if close {
            members.push(if escaped {
                r#""st\u0061te":"cl\u006fsed""#
            } else {
                r#""state":"closed""#
            });
        }
        if duplicate_state {
            members.push(r#""state":"open""#);
        }
        if unknown_body {
            members.push(r#""future":{"mode":"different"}"#);
        }
        if reverse {
            members.reverse();
        }
        let body = if members.is_empty() {
            String::new()
        } else {
            format!("{{ {} }}", members.join(" ,\n "))
        };
        let headers = if unknown_header {
            "Content-Type: application/json\r\nX-Future: first\r\nx-future: second\r\n"
        } else {
            "Content-Type: application/json\r\n"
        };
        let mut raw = raw_request(method, &target, headers, &body);
        if unknown_version {
            raw = raw.replace(
                "X-GitHub-Api-Version: 2022-11-28",
                "X-GitHub-Api-Version: 2099-01-01",
            );
        }
        tc.note(&raw);
        let captured =
            CapturedRequest::parse(raw.as_bytes(), crate::RequestLimits::default()).unwrap();
        let patterns = PatternSet::new(vec![
            Pattern {
                id: "restriction".into(),
                predicates: vec![Predicate::Effect(effect)],
            },
            Pattern {
                id: "complete".into(),
                predicates: vec![
                    Predicate::OnlyEffects(vec![effect]),
                    Predicate::AllResourcesInRepository(Repository { owner, name }),
                ],
            },
        ])
        .unwrap();
        let analysis = analyze(&captured, &patterns).unwrap();
        let complete = !(unknown_body
            || duplicate_state
            || unknown_header
            || unknown_query
            || unknown_version);
        assert!(
            analysis
                .effects
                .iter()
                .any(|observed| observed.kind == effect)
        );
        assert!(
            analysis
                .matches
                .iter()
                .any(|matched| matched.id == "restriction")
        );
        assert_eq!(
            analysis
                .matches
                .iter()
                .any(|matched| matched.id == "complete" && matched.complete),
            complete
        );
        assert_eq!(analysis.complete(), complete);
        assert_eq!(captured.original(), raw.as_bytes());
        assert_eq!(captured.body(), body.as_bytes());
    }

    fn patterns() -> PatternSet {
        PatternSet::new(vec![
            Pattern {
                id: "read".into(),
                predicates: vec![
                    Predicate::Effect(EffectKind::ListIssues),
                    Predicate::OnlyEffects(vec![EffectKind::ListIssues]),
                    Predicate::AllResourcesInRepository(Repository {
                        owner: "ashb".into(),
                        name: "reviewq".into(),
                    }),
                ],
            },
            Pattern {
                id: "forbidden".into(),
                predicates: vec![Predicate::Effect(EffectKind::DeleteIssue)],
            },
        ])
        .unwrap()
    }

    #[test]
    fn known_rest_reads_require_complete_input_coverage() {
        let captured = request(
            "GET",
            "/repos/ashb/reviewq/issues?state=open&per_page=30",
            "",
            "",
        );
        let analysis = analyze(&captured, &patterns()).unwrap();
        assert!(analysis.complete());
        assert_eq!(
            analysis.effects,
            vec![Effect {
                kind: EffectKind::ListIssues,
                location: Location::Target
            }]
        );
        assert_eq!(
            analysis.matches,
            vec![PatternMatch {
                id: "read".into(),
                complete: true
            }]
        );
        for (target, headers, body) in [
            ("/repos/ashb/reviewq/issues?new_feature=yes", "", ""),
            ("/repos/ashb/reviewq/issues?state=open&state=closed", "", ""),
            ("/repos/ashb/reviewq/issues", "X-New: yes\r\n", ""),
            ("/repos/ashb/reviewq/issues", "", "{\"extra\":true}"),
        ] {
            let captured = request("GET", target, headers, body);
            let analysis = analyze(&captured, &patterns()).unwrap();
            assert!(!analysis.complete());
            assert!(analysis.matches.iter().all(|matched| !matched.complete));
        }
    }

    #[test]
    fn unfamiliar_endpoints_versions_encodings_and_repeated_headers_stay_reviewable() {
        for (target, extra) in [
            ("/new-api", ""),
            (
                "/repos/ashb/reviewq/issues",
                "Accept: application/new-format\r\n",
            ),
            (
                "/repos/ashb/reviewq/issues",
                "X-GitHub-Api-Version: 2099-01-01\r\n",
            ),
            ("/repos/ashb%2Freviewq/issues", ""),
            ("/repos/ashb/reviewq/issues", "X-New: one\r\nX-New: two\r\n"),
        ] {
            let captured = request("GET", target, extra, "");
            let original = captured.original().to_vec();
            let analysis = analyze(&captured, &patterns()).unwrap();
            assert!(!analysis.complete());
            assert_eq!(captured.original(), original);
        }
    }

    #[test]
    fn opaque_request_bodies_do_not_consume_the_json_depth_budget() {
        let body = "[".repeat(65);
        for (method, target, headers) in [
            ("POST", "/future", "Content-Type: text/plain\r\n"),
            (
                "POST",
                "/repos/ashb/reviewq/future",
                "Content-Type: application/octet-stream\r\n",
            ),
            (
                "GET",
                "/repos/ashb/reviewq/issues",
                "Content-Type: text/plain\r\n",
            ),
        ] {
            let captured = request(method, target, headers, &body);
            let analysis = analyze(&captured, &patterns()).unwrap();
            assert!(!analysis.complete());
            assert!(analysis.matches.iter().all(|matched| !matched.complete));
            assert_eq!(captured.body(), body.as_bytes());
        }
    }

    #[test]
    fn json_inspection_enforces_the_configured_depth_limit() {
        for (method, target, body) in [
            (
                "PATCH",
                "/repos/ashb/reviewq/issues/42",
                r#"{"state":"closed"}"#,
            ),
            ("POST", "/graphql", r#"{"query":"{__typename}"}"#),
        ] {
            let captured = request(method, target, "Content-Type: application/json\r\n", body);
            let limits = AnalysisLimits {
                json_depth: 1,
                ..AnalysisLimits::default()
            };
            assert!(
                analyze_with_limits(&captured, &PatternSet::default(), limits)
                    .unwrap()
                    .complete()
            );
            assert_eq!(
                analyze_with_limits(
                    &captured,
                    &PatternSet::default(),
                    AnalysisLimits {
                        json_depth: 0,
                        ..limits
                    }
                )
                .unwrap_err(),
                AnalysisError::Limit
            );
        }
    }

    #[test]
    fn generic_method_and_exact_path_patterns_are_observations_without_implicit_permission() {
        let patterns = PatternSet::new(vec![Pattern {
            id: "raw-path".into(),
            predicates: vec![
                Predicate::Method("PATCH".into()),
                Predicate::Path("/repos/ashb/reviewq/issues/42".into()),
            ],
        }])
        .unwrap();
        let captured = request(
            "PATCH",
            "/repos/ashb/reviewq/issues/42",
            "Content-Type: application/json\r\n",
            r#"{"state":"closed","future":true}"#,
        );
        let analysis = analyze(&captured, &patterns).unwrap();
        assert!(
            analysis
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::CloseIssue)
        );
        assert_eq!(
            analysis.matches,
            vec![PatternMatch {
                id: "raw-path".into(),
                complete: false
            }]
        );
    }

    #[test]
    fn duplicate_json_members_and_unknown_siblings_cannot_hide_a_forbidden_effect() {
        let body = r#"{"query":"mutation { deleteIssue(input:{issueId:\"opaque\"}) { clientMutationId } futureOperation }","variables":{},"future":true}"#;
        let captured = request(
            "POST",
            "/graphql",
            "Content-Type: application/json\r\n",
            body,
        );
        let analysis = analyze(&captured, &patterns()).unwrap();
        assert!(!analysis.complete());
        assert!(
            analysis
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::DeleteIssue)
        );
        assert_eq!(
            analysis.matches,
            vec![PatternMatch {
                id: "forbidden".into(),
                complete: false
            }]
        );
        let captured = request(
            "PATCH",
            "/repos/ashb/reviewq/issues/42",
            "Content-Type: application/json\r\n",
            r#"{"state":"open","state":"closed"}"#,
        );
        let analysis = analyze(&captured, &patterns()).unwrap();
        assert!(!analysis.complete());
        assert!(
            analysis
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::CloseIssue)
        );
    }

    #[test]
    fn protocol_fixtures_have_independently_specified_effects_and_references() {
        for (bytes, kind, issue) in [
            (
                include_bytes!("../tests/fixtures/list-issues.http").as_slice(),
                EffectKind::ListIssues,
                false,
            ),
            (
                include_bytes!("../tests/fixtures/read-issue.http").as_slice(),
                EffectKind::ReadIssue,
                true,
            ),
            (
                include_bytes!("../tests/fixtures/close-issue.http").as_slice(),
                EffectKind::CloseIssue,
                true,
            ),
        ] {
            let captured = CapturedRequest::parse(bytes, crate::RequestLimits::default()).unwrap();
            let analysis = analyze(&captured, &PatternSet::default()).unwrap();
            assert!(analysis.complete());
            assert_eq!(analysis.effects.len(), 1);
            assert_eq!(analysis.effects[0].kind, kind);
            let mut expected = vec![Resource::Repository(Repository {
                owner: "ashb".into(),
                name: "reviewq".into(),
            })];
            if issue {
                expected.push(Resource::IssueNumber(
                    std::num::NonZeroU64::new(42).unwrap(),
                ));
            }
            assert_eq!(analysis.resources, expected);
            assert_eq!(captured.original(), bytes);
        }
    }

    #[test]
    fn complete_matching_requires_explicit_coverage_of_every_known_effect() {
        let captured = crate::test_support::graphql(
            r#"{ repository(owner:"ashb",name:"reviewq") { issues(first:10) { nodes {title} } } }"#,
            serde_json::json!({}),
            None,
        );
        let patterns = PatternSet::new(vec![
            Pattern {
                id: "observation".into(),
                predicates: vec![Predicate::Effect(EffectKind::ReadRepository)],
            },
            Pattern {
                id: "metadata-only".into(),
                predicates: vec![Predicate::OnlyEffects(vec![EffectKind::ReadRepository])],
            },
            Pattern {
                id: "all-reads".into(),
                predicates: vec![Predicate::OnlyEffects(vec![
                    EffectKind::ReadRepository,
                    EffectKind::ListIssues,
                ])],
            },
        ])
        .unwrap();
        let analysis = analyze(&captured, &patterns).unwrap();
        assert_eq!(
            analysis.matches,
            vec![
                PatternMatch {
                    id: "observation".into(),
                    complete: false
                },
                PatternMatch {
                    id: "all-reads".into(),
                    complete: true
                }
            ]
        );
        let captured = crate::test_support::graphql(
            r#"{ repository(owner:"ashb",name:"reviewq") { futureField } }"#,
            serde_json::json!({}),
            None,
        );
        let analysis = analyze(&captured, &patterns).unwrap();
        assert_eq!(
            analysis.matches,
            vec![PatternMatch {
                id: "observation".into(),
                complete: false
            }]
        );
    }

    #[test]
    fn invalid_patterns_are_policy_errors() {
        for patterns in [
            vec![Pattern {
                id: "".into(),
                predicates: vec![Predicate::Method("GET".into())],
            }],
            vec![Pattern {
                id: "empty".into(),
                predicates: vec![],
            }],
            vec![Pattern {
                id: "empty-effects".into(),
                predicates: vec![Predicate::OnlyEffects(vec![])],
            }],
            vec![
                Pattern {
                    id: "duplicate".into(),
                    predicates: vec![Predicate::Method("GET".into())],
                },
                Pattern {
                    id: "duplicate".into(),
                    predicates: vec![Predicate::Method("POST".into())],
                },
            ],
        ] {
            assert!(PatternSet::new(patterns).is_err());
        }
    }

    #[test]
    fn invalid_json_on_a_recognized_close_route_is_an_analysis_failure() {
        for body in [
            r#"{"state":"closed","future":"\uD800"}"#,
            r#"{"state":"closed","future":[}"#,
        ] {
            let captured = request(
                "PATCH",
                "/repos/ashb/reviewq/issues/42",
                "Content-Type: application/json\r\n",
                body,
            );
            assert_eq!(
                analyze(&captured, &PatternSet::default()).unwrap_err(),
                AnalysisError::InvalidJson
            );
        }
    }
}

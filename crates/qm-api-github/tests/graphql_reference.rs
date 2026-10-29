mod reference_cases;

use hegel::TestCase;
use qm_api_github::{
    CapturedRequest, EffectKind, Location, Pattern, PatternSet, Predicate, Repository,
    RequestLimits, Resource, analyze,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

#[derive(Debug, Deserialize)]
struct ExecutedEffect {
    kind: String,
    path: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Execution {
    effects: Vec<ExecutedEffect>,
    resources: Vec<String>,
    roots: Vec<(String, String)>,
    unfamiliar: bool,
    errors: Vec<String>,
}

struct ReferenceExecutor {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl ReferenceExecutor {
    fn new() -> Self {
        let mut child = Command::new(std::env::var_os("QM_REFERENCE_NODE").unwrap())
            .arg(std::env::var_os("QM_REFERENCE_EXECUTOR").unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        Self {
            input: child.stdin.take().unwrap(),
            output: BufReader::new(child.stdout.take().unwrap()),
            child,
        }
    }

    fn execute(&mut self, requests: &[Value]) -> Vec<Execution> {
        self.input
            .write_all(&serde_json::to_vec(requests).unwrap())
            .unwrap();
        self.input.write_all(b"\n").unwrap();
        let mut line = String::new();
        assert_ne!(
            self.output.read_line(&mut line).unwrap(),
            0,
            "reference exited before replying"
        );
        let results: Vec<Execution> = serde_json::from_str(&line).unwrap();
        assert_eq!(results.len(), requests.len());
        results
    }
}

impl Drop for ReferenceExecutor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn execute(requests: &[Value]) -> Vec<Execution> {
    thread_local! {
        static EXECUTOR: RefCell<ReferenceExecutor> = RefCell::new(ReferenceExecutor::new());
    }
    EXECUTOR.with_borrow_mut(|executor| executor.execute(requests))
}

fn capture(body: &Value) -> CapturedRequest {
    let body = body.to_string();
    let raw = format!(
        "POST /graphql HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    CapturedRequest::parse(raw.as_bytes(), RequestLimits::default()).unwrap()
}

fn read_patterns() -> PatternSet {
    PatternSet::new(vec![
        Pattern {
            id: "reads".into(),
            predicates: vec![Predicate::OnlyEffects(vec![
                EffectKind::ReadRepository,
                EffectKind::ReadIssue,
                EffectKind::ListIssues,
            ])],
        },
        Pattern {
            id: "scope".into(),
            predicates: vec![
                Predicate::OnlyEffects(vec![
                    EffectKind::ReadRepository,
                    EffectKind::ReadIssue,
                    EffectKind::ListIssues,
                ]),
                Predicate::AllResourcesInRepository(Repository {
                    owner: "scope".into(),
                    name: "repository".into(),
                }),
            ],
        },
    ])
    .unwrap()
}

fn assert_execution(request: &Value, executed: Execution) {
    assert!(
        executed.errors.is_empty(),
        "reference rejected {request}: {:?}",
        executed.errors
    );
    let captured = capture(request);
    let original = captured.original().to_vec();
    let analysis = analyze(&captured, &read_patterns()).unwrap();
    let expected_effects: BTreeSet<_> = executed
        .effects
        .into_iter()
        .map(|effect| (effect.kind, effect.path))
        .collect();
    let observed_effects: BTreeSet<_> = analysis
        .effects
        .iter()
        .map(|effect| {
            let Location::Graphql(path) = &effect.location else {
                panic!("unexpected location");
            };
            (format!("{:?}", effect.kind), path.clone())
        })
        .collect();
    assert_eq!(observed_effects, expected_effects, "{request}");
    let expected_resources: BTreeSet<_> = executed.resources.into_iter().collect();
    let observed_resources: BTreeSet<_> = analysis
        .resources
        .iter()
        .map(|resource| match resource {
            Resource::Repository(repository) => {
                format!("repository:{}/{}", repository.owner, repository.name)
            }
            Resource::IssueNumber(number) => format!("issue:{number}"),
            Resource::NodeId(id) => format!("node:{id}"),
            Resource::RepositoryId(id) => panic!("unexpected repository id {id}"),
        })
        .collect();
    assert_eq!(observed_resources, expected_resources, "{request}");
    let observed_roots: BTreeSet<_> = analysis
        .graphql_roots
        .iter()
        .map(|(operation, name)| (format!("{operation:?}"), name.clone()))
        .collect();
    assert_eq!(
        observed_roots,
        executed.roots.into_iter().collect(),
        "{request}"
    );
    let mutating = expected_effects
        .iter()
        .any(|(kind, _)| matches!(kind.as_str(), "CloseIssue" | "DeleteIssue"));
    let complete = !mutating && !executed.unfamiliar;
    assert_eq!(analysis.complete(), complete, "{request}");
    let reads = complete && !expected_effects.is_empty() && !mutating;
    let scoped = reads
        && expected_resources.iter().all(|resource| {
            !resource.starts_with("repository:") || resource == "repository:scope/repository"
        });
    for (id, expected) in [("reads", reads), ("scope", scoped)] {
        assert_eq!(
            analysis
                .matches
                .iter()
                .any(|matched| matched.id == id && matched.complete),
            expected,
            "{id}: {request}"
        );
    }
    assert_eq!(captured.original(), original);
    assert_eq!(captured.body(), request.to_string().as_bytes());
}

#[test]
fn classifications_agree_with_reference_execution() {
    let mut requests = Vec::new();
    for default in [false, true] {
        for supplied in [None, Some(false), Some(true)] {
            for form in 0..4 {
                for guard in [
                    "@include(if:$go)",
                    "@skip(if:$go)",
                    "@include(if:true) @skip(if:$go)",
                    "@include(if:$go) @skip(if:false)",
                ] {
                    for foreign in [false, true] {
                        for unfamiliar in [false, true] {
                            let string = match form {
                                0 | 1 => "\"scope\"",
                                2 => "\"sc\\u006fpe\"",
                                _ => "\"\"\"\n  scope\n\"\"\"",
                            };
                            let fields = format!(
                                "name {} first:issue(number:42){{title repository{{name issue(number:7){{number}}}}}} issues(first:2,states:[OPEN,CLOSED]){{nodes{{title}} edges{{node{{number}}}} pageInfo{{hasNextPage}} totalCount}}",
                                if unfamiliar { "future" } else { "" }
                            );
                            let (selection, fragments) = match form {
                                0 => (fields, String::new()),
                                1 => (
                                    "...Data ...Data".into(),
                                    format!("fragment Data on Repository{{{fields}}}"),
                                ),
                                2 => (format!("..., on Repository,{{{fields}}}"), String::new()),
                                _ => (
                                    "...Outer".into(),
                                    format!(
                                        "fragment Inner on Repository{{{fields}}} fragment Outer on Repository{{...Inner}}"
                                    ),
                                ),
                            };
                            let other = if foreign {
                                "other:repository(owner:\"outside\",name:\"other\"){name}"
                            } else {
                                ""
                            };
                            let document = format!(
                                "query Read($go:Boolean!={default}){{r:repository(owner:{string},name:\"repository\"){guard}{{{selection}}} {other}}} mutation Write($go:Boolean!={default}){{...Writes {guard}}} fragment Writes on Mutation{{a:closeIssue(input:{{issueId:\"one\"}}){{clientMutationId issue{{repository{{name issue(number:9){{title}}}}}}}} b:deleteIssue(input:{{issueId:\"two\"}}){{clientMutationId}}}} {fragments}"
                            );
                            let variables =
                                supplied.map_or_else(|| json!({}), |value| json!({"go":value}));
                            for operation in ["Read", "Write"] {
                                requests.push(json!({"query":document,"variables":variables,"operationName":operation}));
                            }
                        }
                    }
                }
            }
        }
    }
    println!("Comparing {} requests with GraphQL.js", requests.len());
    let results = execute(&requests);
    for (request, result) in requests.iter().zip(results) {
        assert_execution(request, result);
    }
}

#[test]
fn reference_selection_and_merged_fields_have_observable_controls() {
    let document = "query Read{repository(owner:\"scope\",name:\"repository\"){issue(number:42){title} ...Fields ...Fields}} mutation Write{closeIssue(input:{issueId:\"one\"}){clientMutationId}} fragment Fields on Repository{issue(number:42){number repository{name}}}";
    let requests =
        ["Read", "Write"].map(|operation| json!({"query":document,"operationName":operation}));
    let results = execute(&requests);
    assert!(
        results[0]
            .effects
            .iter()
            .all(|effect| effect.kind != "CloseIssue")
    );
    assert_eq!(
        results[0]
            .effects
            .iter()
            .filter(|effect| effect.kind == "ReadIssue")
            .count(),
        1
    );
    assert_eq!(results[1].effects.len(), 1);
    assert_eq!(results[1].effects[0].kind, "CloseIssue");
    for (request, result) in requests.iter().zip(results) {
        assert_execution(request, result);
    }
}

#[hegel::test(test_cases = 500, database = None, derandomize = false)]
#[hegel::explicit_test_case(request = json!({
    "query": "{repository(owner:\"scope\",name:\"repository\"){issues(first:1,states:OPEN){nodes{title}}}}"
}))]
#[hegel::explicit_test_case(request = json!({
    "query": "{repository(owner:\"scope\",name:\"repository\"){issues(first:1,states:null){nodes{title}}}}"
}))]
fn generated_classifications_agree_with_reference_execution(tc: TestCase) {
    let request = tc.draw(reference_cases::requests());
    tc.note(&request.to_string());
    let executed = execute(std::slice::from_ref(&request)).pop().unwrap();
    tc.note(&format!(
        "executed effects={}, unfamiliar={}",
        executed.effects.len(),
        executed.unfamiliar
    ));
    tc.target_labelled(executed.effects.len() as f64, "executed effects");
    assert_execution(&request, executed);
}

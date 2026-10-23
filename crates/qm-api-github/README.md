# GitHub request analysis

`qm-api-github` captures a bounded HTTP/1.1 request and analyses recognized GitHub
REST and GraphQL inputs. It performs no I/O and holds no credentials. The caller
retains the original request for inspection and dispatch.

```rust
use qm_api_github::{CapturedRequest, PatternSet, RequestLimits, analyze};

let bytes = b"GET /repos/ashb/reviewq/issues HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n";
let captured = CapturedRequest::parse(bytes, RequestLimits::default()).unwrap();
let analysis = analyze(&captured, &PatternSet::default()).unwrap();
assert!(analysis.complete());
assert_eq!(captured.original(), bytes);
```

## Interpreting a result

`Analysis` reports effects, resource references, uncovered inputs and pattern
matches. `complete()` means every supplied input fits the recognition model;
it neither authorizes dispatch nor verifies upstream resource ownership.

An `Effect` or `GraphqlRoot` predicate matches an observed fact even when another
input is unfamiliar. Such matches remain useful for denials and mandatory
approval rules. A complete positive pattern match additionally requires
`OnlyEffects` to cover every observed effect and complete input recognition.
Recognizing one allowed field cannot authorize an additional operation.

`AllResourcesInRepository` requires complete resource coverage. Repository names
are request references; numeric repository IDs and GraphQL node IDs need trusted
ownership mappings before they can establish repository confinement.

Unfamiliar valid input produces uncovered observations. Malformed JSON in a
recognized JSON grammar, invalid GraphQL and resource-limit failures are typed
errors. The caller must apply policy restrictions before considering complete
allow matches; see the [approval contract](../../docs/security-boundaries.md#github-requests-matching-and-approval-proposed).

## Recognition and capture

The model covers issue list/read/close and repository read/delete REST requests,
plus a limited GraphQL repository/issue model. Automatic recognition requires
the explicit `2022-11-28` API version and supported JSON media types. GraphQL
analysis resolves operation selection, variables, fragments, aliases and Boolean
directives within configurable analysis limits.

Capture preserves original method, target, headers and body bytes, including
unfamiliar application input. It accepts one HTTPS authority and fixed-length
HTTP/1.1 framing; ambiguous framing, proxy authentication, upgrades and `Expect`
are rejected. Analysis never rewrites a request. Destination authorization
belongs to the caller.

Other APIs belong in separate crates; see [API classifiers](../../docs/architecture.md#api-classifiers).

## Tests

```sh
bazelisk test //crates/qm-api-github/...
```

The reference test executes requests against a local GraphQL.js fixture schema
and compares effects, paths, resources, roots and pattern matches with Rust.
Bazel supplies Node and GraphQL.js; no GitHub connection is needed. Rejected
generated documents fail the test.

Hegel runs 500 fresh random cases per property, locally and in CI. The containing
Bazel targets always execute so result caching cannot skip generation. Preserve
regressions with `#[hegel::explicit_test_case(...)]`; these run before generation.
The sandbox example database is disabled. Use printed `reproduce_failure` blobs
for temporary debugging: that attribute replaces generation.

To replay an entire generated sample with a fixed seed:

```sh
bazelisk test //crates/qm-api-github/... --test_env=HEGEL_SEED=7
```

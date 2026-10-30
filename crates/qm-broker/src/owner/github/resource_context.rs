use crate::owner::{
    dispatch::CredentialSelection, request::FrozenOperation, transport::OperationResponse,
};
use qm_api_github::{ResourceContext, ResourceKind};
use serde::Serialize;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

const CAPACITY: usize = 256;
const TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Scope {
    credential: CredentialSelection,
    policy: u64,
    configuration: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::owner) struct Target {
    #[serde(skip)]
    scope: Scope,
    pub(super) node_id: String,
    pub(in crate::owner) repository: String,
    pub(super) kind: ResourceKind,
    pub(in crate::owner) number: u64,
    pub(in crate::owner) title: String,
}

impl Target {
    pub(in crate::owner) fn matches(
        &self,
        credential: &CredentialSelection,
        policy: u64,
        configuration: [u8; 32],
    ) -> bool {
        &self.scope.credential == credential
            && self.scope.policy == policy
            && self.scope.configuration == configuration
    }
}

struct Entry {
    target: Target,
    observed: Instant,
}

#[derive(Default)]
pub(in crate::owner) struct ResourceCache {
    entries: VecDeque<Entry>,
}

pub(in crate::owner) struct Observation {
    scope: Scope,
    request: FrozenOperation,
}

impl Observation {
    pub(in crate::owner) fn new(
        request: FrozenOperation,
        credential: CredentialSelection,
        policy: u64,
    ) -> Option<Self> {
        let (_, configuration) = request.github_identity()?;
        request.application()?;
        Some(Self {
            scope: Scope {
                credential,
                policy,
                configuration,
            },
            request,
        })
    }
}

impl ResourceCache {
    pub(in crate::owner) fn clear(&mut self) {
        self.entries.clear();
    }

    fn prune(&mut self, now: Instant) {
        self.entries.retain(|entry| {
            now.checked_duration_since(entry.observed)
                .is_some_and(|age| age < TTL)
        });
    }

    fn insert(&mut self, scope: Scope, context: ResourceContext, now: Instant) {
        self.prune(now);
        self.entries
            .retain(|entry| entry.target.scope != scope || entry.target.node_id != context.node_id);
        if self.entries.len() == CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(Entry {
            observed: now,
            target: Target {
                scope,
                node_id: context.node_id,
                repository: format!("{}/{}", context.repository.owner, context.repository.name),
                kind: context.kind,
                number: context.number,
                title: context.title,
            },
        });
    }

    fn get(&mut self, scope: &Scope, node: &str, now: Instant) -> Option<Target> {
        self.prune(now);
        let position = self
            .entries
            .iter()
            .position(|entry| &entry.target.scope == scope && entry.target.node_id == node)?;
        let entry = self.entries.remove(position)?;
        let target = entry.target.clone();
        self.entries.push_back(entry);
        Some(target)
    }

    pub(in crate::owner) fn observe(
        &mut self,
        observation: &Observation,
        response: &OperationResponse,
        now: Instant,
    ) {
        let OperationResponse::Github(response) = response else {
            return;
        };
        let Some(body) = response.lookup_body() else {
            return;
        };
        let Some(application) = observation.request.application() else {
            return;
        };
        let contexts = application.analysis().resource_contexts(body);
        for context in &contexts {
            if format!("{}/{}", context.repository.owner, context.repository.name)
                != observation.request.repository()
                || contexts
                    .iter()
                    .any(|other| other.node_id == context.node_id && other != context)
            {
                continue;
            }
            self.insert(observation.scope.clone(), context.clone(), now);
        }
    }

    pub(in crate::owner) fn resolve(
        &mut self,
        request: &mut FrozenOperation,
        credential: CredentialSelection,
        policy: u64,
        configuration: [u8; 32],
        now: Instant,
    ) {
        let Some(node) = request
            .application()
            .and_then(super::request::Application::unresolved_issue)
            .map(str::to_owned)
        else {
            return;
        };
        let scope = Scope {
            credential,
            policy,
            configuration,
        };
        if let Some(target) = self
            .get(&scope, &node, now)
            .filter(|target| target.kind == ResourceKind::Issue)
        {
            request.set_resource_context(target);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::test_support::vault;
    use qm_api_github::Repository;

    fn scope() -> Scope {
        Scope {
            credential: vault::selection(&vault::snapshot("github-write")),
            policy: 1,
            configuration: [2; 32],
        }
    }
    fn context(number: u64) -> ResourceContext {
        ResourceContext {
            node_id: format!("I_{number}"),
            repository: Repository {
                owner: "a".into(),
                name: "b".into(),
            },
            kind: ResourceKind::Issue,
            number,
            title: format!("Issue {number}"),
        }
    }

    #[test]
    fn lru_hits_preserve_fixed_expiry_and_evict_the_least_recent_entry() {
        let now = Instant::now();
        let mut cache = ResourceCache::default();
        let scope = scope();
        for n in 1..=CAPACITY as u64 {
            cache.insert(scope.clone(), context(n), now);
        }
        assert!(
            cache
                .get(&scope, "I_1", now + Duration::from_secs(59))
                .is_some()
        );
        cache.insert(scope.clone(), context(257), now + Duration::from_secs(59));
        assert!(
            cache
                .get(&scope, "I_2", now + Duration::from_secs(59))
                .is_none()
        );
        assert!(cache.get(&scope, "I_1", now + TTL).is_none());
        assert!(cache.get(&scope, "I_257", now + TTL).is_some());
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn labels_are_isolated_by_credential_policy_and_configuration() {
        let now = Instant::now();
        let scope = scope();
        let mut cache = ResourceCache::default();
        cache.insert(scope.clone(), context(1), now);
        let mut changed = scope.clone();
        changed.policy += 1;
        assert!(cache.get(&changed, "I_1", now).is_none());
        let mut changed = scope.clone();
        changed.configuration = [3; 32];
        assert!(cache.get(&changed, "I_1", now).is_none());
        let mut changed = scope.clone();
        changed.credential = vault::selection(&vault::snapshot("other-role"));
        assert!(cache.get(&changed, "I_1", now).is_none());
        assert!(cache.get(&scope, "I_1", now).is_some());
        cache.clear();
        assert!(cache.get(&scope, "I_1", now).is_none());
    }
    fn request(query: &str) -> FrozenOperation {
        let config = super::super::configuration::GitHubConfig::decode(br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"a","name":"b"}],"approveUnverifiedRequests":true}"#).unwrap();
        let body = serde_json::json!({"query":query}).to_string();
        let raw = format!(
            "POST /graphql HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        crate::owner::request::read_configured(&mut std::io::Cursor::new(raw), Some(&config))
            .unwrap()
    }

    fn response(status: u16, body: &str) -> OperationResponse {
        let bytes = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let wire = super::super::response::read(&mut std::io::Cursor::new(bytes), "POST").unwrap();
        let super::super::response::Outcome::Response(response) =
            wire.application(b"dummy-credential", false).unwrap()
        else {
            panic!("not a response")
        };
        OperationResponse::Github(response)
    }

    #[test]
    fn lookup_labels_change_only_the_frozen_review_and_never_response_or_authority() {
        let now = Instant::now();
        let credential = scope().credential;
        let lookup =
            request("{repository(owner:\"a\",name:\"b\"){issue(number:1){id number title}}}");
        let configuration = lookup.github_identity().unwrap().1;
        let observation = Observation::new(lookup, credential.clone(), 1).unwrap();
        let response = response(
            200,
            r#"{"data":{"repository":{"issue":{"id":"I_1","number":1,"title":"Test issue"}}}}"#,
        );
        let before = response.public_parts().1.to_vec();
        let mut cache = ResourceCache::default();
        cache.observe(&observation, &response, now);
        assert_eq!(response.public_parts().1, before);
        let mut mutation = request("mutation{reopenIssue(input:{issueId:\"I_1\"}){issue{id}}}");
        let original = mutation
            .application()
            .unwrap()
            .capture()
            .original()
            .to_vec();
        let original_digest = mutation.digest();
        cache.resolve(&mut mutation, credential.clone(), 1, configuration, now);
        let review = serde_json::to_value(&mutation).unwrap();
        assert_eq!(
            review["application"]["resourceContext"]["title"],
            "Test issue"
        );
        assert_eq!(review["application"]["unresolvedTarget"], true);
        assert_eq!(review["application"]["complete"], false);
        assert_eq!(
            mutation.application().unwrap().capture().original(),
            original
        );
        assert_ne!(mutation.digest(), original_digest);
        assert_eq!(mutation.action(), crate::owner::request::Action::Api);
        assert!(mutation.github_identity().is_none());
        assert!(!mutation.is_reusable_read());
        let frozen = mutation.digest();
        cache.clear();
        assert_eq!(mutation.digest(), frozen);
        let mut unknown =
            request("mutation{reopenIssue(input:{issueId:\"I_1\",future:true}){issue{id}}}");
        cache.observe(&observation, &response, now);
        cache.resolve(&mut unknown, credential, 1, configuration, now);
        assert!(
            serde_json::to_value(unknown).unwrap()["application"]
                .get("resourceContext")
                .is_none()
        );
    }

    #[test]
    fn unsuccessful_partial_and_unscoped_responses_do_not_seed_labels() {
        let now = Instant::now();
        let credential = scope().credential;
        let lookup =
            request("{repository(owner:\"a\",name:\"b\"){issue(number:1){id number title}}}");
        let observation = Observation::new(lookup, credential.clone(), 1).unwrap();
        for (status, body) in [
            (
                403,
                r#"{"data":{"repository":{"issue":{"id":"I_1","number":1,"title":"Test"}}}}"#,
            ),
            (
                200,
                r#"{"errors":[{"message":"partial"}],"data":{"repository":{"issue":{"id":"I_1","number":1,"title":"Test"}}}}"#,
            ),
            (
                200,
                r#"{"data":{"repository":{"issue":{"id":"I_1","id":"I_other","number":1,"title":"Test"}}}}"#,
            ),
        ] {
            let mut cache = ResourceCache::default();
            cache.observe(&observation, &response(status, body), now);
            assert!(cache.entries.is_empty());
        }
        assert!(Observation::new(request("{node(id:\"I_1\"){id}}"), credential, 1).is_none());
    }

    #[test]
    fn unusable_titles_leave_the_original_unresolved_mutation_review_available() {
        let now = Instant::now();
        let credential = scope().credential;
        let lookup =
            request("{repository(owner:\"a\",name:\"b\"){issue(number:1){id number title}}}");
        let configuration = lookup.github_identity().unwrap().1;
        let observation = Observation::new(lookup, credential.clone(), 1).unwrap();
        for title in [
            "hidden\u{61c}title".into(),
            "line\nbreak".into(),
            "x".repeat(2049),
        ] {
            let body = serde_json::json!({"data":{"repository":{"issue":{"id":"I_1","number":1,"title":title}}}}).to_string();
            let response = response(200, &body);
            let before = response.public_parts().1.to_vec();
            let mut cache = ResourceCache::default();
            cache.observe(&observation, &response, now);
            let mut mutation = request("mutation{reopenIssue(input:{issueId:\"I_1\"}){issue{id}}}");
            let original = serde_json::to_value(&mutation).unwrap();
            let digest = mutation.digest();
            cache.resolve(&mut mutation, credential.clone(), 1, configuration, now);
            let review = serde_json::to_value(&mutation).unwrap();
            assert_eq!(review, original);
            assert_eq!(mutation.digest(), digest);
            assert_eq!(review["application"]["unresolvedTarget"], true);
            assert!(review["application"].get("resourceContext").is_none());
            assert_eq!(
                review["application"]["effects"],
                serde_json::json!(["reopenIssue"])
            );
            assert!(!mutation.is_reusable_read());
            assert!(mutation.github_identity().is_none());
            assert_eq!(response.public_parts().1, before);
        }
    }
}

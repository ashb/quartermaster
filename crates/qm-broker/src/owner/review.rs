use super::{grant::ReadGrantClaims, request::FrozenOperation};
use qm_api_github::EffectKind;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Presentation {
    intent: GitHubApprovalIntent,
    repository: Option<String>,
    resource_title: Option<String>,
    additional_effects: Vec<EffectKind>,
    understanding_notice: Option<UnderstandingNotice>,
    allows_read_scope: bool,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum GitHubApprovalIntent {
    Request,
    Issue {
        action: EffectKind,
        number: Option<u64>,
    },
    ReadGrant {
        grant: super::grant::ReadGrantDisplay,
    },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum UnderstandingNotice {
    IncompleteRequest,
}

impl Presentation {
    fn new(operation: &FrozenOperation, authorization: Option<&ReadGrantClaims>) -> Self {
        let application = operation.application();
        let grant = authorization.map(ReadGrantClaims::display);
        let allows_read_scope = operation.is_reusable_read();
        let mut effects = application.map_or_else(Vec::new, |application| {
            application
                .analysis()
                .effects
                .iter()
                .map(|effect| effect.kind)
                .collect()
        });
        let complete = application.is_some_and(|application| application.analysis().complete());
        let repository = if !operation.repository().is_empty() {
            Some(operation.repository().to_owned())
        } else {
            application.and_then(|application| application.requested_repository())
        };
        let intent = if let Some(grant) = grant {
            effects.clear();
            GitHubApprovalIntent::ReadGrant { grant }
        } else if complete
            && effects == [EffectKind::CloseIssue]
            && let Some(number) = operation.issue_number()
        {
            effects.clear();
            GitHubApprovalIntent::Issue {
                action: EffectKind::CloseIssue,
                number: Some(number.get()),
            }
        } else {
            GitHubApprovalIntent::Request
        };
        let understanding_notice = if application.is_none() || complete {
            None
        } else {
            Some(UnderstandingNotice::IncompleteRequest)
        };
        if allows_read_scope
            && complete
            && effects
                .iter()
                .all(|effect| matches!(*effect, EffectKind::ListIssues | EffectKind::ReadIssue))
        {
            effects.clear();
        }
        Self {
            intent,
            repository,
            resource_title: None,
            additional_effects: effects,
            understanding_notice,
            allows_read_scope,
        }
    }
}

pub(super) trait CredentialContext {
    fn credential_role(&self) -> &str;
}

pub(super) struct ReviewDocument<C> {
    operation: FrozenOperation,
    authorization: Option<ReadGrantClaims>,
    context: C,
    bytes: Vec<u8>,
}

impl<C> ReviewDocument<C> {
    pub(super) fn new(
        operation: FrozenOperation,
        authorization: Option<ReadGrantClaims>,
        context: C,
    ) -> Result<Self, serde_json::Error>
    where
        C: Serialize + CredentialContext,
    {
        #[derive(Serialize)]
        struct Envelope<'a, C> {
            presentation: Presentation,
            #[serde(flatten)]
            operation: &'a FrozenOperation,
            #[serde(skip_serializing_if = "Option::is_none")]
            authorization: &'a Option<ReadGrantClaims>,
            #[serde(flatten)]
            context: &'a C,
        }
        let bytes = serde_json::to_vec(&Envelope {
            presentation: Presentation::new(&operation, authorization.as_ref()),
            operation: &operation,
            authorization: &authorization,
            context: &context,
        })?;
        Ok(Self {
            operation,
            authorization,
            context,
            bytes,
        })
    }

    pub(super) fn matches(
        &self,
        operation: &FrozenOperation,
        authorization: Option<ReadGrantClaims>,
    ) -> bool {
        &self.operation == operation && self.authorization == authorization
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn context(&self) -> &C {
        &self.context
    }
}

impl<C: CredentialContext> ReviewDocument<C> {
    pub(super) fn credential_role(&self) -> &str {
        self.context.credential_role()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::{github::configuration::GitHubConfig, request, test_support};

    fn operation(method: &str, path: &str, body: &str) -> FrozenOperation {
        let config = GitHubConfig::decode(br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one"}],"approveUnverifiedRequests":true}"#).unwrap();
        let raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        request::read_configured(&mut raw.as_bytes(), Some(&config)).unwrap()
    }

    #[test]
    fn understood_close_has_a_specific_title_without_repeating_its_effect() {
        let request = operation(
            "PATCH",
            "/repos/example/one/issues/42",
            r#"{"state":"closed"}"#,
        );
        let review = test_support::approval::selected_review(request, None, "github-write");
        let wire: serde_json::Value = serde_json::from_slice(review.bytes()).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../macos/Security/Tests/QuartermasterSecurityTests/Fixtures/approval-presentation.json"
        ))).unwrap();
        assert_eq!(wire["presentation"], fixture["presentation"]);
    }

    #[test]
    fn unfamiliar_companions_keep_the_warning_and_known_actions() {
        let request = operation(
            "PATCH",
            "/repos/example/one/issues/42",
            r#"{"state":"closed","future":true}"#,
        );
        let display = Presentation::new(&request, None);
        assert!(matches!(display.intent, GitHubApprovalIntent::Request));
        assert_eq!(display.additional_effects, [EffectKind::CloseIssue]);
        assert!(display.understanding_notice.is_some());
        assert!(!display.allows_read_scope);
        assert!(display.repository.is_none());
    }

    #[test]
    fn multiple_actions_remain_visible_in_the_approval() {
        let request = operation(
            "POST",
            "/graphql",
            r#"{"query":"mutation { closeIssue(input:{issueId:\"I_one\"}) {issue{id}} deleteIssue(input:{issueId:\"I_two\"}) {clientMutationId} }"}"#,
        );
        let display = Presentation::new(&request, None);
        assert!(matches!(display.intent, GitHubApprovalIntent::Request));
        assert!(display.additional_effects.contains(&EffectKind::CloseIssue));
        assert!(
            display
                .additional_effects
                .contains(&EffectKind::DeleteIssue)
        );
        assert!(!display.allows_read_scope);
    }

    #[test]
    fn scope_choices_follow_backend_read_admission() {
        for (path, allowed) in [
            ("/repos/example/one/issues/42", true),
            ("/repos/example/one/issues/42?future=true", false),
            ("/repos/example/two/issues/42", false),
        ] {
            let request = operation("GET", path, "");
            assert_eq!(
                Presentation::new(&request, None).allows_read_scope,
                allowed,
                "{path}"
            );
        }
    }

    #[test]
    fn approved_scope_description_is_frozen_with_its_claims() {
        let request = operation("GET", "/repos/example/one/issues/42", "");
        let principal =
            crate::owner::identity::VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let claims =
            crate::owner::grant::ReadGrantProposal::new(&principal, &request, "github-read")
                .unwrap()
                .claims();
        let review = test_support::approval::selected_review(request, Some(claims), "github-read");
        let wire: serde_json::Value = serde_json::from_slice(review.bytes()).unwrap();
        let display = &wire["presentation"];
        assert_eq!(display["intent"]["kind"], "readGrant");
        assert_eq!(display["intent"]["grant"]["repository"], "example/one");
        assert_eq!(
            display["intent"]["grant"]["permission"],
            serde_json::json!({"kind":"githubCategories","categories":["repository","issues","actions","output"]})
        );
        assert_eq!(
            display["intent"]["grant"]["root"],
            wire["authorization"]["grant"]["root"]
        );
        assert_eq!(
            display["intent"]["grant"]["expiresUnix"],
            wire["authorization"]["grant"]["expiresUnix"]
        );
        assert_eq!(
            display["intent"]["grant"]["id"],
            wire["authorization"]["grant"]["id"]
        );
        assert_eq!(display["additionalEffects"], serde_json::json!([]));
    }
}

use crate::{Analysis, Repository, json::Json};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ResourceKind {
    Issue,
    PullRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceContext {
    pub node_id: String,
    pub repository: Repository,
    pub kind: ResourceKind,
    pub number: u64,
    pub title: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    Repository(Repository),
    Resource {
        kind: Option<ResourceKind>,
        number: u64,
    },
    Scalar(String),
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Field {
    path: Vec<String>,
    step: Step,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LookupPlan {
    fields: Vec<Field>,
    invalid: bool,
}

impl LookupPlan {
    pub(crate) fn record(&mut self, context: &str, name: &str, args: &Json, path: &[String]) {
        if self.invalid || path.len() > 3 {
            return;
        }
        let step = match (path.len(), context, name) {
            (1, "Query", "repository") => {
                let Some(owner) = args.unique("owner").and_then(Json::string) else {
                    return;
                };
                let Some(name) = args.unique("name").and_then(Json::string) else {
                    return;
                };
                Step::Repository(Repository {
                    owner: owner.into(),
                    name: name.into(),
                })
            }
            (2, "Repository", "issue" | "pullRequest" | "issueOrPullRequest") => {
                let Some(Json::Number(number)) = args.unique("number") else {
                    return;
                };
                let Some(number) = number.as_u64().filter(|n| *n > 0) else {
                    return;
                };
                let kind = match name {
                    "issue" => Some(ResourceKind::Issue),
                    "pullRequest" => Some(ResourceKind::PullRequest),
                    _ => None,
                };
                Step::Resource { kind, number }
            }
            (
                3,
                "Issue" | "PullRequest" | "IssueOrPullRequest",
                "id" | "number" | "title" | "__typename",
            ) => Step::Scalar(name.into()),
            _ => Step::Other(name.into()),
        };
        let field = Field {
            path: path.to_vec(),
            step,
        };
        if self.fields.contains(&field) {
            return;
        }
        if self.fields.len() >= 128
            || path.iter().any(|p| p.len() > 256)
            || self
                .fields
                .iter()
                .any(|old| old.path == path && old.step != field.step)
        {
            self.invalid = true;
            self.fields.clear();
        } else {
            self.fields.push(field);
        }
    }

    fn extract(&self, response: &Json) -> Vec<ResourceContext> {
        if self.invalid {
            return Vec::new();
        }
        let Some(data) = response.unique("data") else {
            return Vec::new();
        };
        self.fields
            .iter()
            .filter_map(|field| {
                let Step::Resource { kind, number } = field.step else {
                    return None;
                };
                let repository = self.fields.iter().find_map(|parent| {
                    if parent.path == field.path[..1]
                        && let Step::Repository(repository) = &parent.step
                    {
                        return Some(repository.clone());
                    }
                    None
                })?;
                let object = data.unique(&field.path[0])?.unique(&field.path[1])?;
                let scalar = |name: &str| -> Option<&Json> {
                    let mut value = None;
                    for member in self.fields.iter().filter(|member| {
                        member.path.len() == 3
                            && member.path[..2] == field.path
                            && member.step == Step::Scalar(name.into())
                    }) {
                        let found = object.unique(&member.path[2])?;
                        if value.is_some_and(|old| old != found) {
                            return None;
                        }
                        value = Some(found);
                    }
                    value
                };
                let actual_kind = match scalar("__typename").and_then(Json::string) {
                    Some("Issue") => ResourceKind::Issue,
                    Some("PullRequest") => ResourceKind::PullRequest,
                    None if kind.is_some()
                        && !self.fields.iter().any(|member| {
                            member.path.len() == 3
                                && member.path[..2] == field.path
                                && member.step == Step::Scalar("__typename".into())
                        }) =>
                    {
                        kind?
                    }
                    _ => return None,
                };
                if kind.is_some_and(|kind| kind != actual_kind) {
                    return None;
                }
                let Json::Number(returned_number) = scalar("number")? else {
                    return None;
                };
                if returned_number.as_u64() != Some(number) {
                    return None;
                }
                let id = scalar("id")?.string()?;
                let title = scalar("title")?.string()?;
                if !node_id(id) || !title_label(title) {
                    return None;
                }
                Some(ResourceContext {
                    node_id: id.into(),
                    repository,
                    kind: actual_kind,
                    number,
                    title: title.into(),
                })
            })
            .collect()
    }
}

fn node_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|b| b.is_ascii_graphic())
}

fn title_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && !value.chars().any(|c| {
            matches!(c as u32, 0x00..=0x1f | 0x7f..=0x9f | 0xad | 0x61c | 0x200b | 0x200e..=0x200f | 0x2028..=0x202e | 0x2060..=0x206f | 0xfeff)
        })
}

impl Analysis {
    /// Extracts display metadata; the caller must authenticate the response origin.
    pub fn resource_contexts(&self, response: &[u8]) -> Vec<ResourceContext> {
        if !self.complete()
            || self.effects.iter().any(|effect| !effect.kind.is_read())
            || response.len() > 2 * 1024 * 1024
            || crate::json::check_depth(response, 64).is_err()
        {
            return Vec::new();
        }
        let Ok(response) = serde_json::from_slice::<Json>(response) else {
            return Vec::new();
        };
        if response.duplicate_members() || response.unique("errors").is_some() {
            return Vec::new();
        }
        self.lookup.extract(&response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapturedRequest, PatternSet, RequestLimits, analyze};
    use serde_json::json;

    fn lookup(query: &str, response: serde_json::Value) -> Vec<ResourceContext> {
        let body =
            json!({"query":query,"variables":{"owner":"ashb","repo":"playground","number":1}})
                .to_string();
        let wire = format!(
            "POST /graphql HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let request = CapturedRequest::parse(wire.as_bytes(), RequestLimits::default()).unwrap();
        let analysis = analyze(&request, &PatternSet::default()).unwrap();
        assert!(analysis.complete(), "{:?}", analysis.uncovered);
        analysis.resource_contexts(&serde_json::to_vec(&response).unwrap())
    }

    const QUERY: &str = "query($owner:String!,$repo:String!,$number:Int!){r:repository(owner:$owner,name:$repo){item:issueOrPullRequest(number:$number){__typename ...I ...on PullRequest{id number title}}}} fragment I on Issue{id number title}";

    #[test]
    fn lookup_titles_preserve_unicode_but_reject_hidden_controls_and_byte_overflow() {
        for (title, accepted) in [
            ("Fix 👩‍💻 workflow".into(), true),
            ("العربية / עברית / 日本語 / café".into(), true),
            ("می\u{200c}خواهم".into(), true),
            ("Fix 🏳️‍🌈 workflow".into(), true),
            ("é".repeat(1024), true),
            ("é".repeat(1025), false),
            (String::new(), false),
            ("x".repeat(2049), false),
            ("line\nbreak".into(), false),
            ("hidden\u{85}title".into(), false),
            ("hidden\u{61c}title".into(), false),
            ("hidden\u{200b}title".into(), false),
            ("hidden\u{2028}title".into(), false),
            ("hidden\u{202e}title".into(), false),
            ("hidden\u{2066}title".into(), false),
            ("hidden\u{feff}title".into(), false),
        ] {
            let contexts = lookup(
                QUERY,
                json!({"data":{"r":{"item":{"__typename":"Issue","id":"I_one","number":1,"title":title}}}}),
            );
            assert_eq!(!contexts.is_empty(), accepted, "{title:?}");
            if accepted {
                assert_eq!(contexts[0].title, title);
            }
        }
    }

    #[test]
    fn lookup_node_ids_require_bounded_visible_ascii() {
        for (id, accepted) in [
            ("I_kwDOVSDErs8AAAABYykilQ".into(), true),
            ("x".repeat(256), true),
            ("x".repeat(257), false),
            (String::new(), false),
            ("I_👩‍💻".into(), false),
            ("I_\u{200d}one".into(), false),
            ("I_ one".into(), false),
            ("I_\none".into(), false),
        ] {
            let contexts = lookup(
                QUERY,
                json!({"data":{"r":{"item":{"__typename":"Issue","id":id,"number":1,"title":"An issue"}}}}),
            );
            assert_eq!(!contexts.is_empty(), accepted, "{id:?}");
        }
    }

    #[test]
    fn aliased_union_lookup_resolves_the_returned_kind_and_number() {
        let response = json!({"data":{"r":{"item":{"__typename":"Issue","id":"I_one","number":1,"title":"Test issue"}}}});
        assert_eq!(
            lookup(QUERY, response),
            vec![ResourceContext {
                node_id: "I_one".into(),
                repository: Repository {
                    owner: "ashb".into(),
                    name: "playground".into()
                },
                kind: ResourceKind::Issue,
                number: 1,
                title: "Test issue".into()
            }]
        );
    }

    #[test]
    fn lookup_rejects_errors_wrong_numbers_and_unknown_types() {
        for response in [
            json!({"data":{"r":{"item":{"__typename":"Issue","id":"I_one","number":2,"title":"Test"}}}}),
            json!({"data":{"r":{"item":{"__typename":"User","id":"U_one","number":1,"title":"Test"}}}}),
            json!({"errors":[{"message":"partial"}],"data":{"r":{"item":{"__typename":"Issue","id":"I_one","number":1,"title":"Test"}}}}),
        ] {
            assert!(lookup(QUERY, response).is_empty());
        }
    }
    #[test]
    fn scalar_aliases_follow_query_meaning_and_do_not_confuse_issue_and_pr() {
        let query = "query($owner:String!,$repo:String!,$number:Int!){r:repository(owner:$owner,name:$repo){item:pullRequest(number:$number){key:id n:number heading:title}}}";
        let result = lookup(
            query,
            json!({"data":{"r":{"item":{"key":"PR_one","n":1,"heading":"A PR","id":"fake"}}}}),
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, ResourceKind::PullRequest);
        assert_eq!(result[0].node_id, "PR_one");
        assert!(
            lookup(
                query,
                json!({"data":{"r":{"item":{"id":"PR_one","number":1,"title":"A PR"}}}})
            )
            .is_empty()
        );
    }

    #[test]
    fn conflicting_response_keys_and_skipped_metadata_cannot_seed_context() {
        for query in [
            "query($owner:String!,$repo:String!,$number:Int!){r:repository(owner:$owner,name:$repo){item:issue(number:$number){id number title id:title}}}",
            "query($owner:String!,$repo:String!,$number:Int!){r:repository(owner:$owner,name:$repo){item:issue(number:$number){id number title @skip(if:true)}}}",
            "query($owner:String!,$repo:String!,$number:Int!){r:repository(owner:$owner,name:$repo){item:issue(number:$number){id number title} item:issue(number:2){id number title}}}",
        ] {
            assert!(
                lookup(
                    query,
                    json!({"data":{"r":{"item":{"id":"I_one","number":1,"title":"Test"}}}})
                )
                .is_empty()
            );
        }
    }

    #[test]
    fn selected_typenames_must_be_present_well_typed_and_consistent() {
        let query = "query($owner:String!,$repo:String!,$number:Int!){r:repository(owner:$owner,name:$repo){item:issue(number:$number){a:__typename b:__typename id number title}}}";
        for (a, b) in [
            (json!("Issue"), json!("PullRequest")),
            (json!(null), json!(null)),
            (json!(42), json!(42)),
        ] {
            assert!(lookup(query,json!({"data":{"r":{"item":{"a":a,"b":b,"id":"I_one","number":1,"title":"Test"}}}})).is_empty());
        }
        assert!(
            lookup(
                query,
                json!({"data":{"r":{"item":{"id":"I_one","number":1,"title":"Test"}}}})
            )
            .is_empty()
        );
    }
}

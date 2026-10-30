use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
    sync::OnceLock,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Recognised,
    Unrecognised,
    Remainder,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry<'a> {
    pub key: &'a str,
    pub fingerprint: &'a str,
    pub kind: Kind,
    pub reason: &'a str,
}

#[derive(Deserialize)]
struct Snapshot {
    entries: BTreeMap<String, String>,
    changes: Vec<String>,
}

fn reviews() -> Vec<Entry<'static>> {
    [
        crate::rest::INSPECT_API_REVIEWS,
        crate::rest::READ_ENDPOINT_API_REVIEWS,
        crate::graphql::SCHEMA_API_REVIEWS,
        crate::graphql::DETAIL_API_REVIEWS,
    ]
    .into_iter()
    .flatten()
    .copied()
    .collect()
}

fn snapshot() -> &'static Snapshot {
    static SNAPSHOT: OnceLock<Snapshot> = OnceLock::new();
    SNAPSHOT.get_or_init(|| {
        let mut command = Command::new(std::env::var_os("QM_REFERENCE_NODE").unwrap());
        command.arg(std::env::var_os("QM_SCHEMA_READER").unwrap());
        if cfg!(feature = "live-api-schema") {
            command.arg("--live");
        }
        let output = command.output().expect("start GitHub schema reader");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("GitHub schema inventory")
    })
}

fn remainder_fingerprint(
    entries: &BTreeMap<String, String>,
    prefix: &str,
    explicit: &BTreeSet<&str>,
) -> String {
    let mut hash = Sha256::new();
    for (key, fingerprint) in entries {
        if key.starts_with(&format!("{prefix} ")) && !explicit.contains(key.as_str()) {
            hash.update(key.as_bytes());
            hash.update(b"\0");
            hash.update(fingerprint.as_bytes());
            hash.update(b"\n");
        }
    }
    URL_SAFE_NO_PAD.encode(&hash.finalize()[..8])
}

fn audit(entries: &BTreeMap<String, String>, reviews: &[Entry<'_>]) -> Vec<String> {
    let explicit: BTreeSet<_> = reviews
        .iter()
        .filter(|review| review.kind != Kind::Remainder)
        .map(|review| review.key)
        .collect();
    let remainders: BTreeSet<_> = reviews
        .iter()
        .filter(|review| review.kind == Kind::Remainder)
        .map(|review| review.key)
        .collect();
    let mut seen = BTreeSet::new();
    let mut errors = Vec::new();
    for review in reviews {
        if !seen.insert(review.key) {
            errors.push(format!("Duplicate API review: {}", review.key));
            continue;
        }
        if review.kind != Kind::Recognised && review.reason.trim().is_empty() {
            errors.push(format!("Missing review reason: {}", review.key));
        }
        if review.kind == Kind::Remainder {
            let fingerprint = remainder_fingerprint(entries, review.key, &explicit);
            if fingerprint != review.fingerprint {
                errors.push(format!(
                    "{0} APIs without individual review annotations changed.\n\
                     Schema changes or added or removed annotations can change this group.\n\
                     Review the diff: restore unintended annotation changes, or update \
                     #[api_remainder(\"{0}\", ...)] after review.\n\
                     reviewed: {1}\ncurrent: {fingerprint}",
                    review.key, review.fingerprint,
                ));
            }
        } else {
            match entries.get(review.key) {
                None => errors.push(format!("Removed {}", review.key)),
                Some(fingerprint) if fingerprint != review.fingerprint => errors.push(format!(
                    "Changed {}: reviewed {}, current {fingerprint}",
                    review.key, review.fingerprint,
                )),
                Some(_) => {}
            }
        }
    }
    for key in entries.keys() {
        if !explicit.contains(key.as_str())
            && !key
                .split_once(' ')
                .is_some_and(|(prefix, _)| remainders.contains(prefix))
        {
            errors.push(format!("Unreviewed {key}"));
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReviewFailure(Vec<String>);

    impl std::fmt::Debug for ReviewFailure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.0.join("\n"))
        }
    }

    #[test]
    fn upstream_matches_parser_reviews() -> Result<(), ReviewFailure> {
        let snapshot = snapshot();
        let reviews = reviews();
        let mut errors = audit(&snapshot.entries, &reviews);
        if reviews.is_empty() {
            errors.insert(0, "No parser annotations were collected".into());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            errors.extend(snapshot.changes.iter().cloned());
            Err(ReviewFailure(errors))
        }
    }

    #[test]
    fn changed_and_removed_annotated_operations_require_review() {
        for kind in [Kind::Recognised, Kind::Unrecognised] {
            let review = Entry {
                key: "REST GET /issues",
                fingerprint: "before",
                kind,
                reason: "Not modelled",
            };
            let entries = BTreeMap::from([("REST GET /issues".into(), "after".into())]);
            assert_eq!(
                audit(&entries, &[review]),
                ["Changed REST GET /issues: reviewed before, current after"]
            );
            assert_eq!(
                audit(&BTreeMap::new(), &[review]),
                ["Removed REST GET /issues"]
            );
        }
    }

    #[test]
    fn new_operations_fail_until_the_remainder_is_reviewed() {
        let entries = BTreeMap::from([("GraphQL Query.repository".into(), "known".into())]);
        let old = remainder_fingerprint(&entries, "GraphQL", &BTreeSet::new());
        let review = Entry {
            key: "GraphQL",
            fingerprint: &old,
            kind: Kind::Remainder,
            reason: "Remaining schema",
        };
        assert!(audit(&entries, &[review]).is_empty());
        let mut changed = entries.clone();
        changed.insert("GraphQL Mutation.newOperation".into(), "new".into());
        assert!(
            audit(&changed, &[review])[0]
                .starts_with("GraphQL APIs without individual review annotations changed.")
        );
        let accepted = remainder_fingerprint(&changed, "GraphQL", &BTreeSet::new());
        assert!(
            audit(
                &changed,
                &[Entry {
                    fingerprint: &accepted,
                    ..review
                }]
            )
            .is_empty()
        );
    }

    #[test]
    fn unannotated_signature_changes_are_not_hidden_by_the_remainder() {
        let entries = BTreeMap::from([("GraphQL State.OPEN".into(), "before".into())]);
        let old = remainder_fingerprint(&entries, "GraphQL", &BTreeSet::new());
        let review = Entry {
            key: "GraphQL",
            fingerprint: &old,
            kind: Kind::Remainder,
            reason: "Remaining schema",
        };
        let changed = BTreeMap::from([("GraphQL State.OPEN".into(), "after".into())]);
        assert_eq!(audit(&changed, &[review]).len(), 1);
    }

    #[test]
    fn missing_and_duplicate_reviews_fail() {
        let entries = BTreeMap::from([("REST GET /issues".into(), "known".into())]);
        assert_eq!(audit(&entries, &[]), ["Unreviewed REST GET /issues"]);
        let review = Entry {
            key: "REST GET /issues",
            fingerprint: "known",
            kind: Kind::Recognised,
            reason: "",
        };
        assert_eq!(
            audit(&entries, &[review, review]),
            ["Duplicate API review: REST GET /issues"]
        );
    }

    #[test]
    fn removing_an_annotation_changes_the_reviewed_remainder() {
        let entries = BTreeMap::from([("REST GET /issues".into(), "known".into())]);
        let old = remainder_fingerprint(&entries, "REST", &BTreeSet::from(["REST GET /issues"]));
        let explicit = Entry {
            key: "REST GET /issues",
            fingerprint: "known",
            kind: Kind::Recognised,
            reason: "",
        };
        let remainder = Entry {
            key: "REST",
            fingerprint: &old,
            kind: Kind::Remainder,
            reason: "Remaining schema",
        };
        assert!(audit(&entries, &[explicit, remainder]).is_empty());
        let errors = audit(&entries, &[remainder]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with("REST APIs without individual review annotations changed."));
        assert!(errors[0].contains("added or removed annotations"));
        assert!(errors[0].contains("restore unintended annotation changes"));
        assert!(errors[0].contains(&format!("reviewed: {old}")));
        assert!(errors[0].contains(&format!(
            "current: {}",
            remainder_fingerprint(&entries, "REST", &BTreeSet::new())
        )));
    }
}

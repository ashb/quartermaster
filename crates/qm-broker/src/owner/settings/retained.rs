use super::ProviderPin;
use crate::owner::persistence;
use qm_providers::EnrollmentPhase;
use std::{fs, path::Path};

pub(in crate::owner) fn discover(base: &Path) -> Vec<ProviderPin> {
    let mut slots = vec!["legacy".to_owned()];
    if let Ok(entries) = fs::read_dir(base.join("enrollments")) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir())
                && let Some(slot) = entry.file_name().to_str()
                && slot != "legacy"
                && ProviderPin::valid_slot(slot)
            {
                slots.push(slot.to_owned());
            }
        }
    }
    slots.sort();
    slots
        .into_iter()
        .filter_map(|slot| candidate(base, slot))
        .collect()
}

fn candidate(base: &Path, slot: String) -> Option<ProviderPin> {
    let root = if slot == "legacy" {
        base.to_owned()
    } else {
        base.join("enrollments").join(&slot)
    };
    if !root.join("vault").is_dir() {
        return None;
    }
    let store = persistence::store(&root).ok()?;
    let manifest = persistence::enrollment(&store).ok()??;
    if manifest.phase() != EnrollmentPhase::Ready {
        return None;
    }
    let provider = ProviderPin {
        slot,
        binding: manifest.binding().clone(),
        scope: manifest.scope().into(),
        device_key: manifest.identity()?,
    };
    provider.validate().ok()?;
    Some(provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::{test_support, vault};
    use std::os::unix::fs::symlink;

    #[test]
    fn discovery_includes_legacy_and_slot_enrollments_but_skips_damaged_or_linked_entries() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        assert!(discover(&root).is_empty());
        assert!(!root.join("vault").exists());
        let snapshot = test_support::vault::snapshot("github-write");
        vault::fixture::put(&root, &snapshot);
        vault::fixture::put(&root.join("enrollments").join("a".repeat(32)), &snapshot);
        let damaged = root.join("enrollments").join("b".repeat(32)).join("vault");
        fs::create_dir_all(&damaged).unwrap();
        fs::write(damaged.join("enrollment.json"), b"invalid").unwrap();
        symlink(&root, root.join("enrollments").join("c".repeat(32))).unwrap();
        vault::fixture::put(&root.join("enrollments").join("invalid-slot"), &snapshot);
        let candidates = discover(&root);
        assert_eq!(
            candidates
                .iter()
                .map(|pin| pin.slot.as_str())
                .collect::<Vec<_>>(),
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "legacy"]
        );
        assert!(
            candidates
                .iter()
                .all(|pin| pin.binding == *snapshot.binding())
        );
    }
}

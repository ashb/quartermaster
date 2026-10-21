use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn github_configuration_loading_rejects_unsafe_files_instead_of_ignoring_them() {
    for case in 0..6 {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("github.json");
        let bytes = match case {
            2 => b"{\"mode\":\"automatic\"}".to_vec(),
            3 => vec![b' '; 65537],
            _ => br#"{"version":1,"mode":"github","repositories":[]}"#.to_vec(),
        };
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        match case {
            0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            1 => {
                let target = root.path().join("target");
                fs::rename(&path, &target).unwrap();
                std::os::unix::fs::symlink(target, &path).unwrap();
            }
            4 => fs::hard_link(&path, root.path().join("other-link")).unwrap(),
            5 => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            _ => {}
        }
        assert!(policy(root.path()).is_err(), "case {case}");
    }
}

#[cfg(all(target_os = "macos", debug_assertions))]
mod unix {
    use qm_broker::{ServiceError, ServiceOptions, serve};
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn service_rejects_publicly_accessible_storage_before_starting() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();

        let result = serve(ServiceOptions {
            storage_root: root.path().into(),
            bundle_root: root.path().join("Quartermaster.app"),
        });

        assert!(matches!(result, Err(ServiceError::UnsafeStorage)));
        assert!(fs::read_dir(root.path()).unwrap().next().is_none());
    }

    #[test]
    fn service_rejects_symlinked_storage_without_following_it() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("storage");
        std::os::unix::fs::symlink(root.path(), &link).unwrap();

        let result = serve(ServiceOptions {
            storage_root: link,
            bundle_root: root.path().join("Quartermaster.app"),
        });

        assert!(matches!(result, Err(ServiceError::UnsafeStorage)));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn service_rejects_a_bundle_that_does_not_contain_the_running_backend() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let bundle = root.path().join("Quartermaster.app");
        fs::create_dir(&bundle).unwrap();

        let result = serve(ServiceOptions {
            storage_root: root.path().into(),
            bundle_root: bundle,
        });

        assert!(matches!(result, Err(ServiceError::InvalidBundle)));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}

#[cfg(all(target_os = "macos", not(debug_assertions)))]
#[test]
fn release_service_refuses_to_open_the_development_namespace() {
    let result = qm_broker::serve(qm_broker::ServiceOptions {
        storage_root: "/missing/development-state".into(),
        bundle_root: "/missing/Quartermaster.app".into(),
    });

    assert!(
        matches!(result, Err(qm_broker::ServiceError::Runtime(error))
        if error.kind() == std::io::ErrorKind::PermissionDenied)
    );
}

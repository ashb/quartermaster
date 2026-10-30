use block2::{DynBlock, RcBlock};
use objc2::rc::autoreleasepool;
use objc2_app_kit::{NSRunningApplication, NSWorkspace, NSWorkspaceOpenConfiguration};
use objc2_foundation::{NSError, NSURL};
use std::{io, path::Path, sync::mpsc, time::Instant};

pub(crate) fn launch_application(app: &Path, deadline: Instant) -> io::Result<()> {
    launch_with(app, deadline, |url, configuration, completion| {
        NSWorkspace::sharedWorkspace().openApplicationAtURL_configuration_completionHandler(
            url,
            configuration,
            Some(completion),
        );
    })
}

fn launch_with(
    app: &Path,
    deadline: Instant,
    open: impl FnOnce(
        &NSURL,
        &NSWorkspaceOpenConfiguration,
        &DynBlock<dyn Fn(*mut NSRunningApplication, *mut NSError)>,
    ),
) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "application launch expired",
        ));
    }
    let receive = autoreleasepool(|_| {
        let url = NSURL::from_directory_path(app).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid application path")
        })?;
        let configuration = NSWorkspaceOpenConfiguration::configuration();
        configuration.setAllowsRunningApplicationSubstitution(false);
        configuration.setPromptsUserIfNeeded(false);
        let (send, receive) = mpsc::channel();
        let completion =
            RcBlock::new(move |app: *mut NSRunningApplication, error: *mut NSError| {
                let _ = send.send(!app.is_null() && error.is_null());
            });
        open(&url, &configuration, &completion);
        Ok::<_, io::Error>(receive)
    })?;
    match receive.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(true) => Ok(()),
        Ok(false) | Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("application launch failed"))
        }
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "application launch timed out",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objc2::rc::Retained;
    use objc2_foundation::ns_string;
    use std::{cell::RefCell, ptr, time::Duration};

    #[test]
    fn launch_activates_the_exact_bundle_and_waits_for_success() {
        let path = Path::new("/Applications/Quartermaster Development.app");
        launch_with(
            path,
            Instant::now() + Duration::from_secs(1),
            |url, configuration, completion| {
                assert_eq!(url.to_file_path().unwrap(), path);
                assert!(configuration.activates());
                assert!(!configuration.createsNewApplicationInstance());
                assert!(!configuration.allowsRunningApplicationSubstitution());
                assert!(!configuration.promptsUserIfNeeded());
                let app = NSRunningApplication::currentApplication();
                completion.call((Retained::as_ptr(&app).cast_mut(), ptr::null_mut()));
            },
        )
        .unwrap();
    }

    #[test]
    fn launch_errors_or_missing_application_cannot_report_success() {
        for has_app in [false, true] {
            let result = launch_with(
                Path::new("/Applications/Quartermaster.app"),
                Instant::now() + Duration::from_secs(1),
                |_, _, completion| {
                    let app = NSRunningApplication::currentApplication();
                    let error = unsafe {
                        NSError::errorWithDomain_code_userInfo(ns_string!("launch-test"), 1, None)
                    };
                    let app = if has_app {
                        Retained::as_ptr(&app).cast_mut()
                    } else {
                        ptr::null_mut()
                    };
                    completion.call((app, Retained::as_ptr(&error).cast_mut()));
                },
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn launch_timeout_allows_a_late_native_callback_to_finish_safely() {
        let pending = RefCell::new(None);
        let result = launch_with(
            Path::new("/Applications/Quartermaster.app"),
            Instant::now() + Duration::from_millis(10),
            |_, _, completion| {
                *pending.borrow_mut() = Some(completion.copy());
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let app = NSRunningApplication::currentApplication();
        pending
            .into_inner()
            .unwrap()
            .call((Retained::as_ptr(&app).cast_mut(), ptr::null_mut()));
    }

    #[test]
    fn expired_launch_does_not_start_an_application() {
        let result = launch_with(
            Path::new("/Applications/Quartermaster.app"),
            Instant::now(),
            |_, _, _| panic!("expired launch was started"),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn native_launch_reports_an_invalid_bundle_without_displaying_a_prompt() {
        let directory = tempfile::tempdir().unwrap();
        let app = directory.path().join("Invalid.app");
        std::fs::create_dir(&app).unwrap();
        let result = launch_application(&app, Instant::now() + Duration::from_secs(5));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
    }
}

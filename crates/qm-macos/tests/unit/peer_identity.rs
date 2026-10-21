use super::*;

fn observation(pid: u32, parent_pid: u32, started: (u64, u64)) -> ObservedProcess {
    ObservedProcess {
        pid,
        parent_pid,
        name: "process".into(),
        executable: "/process".into(),
        started,
    }
}

#[test]
fn unchanged_parent_link_can_be_displayed() {
    let parent = observation(10, 1, (100, 0));
    let child = observation(20, 10, (101, 0));
    let mut current: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    current.pbi_ppid = 10;
    current.pbi_start_tvsec = 101;
    assert!(parent_link_is_current(&child, &parent, &current));
}

#[test]
fn pid_reuse_or_reparenting_cannot_extend_the_observed_chain() {
    let child = observation(20, 10, (101, 0));
    for (parent_started, child_started, current_parent) in [
        ((102, 0), (101, 0), 10),
        ((100, 0), (103, 0), 10),
        ((100, 0), (101, 0), 1),
    ] {
        let parent = observation(10, 1, parent_started);
        let mut current: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        current.pbi_start_tvsec = child_started.0;
        current.pbi_start_tvusec = child_started.1;
        current.pbi_ppid = current_parent;
        assert!(!parent_link_is_current(&child, &parent, &current));
    }
}

fn argument_buffer(arguments: &[&str]) -> Vec<u8> {
    let mut bytes = (arguments.len() as i32).to_ne_bytes().to_vec();
    bytes.extend(b"/nix/store/example/bin/.gh-wrapped\0\0\0\0\0\0");
    for argument in arguments {
        bytes.extend(argument.as_bytes());
        bytes.push(0);
    }
    bytes.extend(b"GH_ENTERPRISE_TOKEN=environment-canary\0");
    bytes
}

#[test]
fn arbitrary_commands_keep_all_arguments_and_never_environment() {
    for arguments in [
        vec![
            "/nix/profile/bin/gh",
            "issue",
            "reopen",
            "1",
            "--repo",
            "ashb/example",
        ],
        vec!["wiff", "forge", "pull"],
        vec!["unfamiliar-tool", "new-action", "--new-flag=value"],
        vec!["tool", "--password", "caller-supplied-value"],
    ] {
        let displayed = command_line(&argument_buffer(&arguments)).unwrap();
        let mut expected = arguments.clone();
        expected[0] = Path::new(arguments[0])
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(displayed, expected.join(" "));
        assert!(!displayed.contains("environment-canary"));
    }
    assert_eq!(
        command_line(&argument_buffer(&[
            "gh",
            "api",
            "--jq",
            "{number,state,html_url}"
        ]))
        .unwrap(),
        "gh api --jq $'{number,state,html_url}'"
    );
}

#[test]
fn native_arguments_preserve_empty_values_quotes_and_controls() {
    let bytes = argument_buffer(&["tool", "", "two words", "a'b", "line\n\u{202e}\u{1b}"]);
    assert_eq!(
        command_line(&bytes).unwrap(),
        "tool $'' $'two words' $'a\\'b' $'line\\n\\xe2\\x80\\xae\\x1b'"
    );
}

#[test]
fn leading_empty_arguments_cannot_consume_environment_entries() {
    for (arguments, expected) in [
        (vec!["", "visible"], "$'' visible"),
        (vec!["", "", "visible"], "$'' $'' visible"),
        (vec![""], "$''"),
    ] {
        assert_eq!(
            command_line(&argument_buffer(&arguments)).unwrap(),
            expected
        );
    }
}

#[test]
fn path_alignment_preserves_empty_argv_at_every_padding_length() {
    for path in [
        b"/aaaaaa\0".as_slice(),
        b"/aaaaa\0\0",
        b"/aaaa\0\0\0",
        b"/aaa\0\0\0\0",
        b"/aa\0\0\0\0\0",
        b"/a\0\0\0\0\0\0",
        b"/\0\0\0\0\0\0\0",
        b"/aaaaaaa\0\0\0\0\0\0\0\0",
    ] {
        let mut bytes = 3i32.to_ne_bytes().to_vec();
        bytes.extend(path);
        bytes.extend(b"\0\0visible\0ENV=environment-canary\0");
        assert_eq!(command_line(&bytes).unwrap(), "$'' $'' visible");
    }
}

#[test]
fn argument_count_is_bounded_by_the_capture_not_cli_syntax() {
    let mut arguments = vec!["tool"];
    arguments.extend(std::iter::repeat_n("--new-flag=value", 64));
    assert_eq!(
        command_line(&argument_buffer(&arguments)).unwrap(),
        arguments.join(" ")
    );
}

#[test]
fn malformed_or_excessive_arguments_have_no_command_context() {
    let mut unterminated = 2i32.to_ne_bytes().to_vec();
    unterminated.extend(b"/bin/gh\0gh\0api");
    let mut invalid_utf8 = 1i32.to_ne_bytes().to_vec();
    invalid_utf8.extend(b"/bin/gh\0\xff\0");
    let mut full_buffer = argument_buffer(&["tool"]);
    full_buffer.resize(COMMAND_LINE_BYTES, 0);
    for bytes in [
        vec![],
        0i32.to_ne_bytes().to_vec(),
        33i32.to_ne_bytes().to_vec(),
        unterminated,
        invalid_utf8,
        full_buffer,
    ] {
        assert!(command_line(&bytes).is_none());
    }
}

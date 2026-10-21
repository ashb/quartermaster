use super::*;

#[test]
fn special_arguments_are_quoted_without_hidden_formatting() {
    for (value, expected) in [
        ("plain", "plain"),
        ("", "$''"),
        ("two words", "$'two words'"),
        ("single'quote", r#"$'single\'quote'"#),
        ("double\"quote", r#"$'double"quote'"#),
        ("back\\slash", r#"$'back\\slash'"#),
        ("$(printf substituted)", "$'$(printf substituted)'"),
        ("`printf substituted`", "$'`printf substituted`'"),
        ("*?[pattern]", "$'*?[pattern]'"),
        ("line\n\t\u{202e}\u{1b}", r#"$'line\n\t\xe2\x80\xae\x1b'"#),
        ("é", "$'é'"),
    ] {
        assert_eq!(argument(value), expected);
    }
}

#[test]
fn nix_wrapper_names_are_normalized_only_for_binaries_in_the_store() {
    for (executable, expected) in [
        ("/nix/store/example-gh/bin/.gh-wrapped", "gh"),
        ("/nix/store/example-gh/bin/gh", "gh"),
        ("/tmp/.gh-wrapped", ".gh-wrapped"),
        (
            "/nix/store-lookalike/example/bin/.gh-wrapped",
            ".gh-wrapped",
        ),
        ("/nix/store/example/bin/.-wrapped", ".-wrapped"),
    ] {
        let path = Path::new(executable);
        assert_eq!(
            display_name(path, path.file_name().unwrap().to_str().unwrap()),
            expected
        );
    }
}

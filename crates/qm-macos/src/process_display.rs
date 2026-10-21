use std::fmt::Write;
use std::path::Path;

pub(crate) fn argument(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-+=:/.,@%".contains(&byte))
    {
        return value.to_owned();
    }
    let mut quoted = String::from("$'");
    for character in value.chars() {
        match character {
            '\'' => quoted.push_str("\\'"),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '"' => quoted.push(character),
            character if character.escape_debug().eq(std::iter::once(character)) => {
                quoted.push(character)
            }
            character => {
                let mut bytes = [0; 4];
                for byte in character.encode_utf8(&mut bytes).as_bytes() {
                    write!(quoted, "\\x{byte:02x}").unwrap();
                }
            }
        }
    }
    quoted.push('\'');
    quoted
}

pub(crate) fn display_name<'a>(executable: &Path, name: &'a str) -> &'a str {
    if executable.starts_with("/nix/store")
        && executable
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|parent| parent == "bin")
        && let Some(unwrapped) = name
            .strip_prefix('.')
            .and_then(|name| name.strip_suffix("-wrapped"))
        && !unwrapped.is_empty()
    {
        unwrapped
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
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
}

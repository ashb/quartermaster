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
#[path = "../tests/unit/process_display.rs"]
mod tests;

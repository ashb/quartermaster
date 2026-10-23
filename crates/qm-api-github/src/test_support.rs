use crate::{CapturedRequest, RequestLimits};
use hegel::{TestCase, generators as gs};

pub(crate) mod query_model;

pub(crate) fn request(method: &str, target: &str, extra: &str, body: &str) -> CapturedRequest {
    let raw = raw_request(method, target, extra, body);
    CapturedRequest::parse(raw.as_bytes(), RequestLimits::default()).unwrap()
}

pub(crate) fn raw_request(method: &str, target: &str, extra: &str, body: &str) -> String {
    format!(
        "{method} {target} HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[derive(Debug)]
pub(crate) struct GraphqlSyntax {
    aliases: bool,
    string_form: u8,
    fragment_form: u8,
    fragment_depth: u8,
    pub separator: &'static str,
}

impl GraphqlSyntax {
    pub(crate) fn plain() -> Self {
        Self {
            aliases: false,
            string_form: 0,
            fragment_form: 0,
            fragment_depth: 0,
            separator: " ",
        }
    }

    pub(crate) fn dense() -> Self {
        Self {
            aliases: true,
            string_form: 1,
            fragment_form: 1,
            fragment_depth: 2,
            separator: ", ",
        }
    }

    pub(crate) fn draw(tc: &TestCase) -> Self {
        Self {
            aliases: tc.draw(gs::booleans()),
            string_form: tc.draw(gs::integers::<u8>().max_value(2)),
            fragment_form: tc.draw(gs::integers::<u8>().max_value(1)),
            fragment_depth: tc.draw(gs::integers::<u8>().max_value(2)),
            separator: tc.draw(gs::sampled_from(&[" ", ", ", "\n# request trivia\n"])),
        }
    }

    pub(crate) fn field(&self, name: &str, index: usize) -> String {
        if self.aliases {
            format!("alias_{index}{0}:{0}{name}", self.separator)
        } else {
            name.into()
        }
    }

    pub(crate) fn string(&self, value: &str) -> String {
        match self.string_form {
            0 => serde_json::to_string(value).unwrap(),
            1 => format!(
                "\"{}\"",
                value
                    .chars()
                    .map(|character| format!("\\u{:04x}", u32::from(character)))
                    .collect::<String>()
            ),
            _ => format!("\"\"\"\n  {value}\n\"\"\""),
        }
    }

    pub(crate) fn operation(&self, kind: &str, variables: &str, selection: &str) -> String {
        let context = if kind == "mutation" {
            "Mutation"
        } else {
            "Query"
        };
        let separator = self.separator;
        let mut selection = selection.to_owned();
        let mut fragments = String::new();
        for index in 0..self.fragment_depth {
            if self.fragment_form == 0 {
                selection =
                    format!("...{separator}on{separator}{context}{separator}{{{selection}}}");
            } else {
                fragments.push_str(&format!(
                    "{separator}fragment{separator}Fields{index}{separator}on{separator}{context}{separator}{{{selection}}}"
                ));
                selection = format!("...{separator}Fields{index}");
            }
        }
        format!("{kind}{separator}Selected{variables}{separator}{{{selection}}}{fragments}")
    }
}

pub(crate) fn graphql(
    query: &str,
    variables: serde_json::Value,
    operation: Option<&str>,
) -> CapturedRequest {
    let body = serde_json::json!({"query":query, "variables":variables, "operationName":operation})
        .to_string();
    request(
        "POST",
        "/graphql",
        "Content-Type: application/json\r\n",
        &body,
    )
}

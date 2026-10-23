use hegel::{TestCase, generators as gs};
use serde_json::{Value, json};

struct Renderer<'a> {
    tc: &'a TestCase,
    sequence: usize,
    fragments: Vec<String>,
    number_variable: bool,
    string_form: u8,
}

impl Renderer<'_> {
    fn identifier(&mut self, prefix: &str) -> String {
        self.sequence += 1;
        format!("{prefix}{}", self.sequence)
    }

    fn string(&self, value: &str) -> String {
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

    fn guard(&self) -> &'static str {
        self.tc.draw(gs::sampled_from(&[
            "",
            "@include(if:true)",
            "@skip(if:false)",
            "@include(if:$go)",
            "@skip(if:$go)",
            "@include(if:$go) @skip(if:false)",
            "@skip(if:$go) @include(if:true)",
        ]))
    }

    fn field(&mut self, name: &str, arguments: &str, selection: &str) -> String {
        let alias = self.identifier("f");
        let guard = self.guard();
        if selection.is_empty() {
            format!("{alias}:{name}{arguments} {guard}")
        } else {
            format!("{alias}:{name}{arguments} {guard}{{{selection}}}")
        }
    }

    fn wrap(&mut self, ty: &str, selection: String, repeat: bool) -> String {
        match self
            .tc
            .draw(gs::integers::<u8>().max_value(if repeat { 3 } else { 2 }))
        {
            0 => selection,
            1 => format!("... on {ty} {} {{{selection}}}", self.guard()),
            mode => {
                let name = self.identifier("Fields");
                self.fragments
                    .push(format!("fragment {name} on {ty}{{{selection}}}"));
                let spread = format!("...{name} {}", self.guard());
                if mode == 3 {
                    format!("{spread} {spread}")
                } else {
                    spread
                }
            }
        }
    }

    fn issue(&mut self, depth: u8) -> String {
        let mut fields = String::from("title number");
        if depth > 0 {
            let repository = self.repository(depth - 1);
            fields.push(' ');
            fields.push_str(&self.field("repository", "", &repository));
        }
        self.wrap("Issue", fields, depth == 0)
    }

    fn repository(&mut self, depth: u8) -> String {
        let mut fields = String::from("name @include(if:$go)");
        let number = if self.number_variable {
            "$number".into()
        } else {
            self.tc
                .draw(gs::integers::<u16>().min_value(1).max_value(1000))
                .to_string()
        };
        let issue = self.issue(depth);
        fields.push_str(&self.field("issue", &format!("(number:{number})"), &issue));
        if self.tc.draw(gs::booleans()) {
            let issue = self.issue(depth);
            let states = self.tc.draw(gs::sampled_from(&[
                "",
                ",states:[OPEN,CLOSED]",
                ",states:OPEN",
                ",states:null",
            ]));
            let limit = self
                .tc
                .draw(gs::integers::<u8>().min_value(1).max_value(100));
            let connection = format!(
                "nodes{{{issue}}} edges{{node{{{issue}}} cursor}} pageInfo{{hasNextPage endCursor}} totalCount"
            );
            fields.push_str(&self.field(
                "issues",
                &format!("(first:{limit}{states})"),
                &connection,
            ));
        }
        if self.tc.draw(gs::booleans()) {
            fields.push_str(&self.field("future", "", ""));
        }
        self.wrap("Repository", fields, depth == 0)
    }

    fn query(&mut self, default: bool, number: u16) -> String {
        self.number_variable = true;
        let count = self.tc.draw(gs::integers::<u8>().min_value(1).max_value(3));
        let depth = self.tc.draw(gs::integers::<u8>().max_value(2));
        let mut fields = String::new();
        for index in 0..count {
            let owner = if index == 0 {
                "$owner".into()
            } else {
                self.string(self.tc.draw(gs::sampled_from(&["scope", "outside"])))
            };
            let name = self.string("repository");
            let selection = self.repository(depth);
            fields.push_str(&self.field(
                "repository",
                &format!("(owner:{owner},name:{name})"),
                &selection,
            ));
        }
        let fields = self.wrap("Query", fields, true);
        format!(
            "query Read($go:Boolean!={default},$owner:String!={},$number:Int!={number}){{{fields}}}",
            self.string("scope")
        )
    }

    fn mutation(&mut self, default: bool) -> String {
        self.number_variable = false;
        let count = self.tc.draw(gs::integers::<u8>().min_value(1).max_value(3));
        let mut fields = String::new();
        for index in 0..count {
            let close = self.tc.draw(gs::booleans());
            let id = if index == 0 {
                "$id".into()
            } else {
                self.string(&format!("issue-{index}"))
            };
            let mut payload = String::from("clientMutationId @include(if:$go)");
            if close && self.tc.draw(gs::booleans()) {
                let issue = self.issue(self.tc.draw(gs::integers::<u8>().max_value(2)));
                payload.push_str(&format!("issue{{{issue}}}"));
            }
            let payload = self.wrap(
                if close {
                    "CloseIssuePayload"
                } else {
                    "DeleteIssuePayload"
                },
                payload,
                false,
            );
            fields.push_str(&self.field(
                if close { "closeIssue" } else { "deleteIssue" },
                &format!("(input:{{issueId:{id}}})"),
                &payload,
            ));
        }
        let fields = self.wrap("Mutation", fields, true);
        format!(
            "mutation Write($go:Boolean!={default},$id:ID!={}){{{fields}}}",
            self.string("first-issue")
        )
    }
}

#[hegel::composite]
pub fn requests(tc: &TestCase) -> Value {
    let default = tc.draw(gs::booleans());
    let number = tc.draw(gs::integers::<u16>().min_value(1).max_value(1000));
    let mut renderer = Renderer {
        tc,
        sequence: 0,
        fragments: Vec::new(),
        number_variable: false,
        string_form: tc.draw(gs::integers::<u8>().max_value(2)),
    };
    let query = renderer.query(default, number);
    let mutation = renderer.mutation(default);
    if tc.draw(gs::booleans()) {
        renderer.fragments.reverse();
    }
    let document = format!("{query} {mutation} {}", renderer.fragments.join("\n"));
    let read = tc.draw(gs::booleans());
    let mut variables = json!({});
    if tc.draw(gs::booleans()) {
        variables["go"] = json!(tc.draw(gs::booleans()));
    }
    if read {
        if tc.draw(gs::booleans()) {
            variables["owner"] = json!(tc.draw(gs::sampled_from(&["scope", "outside"])));
        }
        if tc.draw(gs::booleans()) {
            variables["number"] =
                json!(tc.draw(gs::integers::<u16>().min_value(1).max_value(1000)));
        }
    } else if tc.draw(gs::booleans()) {
        variables["id"] = json!("supplied-issue");
    }
    tc.event_value("fragments", renderer.fragments.len() as f64);
    tc.event_value("document bytes", document.len() as f64);
    tc.event(if read {
        "selected Read"
    } else {
        "selected Write"
    });
    json!({"query":document,"variables":variables,"operationName":if read { "Read" } else { "Write" }})
}

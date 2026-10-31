import Foundation
import Testing

@testable import QuartermasterSecurity

private func apiFixture() throws -> [String: Any] {
    let url = try #require(
        Bundle.module.url(forResource: "github-request-review", withExtension: "json", subdirectory: "Fixtures"))
    return try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
}

private func reviewBody(
    _ body: String, headers: String = "Content-Type: application/json\r\n", path: String = "/graphql?option=%2f"
) throws
    -> APIRequestReview
{
    var fixture = try apiFixture()
    var application = try #require(fixture["application"] as? [String: Any])
    application["request"] = Data("POST \(path) HTTP/1.1\r\n\(headers)\r\n\(body)".utf8)
        .base64EncodedString()
    fixture["application"] = application
    let data = try JSONSerialization.data(withJSONObject: fixture)
    return try #require(try APIRequestReview.parse(request: data))
}

@Test func readableRequestsDecodeQueriesAndRetainEveryEnvelopeField() throws {
    let body =
        #"{"query":"\n\tquery AnyName { repository { id } }\n","variables":{"n":9007199254740993},"operationName":"AnyName","extensions":{"future":1.2300e+9}}"#
    let review = try reviewBody(body)
    let readable = try #require(review.readableText)
    #expect(
        readable == """
            POST /graphql?option=%2f HTTP/1.1
            Content-Type: application/json

            "query" (decoded string):
              query AnyName {
                repository {
                  id
                }
              }

            "variables":
              {
                "n": 9007199254740993
              }

            "operationName":
              "AnyName"

            "extensions":
              {
                "future": 1.2300e+9
              }
            """)
    #expect(review.text.hasSuffix(body.replacingOccurrences(of: "\\", with: "\\\\")))
}

@Test(arguments: [
    (
        #"{"query":"query PullRequestByNumber($number: Int!) { repository { pullRequest(number: $number) { id } } }","variables":{"number":2}}"#,
        "query PullRequestByNumber · number: 2"
    ),
    (
        #"{"query":"query Read { viewer { id } } mutation Reopen($id: ID!) { reopenIssue(input:{issueId:$id}) { clientMutationId } }","operationName":"Reopen","variables":{"id":"I_one"}}"#,
        "mutation Reopen · id: \"I_one\""
    ),
    (#"{"query":"fragment Info on User { id } # query Decoy\nquery Actual { viewer { ...Info } }"}"#, "query Actual"),
    (#"{"query":"{ viewer { id } }"}"#, "query"),
    (#"{"query":"query @skip(if: false) { viewer { id } }"}"#, "query"),
    (
        #"{"query":"query Number { viewer { id } }","variables":{"n":9007199254740993}}"#,
        "query Number · n: 9007199254740993"
    ),
])
func graphQLPreviewShowsTheSelectedOperationAndLiteralVariables(_ body: String, _ expected: String) throws {
    #expect(try reviewBody(body).graphQLSummary == expected)
}

@Test(arguments: [
    #"{"query":"query A { viewer { id } } query B { viewer { login } }"}"#,
    #"{"query":"query A { viewer { id } }","operationName":"Missing"}"#,
    #"{"query":"query A { viewer { id } }","query":"mutation B { f }"}"#,
    #"{"query":"query A { viewer { id } }","variables":{"n":1,"n":2}}"#,
    #"{"query":"query A { unfinished"}"#,
])
func ambiguousGraphQLHasNoCompactOperationPreview(_ body: String) throws {
    #expect(try reviewBody(body).graphQLSummary == nil)
}

@Test func graphQLPreviewIsBoundedAndEscapesControlCharactersInVariables() throws {
    let body = try JSONSerialization.data(withJSONObject: [
        "query": "query Lookup { viewer { id } }",
        "variables": ["id\u{202e}": "\u{1b}" + String(repeating: "x", count: 300)],
    ])
    let preview = try #require(try reviewBody(String(decoding: body, as: UTF8.self)).graphQLSummary)
    #expect(!preview.contains("\u{202e}") && !preview.contains("\u{1b}"))
    #expect(preview.contains("\\u{202e}"))
    #expect(preview.count <= 241)
    #expect(preview.hasSuffix("…"))
}

@Test func aQueryFieldInARestBodyDoesNotBecomeAGraphQLPreview() throws {
    #expect(
        try reviewBody(#"{"query":"query Search { viewer { id } }"}"#, path: "/search/issues").graphQLSummary == nil)
}

@Test(arguments: [
    #"{"query":"one","query":"two"}"#,
    #"{"query":"one","qu\u0065ry":"two"}"#,
    #"{"query":"one","variables":{"x":1,"x":2}}"#,
    #"{"query":"one","extensions":[{"x":1,"x":2}]}"#,
    #"{"query":"unfinished}"#,
    #"{"query":"one"} trailing"#,
])
func ambiguousOrMalformedJSONKeepsTheRawView(_ body: String) throws {
    let review = try reviewBody(body)
    #expect(review.readableText == nil)
    #expect(review.text.hasSuffix(body.replacingOccurrences(of: "\\", with: "\\\\")))
}

@Test func decodedQueriesCannotHideControlBytes() throws {
    let review = try reviewBody(#"{"query":"query { f(arg: \"\\n\") }\n\t\u001b\u0000\u202e"}"#)
    let readable = try #require(review.readableText)
    #expect(readable.contains(#"f(arg: "\\n")"#))
    #expect(readable.contains("\n  \t\\x1b\\x00\\xe2\\x80\\xae"))
    #expect(!readable.contains("\u{1b}") && !readable.contains("\u{202e}"))
}

@Test(arguments: [
    "Content-Type: text/plain\r\n", "Content-Type: application/json\r\nContent-Type: text/plain\r\n", "",
    "Content-Type: application/json\r\nContent-Type:\r\n",
])
func readableJSONRequiresAnUnambiguousContentType(_ headers: String) throws {
    let review = try reviewBody(#"{"query":"query { viewer { login } }"}"#, headers: headers)
    #expect(review.readableText == nil)
    #expect(review.graphQLSummary == nil)
}

@Test func genericJSONFormattingPreservesArraysAndScalarSpellings() throws {
    let review = try reviewBody(#"[{},[],true,null,-0,1.2300e+9,"literal\\path"]"#)
    let readable = try #require(review.readableText)
    #expect(
        readable == "POST /graphql?option=%2f HTTP/1.1\nContent-Type: application/json\n\n" + """
            [
              {},
              [],
              true,
              null,
              -0,
              1.2300e+9,
              "literal\\\\\\\\path"
            ]
            """)
}

@Test func deeplyNestedJSONKeepsTheRawView() throws {
    let body = String(repeating: "[", count: 65) + "0" + String(repeating: "]", count: 65)
    let review = try reviewBody(body)
    #expect(review.readableText == nil)
    #expect(review.text.hasSuffix(body))
}

@Test func oversizedFormattedJSONKeepsTheCompleteRawView() throws {
    let values = Array(repeating: "0", count: 5000).joined(separator: ",")
    let body = String(repeating: "[", count: 60) + values + String(repeating: "]", count: 60)
    let review = try reviewBody(body)
    #expect(review.readableText == nil)
    #expect(review.text.hasSuffix(body))
}

@Test func apiReviewShowsTheCompleteRequestProducedByRustWithoutGrantingScope() throws {
    let data = try JSONSerialization.data(withJSONObject: apiFixture())
    let review = try #require(try APIRequestReview.parse(request: data))
    #expect(review.text.hasPrefix("POST /graphql?option=%2f HTTP/1.1\n"))
    #expect(review.text.contains("X-Custom: first\nx-custom: second"))
    #expect(review.text.contains("<selected Quartermaster credential>"))
    #expect(review.text.hasSuffix("{ \"query\": \"query { viewer { login } }\", \"variables\": {} }"))
    #expect(!review.text.contains("caller-placeholder"))
}

@Test(arguments: [
    ("first\r\nsecond\r\n", "first\nsecond\n"),
    ("first\nsecond\n", "first\nsecond\n"),
    ("first\rsecond\r", "first\\rsecond\\r"),
    ("literal \\r\\n", "literal \\\\r\\\\n"),
    ("\t\u{1b}", "\\x09\\x1b"),
])
func apiReviewShowsLineBreaksWithoutHidingOtherControls(_ body: String, _ expected: String) throws {
    var fixture = try apiFixture()
    var application = try #require(fixture["application"] as? [String: Any])
    application["request"] = Data("POST /graphql?option=%2f HTTP/1.1\r\n\r\n\(body)".utf8).base64EncodedString()
    fixture["application"] = application
    let data = try JSONSerialization.data(withJSONObject: fixture)
    let review = try #require(try APIRequestReview.parse(request: data))
    #expect(review.text == "POST /graphql?option=%2f HTTP/1.1\n\n\(expected)")
}

@Test(arguments: ["version", "method", "origin", "digest"])
func apiReviewFormatsTheSuppliedCaptureWithoutInterpretingBackendPolicy(_ field: String) throws {
    var fixture = try apiFixture()
    var application = try #require(fixture["application"] as? [String: Any])
    switch field {
    case "version": application["version"] = "unsupported"
    case "method": fixture["method"] = "DELETE"
    case "origin": fixture["origin"] = "https://another.example"
    default: application["originalDigest"] = Data([1]).base64EncodedString()
    }
    fixture["application"] = application
    let data = try JSONSerialization.data(withJSONObject: fixture)
    let review = try #require(try APIRequestReview.parse(request: data))
    #expect(review.text.hasPrefix("POST /graphql?option=%2f HTTP/1.1\n"))
}

@Test func apiReviewEscapesBinaryAndControlBytesWithoutDroppingThem() throws {
    var fixture = try apiFixture()
    var application = try #require(fixture["application"] as? [String: Any])
    var wire = Data("POST /graphql?option=%2f HTTP/1.1\r\nContent-Type: application/json\r\n\r\n".utf8)
    wire.append(contentsOf: [0, 255, 92, 27])
    application["request"] = wire.base64EncodedString()
    fixture["application"] = application
    let data = try JSONSerialization.data(withJSONObject: fixture)
    let review = try #require(try APIRequestReview.parse(request: data))
    #expect(review.text.hasSuffix("\\x00\\xff\\\\\\x1b"))
    #expect(!review.text.contains("\u{1b}"))
    #expect(review.readableText == nil)
}

@Test func invalidCaptureEncodingFailsDecoding() throws {
    #expect(throws: DecodingError.self) {
        try APIRequestReview.parse(request: Data(#"{"application":{"request":"not base64"}}"#.utf8))
    }
    #expect(try APIRequestReview.parse(request: Data("{}".utf8)) == nil)
}

@Test func graphQLDisplayIndentsNestedSelectionsWithoutChangingTheRawRequest() throws {
    let query = "query Example($id: ID!) { node(id: $id) { ... on Repository { name } } }"
    let pretty = try #require(GraphQLDisplayFormat.readable(query))
    #expect(
        pretty == """
            query Example($id: ID!) {
              node(id: $id) {
                ... on Repository {
                  name
                }
              }
            }
            """)
    let data = try JSONSerialization.data(withJSONObject: ["query": query])
    let body = String(decoding: data, as: UTF8.self)
    let review = try reviewBody(body)
    #expect(try #require(review.readableText).contains("\n        name\n"))
    #expect(review.text.hasSuffix(body.replacingOccurrences(of: "\\", with: "\\\\")))
}

@Test func graphQLDisplayPreservesStringsCommentsArgumentsAndFragmentSyntax() throws {
    let literal = #""escaped \" { } # \\""#
    let source = """
        query Example($input: Input = {weight:-1.2300e+9, flags:[true,false]}) @include(if:true) { f(arg:\(literal)) { ...Fields # keep } { \" visible
        id } } fragment Fields on Node { name }
        """
    let formatted = try #require(GraphQLDisplayFormat.readable(source))
    #expect(formatted.contains(literal))
    #expect(formatted.contains("weight:-1.2300e+9, flags:[true,false]"))
    #expect(formatted.contains("@include(if:true)"))
    #expect(formatted.contains("...Fields # keep } { \" visible\n"))
    #expect(formatted.contains("fragment Fields on Node {\n  name\n}"))
}

@Test func graphQLDisplayCopiesBlockStringsIncludingEscapedTripleQuotes() throws {
    let block = "\"\"\"first\n  # { not syntax }\n  \\\"\"\" escaped delimiter\nlast\"\"\""
    let source = "query { f(arg:\(block)) { id } }"
    let formatted = try #require(GraphQLDisplayFormat.readable(source))
    #expect(formatted.contains(block))
    #expect(formatted.hasSuffix("{\n    id\n  }\n}"))
}

@Test(arguments: [
    "query { field( }", "query { field", "query { field } }", "query { f(arg: \"unfinished) }",
    #"query { f(arg: "invalid\q") }"#, "query { f(arg: \"\"\"unfinished) }", "query { future^syntax }",
    "query { f(arg: 1.2.3) }", "query { f(arg: 1e+) }", "query { f(arg: 01) }",
])
func uncertainGraphQLDisplayFallsBackToTheOriginalDecodedQuery(_ source: String) throws {
    #expect(GraphQLDisplayFormat.readable(source) == nil)
    let data = try JSONSerialization.data(withJSONObject: ["query": source])
    let readable = try #require(JSONRequestBody.readable(data))
    #expect(readable == "\"query\" (decoded string):\n  " + source)
}

@Test func graphQLDisplayBoundsNestingAndExpandedOutput() {
    let deep = String(repeating: "{", count: 65) + "id" + String(repeating: "}", count: 65)
    #expect(GraphQLDisplayFormat.readable(deep) == nil)
    let expansive =
        String(repeating: "{", count: 60) + String(repeating: "f { id } ", count: 3000)
        + String(repeating: "}", count: 60)
    #expect(expansive.utf8.count < BrokerLimits.reviewBytes)
    #expect(GraphQLDisplayFormat.readable(expansive) == nil)
}

import Foundation
import Testing

@testable import QuartermasterSecurity

private func apiFixture() throws -> [String: Any] {
    let url = try #require(
        Bundle.module.url(forResource: "github-request-review", withExtension: "json", subdirectory: "Fixtures"))
    return try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
}

private func reviewBody(_ body: String, headers: String = "Content-Type: application/json\r\n") throws
    -> APIRequestReview
{
    var fixture = try apiFixture()
    var application = try #require(fixture["application"] as? [String: Any])
    application["request"] = Data("POST /graphql?option=%2f HTTP/1.1\r\n\(headers)\r\n\(body)".utf8)
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
            \("  ")
              \tquery AnyName { repository { id } }
            \("  ")

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
    #expect(!review.complete)
    #expect(review.effects.isEmpty)
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
func apiReviewRejectsUnsupportedOrInconsistentCaptureBindings(_ field: String) throws {
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
    #expect(throws: APIRequestReview.Failure.self) { try APIRequestReview.parse(request: data) }
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

@Test(arguments: [("quartermaster/one", false), ("owner/repo/extra", true), ("owner/space name", true)])
func repositoryDisplayContextRequiresACompleteAnalysisAndAValidName(_ repository: String, _ complete: Bool) throws {
    var fixture = try apiFixture()
    var application = try #require(fixture["application"] as? [String: Any])
    application["requestedRepository"] = repository
    application["complete"] = complete
    fixture["application"] = application
    let bytes = try JSONSerialization.data(withJSONObject: fixture)
    #expect(throws: APIRequestReview.Failure.self) { try APIRequestReview.parse(request: bytes) }
}

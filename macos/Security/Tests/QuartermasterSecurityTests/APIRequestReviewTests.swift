import Foundation
import Testing

@testable import QuartermasterSecurity

private func apiFixture() throws -> [String: Any] {
    let url = try #require(
        Bundle.module.url(forResource: "github-request-review", withExtension: "json", subdirectory: "Fixtures"))
    return try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
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
    var wire = Data("POST /graphql?option=%2f HTTP/1.1\r\n\r\n".utf8)
    wire.append(contentsOf: [0, 255, 92, 27])
    application["request"] = wire.base64EncodedString()
    fixture["application"] = application
    let data = try JSONSerialization.data(withJSONObject: fixture)
    let review = try #require(try APIRequestReview.parse(request: data))
    #expect(review.text.hasSuffix("\\x00\\xff\\\\\\x1b"))
    #expect(!review.text.contains("\u{1b}"))
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

import Foundation
import Testing
@testable import QuartermasterSecurity

@Test func monotonicTimestampPreservesNanosecondWirePrecisionAndRejectsReverseTime() throws {
    let decoder = JSONDecoder()
    let earlier = try decoder.decode(MonotonicTimestamp.self, from: Data("100000000000".utf8))
    let later = try decoder.decode(MonotonicTimestamp.self, from: Data("120000000001".utf8))

    #expect(try later.duration(since: earlier) == .seconds(20) + .nanoseconds(1))
    #expect(throws: MonotonicTimestamp.Failure.self) { try earlier.duration(since: later) }
    #expect(try String(decoding: JSONEncoder().encode(later), as: UTF8.self) == "120000000001")
}

@Test func monotonicTimestampRejectsOverflowAndNegativeDurations() throws {
    let last = try JSONDecoder().decode(MonotonicTimestamp.self, from: Data("18446744073709551615".utf8))

    #expect(throws: MonotonicTimestamp.Failure.self) { try last.advanced(by: .nanoseconds(1)) }
    #expect(throws: MonotonicTimestamp.Failure.self) { try last.advanced(by: .seconds(-1)) }
    #expect(throws: DecodingError.self) { try JSONDecoder().decode(MonotonicTimestamp.self, from: Data("-1".utf8)) }
}

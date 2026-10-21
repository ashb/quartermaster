import Darwin
import Foundation

public struct MonotonicTimestamp: Codable, Comparable, Sendable {
    public enum Failure: Error { case reversedTime, invalidDuration, overflow }
    private let nanoseconds: UInt64

    public static var now: Self { Self(nanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)) }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.nanoseconds < rhs.nanoseconds }

    public var isZero: Bool { nanoseconds == 0 }
    public var serializedNanoseconds: UInt64 { nanoseconds }

    public func duration(since earlier: Self) throws -> Duration {
        guard self >= earlier else { throw Failure.reversedTime }
        let elapsed = nanoseconds - earlier.nanoseconds
        return .seconds(Int64(elapsed / 1_000_000_000)) + .nanoseconds(Int64(elapsed % 1_000_000_000))
    }

    public func advanced(by duration: Duration) throws -> Self {
        let (seconds, attoseconds) = duration.components
        guard seconds >= 0, attoseconds >= 0, attoseconds % 1_000_000_000 == 0 else { throw Failure.invalidDuration }
        let (whole, wholeOverflow) = UInt64(seconds).multipliedReportingOverflow(by: 1_000_000_000)
        let (offset, offsetOverflow) = whole.addingReportingOverflow(UInt64(attoseconds / 1_000_000_000))
        let (result, overflow) = nanoseconds.addingReportingOverflow(offset)
        guard !wholeOverflow, !offsetOverflow, !overflow else { throw Failure.overflow }
        return Self(nanoseconds: result)
    }

    private init(nanoseconds: UInt64) { self.nanoseconds = nanoseconds }

    public init(from decoder: any Decoder) throws {
        nanoseconds = try decoder.singleValueContainer().decode(UInt64.self)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(nanoseconds)
    }
}

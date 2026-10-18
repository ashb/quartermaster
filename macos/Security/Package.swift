// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "QuartermasterSecurity",
    platforms: [.macOS(.v15)],
    products: [.library(name: "QuartermasterSecurity", targets: ["QuartermasterSecurity"])],
    targets: [
        .target(name: "QuartermasterSecurity"),
        .testTarget(name: "QuartermasterSecurityTests", dependencies: ["QuartermasterSecurity"]),
    ]
)

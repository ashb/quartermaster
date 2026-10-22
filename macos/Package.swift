// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Quartermaster",
    platforms: [.macOS("26.0")],
    products: [
        .executable(name: "Quartermaster", targets: ["Quartermaster"]),
        .library(name: "QuartermasterApprovalUI", targets: ["QuartermasterApprovalUI"]),
        .executable(name: "QuartermasterIntegrationTests", targets: ["QuartermasterIntegrationTests"]),
    ],
    dependencies: [.package(path: "Security")],
    targets: [
        .target(
            name: "QuartermasterApprovalUI",
            dependencies: [.product(name: "QuartermasterSecurity", package: "Security")],
            path: "ApprovalUI"),
        .executableTarget(
            name: "QuartermasterIntegrationTests",
            dependencies: ["QuartermasterApprovalUI", .product(name: "QuartermasterSecurity", package: "Security")],
            path: "Tests"),
        .executableTarget(
            name: "Quartermaster",
            dependencies: ["QuartermasterApprovalUI", .product(name: "QuartermasterSecurity", package: "Security")],
            path: "Quartermaster",
            exclude: ["Info.plist", "Backend-Info.plist", "Quartermaster.entitlements", "Backend.entitlements"]),
    ]
)

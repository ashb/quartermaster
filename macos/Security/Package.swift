// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "QuartermasterSecurity",
    platforms: [.macOS(.v15)],
    products: [.library(name: "QuartermasterSecurity", targets: ["QuartermasterSecurity"])],
    targets: [
        .target(name: "QuartermasterIPC", publicHeadersPath: "include",
                linkerSettings: [.linkedFramework("Foundation"), .linkedFramework("LocalAuthentication")]),
        .target(name: "QuartermasterSecurity", dependencies: ["QuartermasterIPC"]),
        .testTarget(name: "QuartermasterSecurityTests", dependencies: ["QuartermasterSecurity", "QuartermasterIPC"],
                    resources: [.copy("Fixtures")]),
    ]
)

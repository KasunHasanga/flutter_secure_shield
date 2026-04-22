// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "flutter_secure_shield",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(name: "flutter-secure-shield", targets: ["flutter_secure_shield"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "flutter_secure_shield",
            dependencies: [],
            path: "Classes",
            resources: []
        )
    ]
)

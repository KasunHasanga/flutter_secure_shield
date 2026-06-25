// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "flutter_secure_shield",
    platforms: [
        .iOS("13.0")
    ],
    products: [
        .library(name: "flutter-secure-shield", targets: ["flutter_secure_shield"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework")
    ],
    targets: [
        .target(
            name: "flutter_secure_shield",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework")
            ],
            resources: []
        )
    ]
)

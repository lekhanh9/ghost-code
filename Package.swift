// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "GhostCode",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(
            name: "GhostCode",
            targets: ["GhostCode"]
        ),
    ],
    targets: [
        .target(
            name: "GhostCode"
        ),
        .testTarget(
            name: "GhostCodeTests",
            dependencies: ["GhostCode"]
        ),
    ]
)

// swift-tools-version:5.9

// A manifest for WireGuardKit, because upstream's does not build.
//
// `wireguard-apple`'s own Package.swift declares `swift-tools-version:5.3` and
// then uses `.iOS(.v15)`, which PackageDescription only gained in 5.5. Older
// SwiftPM let that through; the one in Xcode 26 does not, and rejects the
// manifest outright:
//
//     'v15' was introduced in PackageDescription 5.5
//
// The fix is one line, in a repository nobody here can push to. So the upstream
// sources are fetched unmodified into `upstream/` — pinned to the revision in
// ../../WIREGUARD_REVISION, never a branch — and compiled through this manifest
// instead. The target graph below is upstream's, unchanged.

import PackageDescription

let package = Package(
    name: "WireGuardKit",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(name: "WireGuardKit", targets: ["WireGuardKit"])
    ],
    targets: [
        .target(
            name: "WireGuardKit",
            dependencies: ["WireGuardKitGo", "WireGuardKitC"],
            path: "upstream/Sources/WireGuardKit"
        ),
        .target(
            name: "WireGuardKitC",
            path: "upstream/Sources/WireGuardKitC",
            publicHeadersPath: "."
        ),
        // Go sources and a Makefile, not a library. `-lwg-go` is a promise that
        // something else will have produced libwg-go.a by link time; the
        // tunnel target's pre-build step is what keeps it.
        .target(
            name: "WireGuardKitGo",
            path: "upstream/Sources/WireGuardKitGo",
            exclude: [
                "goruntime-boottime-over-monotonic.diff",
                "go.mod",
                "go.sum",
                "api-apple.go",
                "Makefile",
            ],
            publicHeadersPath: ".",
            linkerSettings: [.linkedLibrary("wg-go")]
        ),
    ]
)

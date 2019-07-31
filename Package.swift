// swift-tools-version:4.0
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "swift-nio-ssl",
    products: [
        .library(name: "NIOOpenSSL", targets: ["NIOOpenSSL"]),
        .executable(name: "NIOTLSServer", targets: ["NIOTLSServer"]),
    ],
    dependencies: [
        .package(url: "https://github.com/readdle/swift-nio.git", .branch("1.14.1-android")),
        .package(url: "https://github.com/readdle/swift-openssl-prebuilt.git", .exact("0.0.3"))
    ],
    targets: [
        .target(name: "CNIOOpenSSL"),
        .target(name: "NIOOpenSSL",
                dependencies: ["NIO", "NIOConcurrencyHelpers", "CNIOOpenSSL", "NIOTLS"]),
        .target(name: "NIOTLSServer", dependencies: ["NIO", "NIOOpenSSL", "NIOConcurrencyHelpers"]),
        .testTarget(name: "NIOOpenSSLTests", dependencies: ["NIOTLS", "NIOOpenSSL"]),
    ]
)

# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI for Linux, macOS and Windows, including build, tests,
  formatting, Clippy and package verification.
- A tag-triggered crates.io publishing workflow and documented release process.
- crates.io metadata, dual `MIT OR Apache-2.0` licensing and third-party notices.
- A unique crates.io package name, `nightwatch-ndr` (the `nightwatch` name is
  already occupied).

## [0.1.0] - 2025-11-18

### Added
- Offline PCAP analysis with Ethernet, IPv4, IPv6, TCP, UDP, DNS and ICMP parsing.
- Modular detection engine, declarative hot-reloadable rules, SQLite event
  storage, incident correlation and JSON reporting.
- Linux, macOS and Windows platform paths and key-file handling.
- qs_crypt-backed SHA3-256 report digests and ChaCha20-Poly1305 sealed reports.
- Synthetic PCAP fixtures and integration tests.

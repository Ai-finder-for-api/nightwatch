# NIGHTWATCH — Network Threat Detection Engine

[![CI](https://github.com/Ai-finder-for-api/nightwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/Ai-finder-for-api/nightwatch/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/nightwatch-ndr.svg)](https://crates.io/crates/nightwatch-ndr)
[![docs.rs](https://docs.rs/nightwatch-ndr/badge.svg)](https://docs.rs/nightwatch-ndr)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

A passive, modular network security engine in Rust (stable) with a Tokio
pipeline and SQLite storage. It decodes captured traffic, runs declarative
detection rules, stores findings, correlates them into incidents and exports
JSON. It never transmits packets or probes external systems.

> **Package name:** `nightwatch-ndr`. The crates.io name `nightwatch` is already
> registered by another crate. The installed executable is `nightwatch`, and the
> Rust library crate is `nightwatch_ndr`. The crate is prepared for publishing,
> but version 0.1.0 is not published yet; see [PUBLISHING.md](PUBLISHING.md).

## Install and build

```sh
cargo install nightwatch-ndr --bin nightwatch   # once published
# Or, from a checkout:
cargo build --release
cargo test --locked --all-targets
```

GitHub Actions builds and tests every push and pull request on Ubuntu, Windows
and macOS, runs Rustfmt/Clippy, and verifies the crates.io package. A separate
tag-triggered workflow publishes to crates.io after the
`CARGO_REGISTRY_TOKEN` repository secret is configured.

## Quick start (offline analysis)

```sh
nightwatch gen-fixtures fixtures/sample_attacks.pcap
nightwatch analyze fixtures/sample_attacks.pcap --db nightwatch.db --json fixtures/sample_findings.json
nightwatch incidents --db nightwatch.db
nightwatch report --db nightwatch.db --out report.json
nightwatch rules validate rules/default.json
nightwatch rules list rules/default.json
nightwatch rules watch rules/default.json     # hot reload on file change
```

## CLI

| Command | Purpose |
|---|---|
| `analyze <pcap>` | Offline PCAP analysis, stores findings in SQLite, optional JSON export |
| `monitor --iface` | Live capture. **Not implemented in this build** (reports an error; no libpcap/raw-socket backend) |
| `rules validate\|list\|watch` | Rule management and hot reload |
| `alerts [--json]` | List stored alerts |
| `incidents [--gap-secs]` | Correlated incidents with timelines |
| `report --out` | Full JSON report (findings + incidents) |
| `keygen` | Generate a 256-bit sealed-report key file |
| `report --seal` | Encrypt and authenticate the report with qs_crypt |
| `unseal <file>` | Verify and decrypt a sealed report |
| `info` | Show platform, crypto backend and capture interfaces |
| `gen-fixtures <out>` | Write the synthetic sample capture |

## Architecture (independent modules, `src/`)

- `pcap` — libpcap reader/writer (both byte orders, us/ns timestamps, bounded record size).
- `parse` — Ethernet (incl. 802.1Q/QinQ), IPv4, IPv6 (extension headers), TCP, UDP, ICMP, ICMPv6, DNS.
  All reads are bounds-checked; malformed input returns `ParseError`, never panics.
- `rules` — declarative JSON rules: kind, thresholds, time windows, protocol filters, severity, confidence.
  Validation rejects duplicate IDs, confidence outside 0..1, and zero thresholds/windows.
  `RuleStore::reload_if_changed` keeps the previous good rule set if a new file is invalid.
- `detect` — engine with per-rule, per-source sliding windows. Rule kinds:
  - `port_scan` — distinct destination ports (or hosts with `by_host`) per source; TCP SYN-only probes.
  - `failed_connections` — RST responses from a server to a client, optionally filtered by server port.
  - `dns_anomaly` — over-long query names, query volume, NXDOMAIN rate.
  - `packet_threshold` — generic count per protocol/port within a window (e.g., ICMP flood).
  `Engine::reload` swaps rules while keeping state for surviving rules.
- `store` — SQLite (WAL) tables for findings and runs.
- `investigate` — groups findings per actor with a gap threshold into incidents; combined confidence is
  `1 - Π(1 - cᵢ)`; timelines are rendered per incident.
- `pipeline` — Tokio pipeline: a blocking reader thread decodes records and pushes packets into a bounded
  `mpsc` channel (back-pressure); the detector drains it asynchronously.
- `platform` — per-OS data directory (`%APPDATA%`, XDG, or macOS Application Support), key files
  (mode 0600 on Unix, read-only on Windows), OS entropy, and interface listing (Linux only).
- `qscrypt` — safe FFI wrapper over the vendored, dual-licensed qs_crypt C subset.
- `fixtures` — synthetic frame builders and `sample_capture()` (benign web/DNS plus port scan, failed-connection
  burst, DNS tunnelling-style name, ICMP flood). Uses documentation/private address ranges only.

## Rule format

```json
{"version": 1, "rules": [
  {"id": "PS-001", "title": "Horizontal TCP port scan", "enabled": true,
   "severity": "high", "confidence": 0.9,
   "kind": "port_scan", "protocol": "tcp", "distinct_ports": 20, "window_secs": 60}
]}
```

Kinds: `port_scan`, `failed_connections`, `dns_anomaly`, `packet_threshold`
(see `rules/default.json`).

## Tests

`tests/engine.rs` covers malformed input without panics, TCP parsing, all attack
patterns detected on the synthetic capture, benign traffic producing no
findings, PCAP write/read round trip through the async pipeline, and rule
validation. `tests/qscrypt.rs` covers SHA3-256 known answers, seal/open with
tamper detection, wrong-key and bad-length rejection, and platform paths.

## CI, packaging and publishing

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — cross-platform
  build/test matrix, Rustfmt, Clippy, release binary, `cargo package` and
  `cargo publish --dry-run`.
- [`.github/workflows/publish.yml`](.github/workflows/publish.yml) — verifies
  that a `vX.Y.Z` tag matches `Cargo.toml`, dry-runs the package and publishes
  with `CARGO_REGISTRY_TOKEN`.
- [PUBLISHING.md](PUBLISHING.md) — one-time crates.io setup and release steps.
- [CONTRIBUTING.md](CONTRIBUTING.md) — local checks expected before a PR.
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — provenance, licensing and
  security caveats for vendored qs_crypt.

## Platform support and qs_crypt

NIGHTWATCH targets **Linux, Windows and macOS** for offline PCAP analysis. The
CI matrix builds the C subset with the system C compiler: Windows links
`bcrypt`, Linux links `pthread`, and macOS uses its system libSystem. Only the
qs_crypt modules used by NIGHTWATCH are compiled.

```sh
nightwatch keygen
nightwatch report --db nightwatch.db --out report.sealed --seal
nightwatch unseal report.sealed
nightwatch info
```

`report` prints a SHA3-256 digest; `--seal` encrypts and authenticates JSON
with ChaCha20-Poly1305, with the algorithm bound into the container. Key files
are stored unencrypted at rest. qs_crypt has not had an independent security
audit; review `vendor/qs_crypt/HANDOFF.md` before production use.

## License and status

Dual-licensed under `MIT OR Apache-2.0`; see `LICENSE-MIT`, `LICENSE-APACHE`,
`NOTICE` and `THIRD_PARTY_NOTICES.md`.

Honest limitations:

- Live interface capture is not implemented; `monitor` returns an explicit
  error. Windows live capture would additionally need Npcap.
- Benchmarks are not included yet.
- DNS names with labels longer than 63 bytes are rejected by the parser
  (RFC-invalid); such queries are not scored by DNS rules.
- Rule reload is available through `rules watch` and the library APIs; the
  analysis command loads rules at startup.

# NIGHTWATCH — Network Threat Detection Engine

A passive, modular network security engine in Rust (stable) with a Tokio pipeline and SQLite storage.
It decodes captured traffic, runs declarative detection rules, stores findings, correlates them into
incidents and exports JSON. It never transmits packets or probes external systems.

## Build and test
From the repository root, with Git, Rust stable and a C11 compiler:

    git submodule update --init --recursive
    cargo build --release --locked
    cargo test --locked

Windows x64: install the Rust MSVC toolchain and Visual Studio 2022 Build Tools
(Desktop development with C++ and a Windows SDK). Run the commands above from
Developer PowerShell. The executable is `target\release\nightwatch.exe`.
Linux: install GCC or Clang and libc development headers. The binary is
`target/release/nightwatch`. SQLite and the qs_crypt hash backend are linked
at build time; offline analysis and reports need no packet driver.

## Passive interface capture (Windows and Linux)
Install Wireshark 4.4+ with dumpcap; on Windows also install Npcap. On Linux,
use your distribution's supported non-root capture permission setup for dumpcap.
Do not grant the entire NIGHTWATCH executable elevated privileges. From the
repo root (PowerShell example):

    .\target\release\nightwatch.exe interfaces
    .\target\release\nightwatch.exe monitor --iface 1 --seconds 30 --count 5000
    .\target\release\nightwatch.exe report --out report.json
    (Get-FileHash -Algorithm SHA256 report.json).Hash

On Linux use `./target/release/nightwatch` with the same arguments, then
`sha256sum report.json`. Choose the index printed for your authorized Ethernet
or raw-IP adapter; do not assume 1 is the intended interface. Both live commands
accept `--dumpcap` with an absolute path to a trusted installation if outside
`%ProgramFiles%\Wireshark` or `/usr/bin`. No shell, packet injection, name
resolution, or promiscuous capture is requested. Capture stops at the first
limit (default 60 seconds or 10,000 frames). Findings are stored after successful
completion, not continuously. Ctrl-C aborts rather than committing a partial run.
Linux `any` (cooked capture) and Npcap loopback/null link types are not supported.

## Report fingerprints
`report --out` prints the lowercase SHA-256 of the precise JSON bytes it writes.
The Rust wrapper calls the public `qsc_hash` API through a small C adapter;
Cargo builds the pinned [qs_crypt](https://github.com/Ai-finder-for-api/qs_crypt)
submodule with the target C compiler. No binary downloads during build, DLL
search path, or experimental primitives. Linux already has pthread/getrandom
support upstream; Windows uses the Windows SDK/bcrypt. This first integration
is deliberately **not** report encryption, authentication, or database protection.
Retain the digest separately in a trusted location if comparing exports later.

## Quick start (offline analysis)
    nightwatch gen-fixtures fixtures/sample_attacks.pcap
    nightwatch analyze fixtures/sample_attacks.pcap --db nightwatch.db --json fixtures/sample_findings.json
    nightwatch incidents --db nightwatch.db
    nightwatch report --db nightwatch.db --out report.json
    nightwatch rules validate rules/default.json
    nightwatch rules list rules/default.json
    nightwatch rules watch rules/default.json     # hot reload on file change

## CLI
| Command | Purpose |
|---|---|
| `analyze <pcap>` | Offline PCAP analysis, stores findings in SQLite, optional JSON export |
| `interfaces` / `monitor --iface <index>` | List interfaces / passively analyze a bounded capture through dumpcap |
| `rules validate|list|watch` | Rule management and hot reload |
| `alerts [--json]` | List stored alerts |
| `incidents [--gap-secs]` | Correlated incidents with timelines |
| `report --out` | Full JSON report (findings + incidents) |
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
- `fixtures` — synthetic frame builders and `sample_capture()` (benign web/DNS plus port scan, failed-connection
  burst, DNS tunnelling-style name, ICMP flood). Uses documentation/private address ranges only.

## Rule format
    {"version": 1, "rules": [
      {"id": "PS-001", "title": "Horizontal TCP port scan", "enabled": true,
       "severity": "high", "confidence": 0.9,
       "kind": "port_scan", "protocol": "tcp", "distinct_ports": 20, "window_secs": 60}
    ]}
Kinds: `port_scan`, `failed_connections`, `dns_anomaly`, `packet_threshold` (see `rules/default.json`).

## Tests
`tests/engine.rs` covers: malformed input does not panic, TCP parsing, all attack patterns detected on the
synthetic capture, benign traffic produces no findings, PCAP write/read round trip through the async pipeline,
and rule validation.

The Windows/Linux CI recipe runs the Rust suite and `qa/smoke.py`, which exercises
the monitor child-process interface with fixture bytes, rejects a failed capture,
and compares the report fingerprint with Python hashlib. It does not test Npcap drivers.

## Limitations
- Live capture depends on capture-driver permissions and a supported adapter link type.
- Benchmarks are not included yet.
- DNS names with labels longer than 63 bytes are rejected by the parser (RFC-invalid); such queries are not
  scored by DNS rules.
- Rule reload is via `rules watch` (polling) and `RuleStore`/`Engine::reload` in the library; the analysis
  command loads rules at start.

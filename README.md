# NIGHTWATCH — Network Threat Detection Engine

A passive, modular network security engine in Rust (stable) with a Tokio pipeline and SQLite storage.
It decodes captured traffic, runs declarative detection rules, stores findings, correlates them into
incidents and exports JSON. It never transmits packets or probes external systems.

## Build and test
    cargo build --release
    cargo test

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
| `monitor --iface` | Live capture. **Not implemented in this build** (reports an error; no libpcap/raw-socket backend) |
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

## Limitations (honest status)
- Live interface capture is not implemented; `monitor` returns an explicit error. Offline PCAP analysis is complete.
- Benchmarks are not included yet.
- DNS names with labels longer than 63 bytes are rejected by the parser (RFC-invalid); such queries are not
  scored by DNS rules.
- Rule reload is via `rules watch` (polling) and `RuleStore`/`Engine::reload` in the library; the analysis
  command loads rules at start.

## Platform support and qs_crypt (new)

NIGHTWATCH now targets **Linux, Windows and macOS** (offline PCAP analysis on all three; CI matrix in `.github/workflows/ci.yml`).
Windows CI has not been run yet from here; only Linux was built and tested locally.

- `src/platform.rs`: per-OS data dir (`%APPDATA%\nightwatch`, `$XDG_DATA_HOME`, macOS Application Support), key files (0600 on Unix, read-only on Windows), OS entropy, interface listing (Linux `/sys/class/net`).
- `src/qscrypt.rs` + `build.rs`: [qs_crypt](https://github.com/ai-finder-for-api/qs_crypt) is vendored in `vendor/qs_crypt` and compiled with the `cc` crate. Linux links pthread; Windows links `bcrypt`. qs_crypt's own code already had POSIX paths (getrandom, pthread), so the port needed only the build integration, no C changes (the vendored copy is unmodified).
- Uses: SHA3-256 digest printed for every report; `report --seal` encrypts and authenticates the JSON with ChaCha20-Poly1305 (algorithm bound into the container); `unseal` verifies and decrypts; `keygen` creates the key file.

```
nightwatch keygen
nightwatch report --db nightwatch.db --out report.sealed --seal
nightwatch unseal report.sealed
nightwatch info
```
Caveats: qs_crypt states it is not independently audited and its repo has no license file, so check licensing before redistributing. Live capture is still not implemented on any OS (Windows would need Npcap). Key files are unencrypted at rest.

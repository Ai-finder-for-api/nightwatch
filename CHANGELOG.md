# Changelog

## 0.1.0 - unreleased
- Passive PCAP analysis: Ethernet/IPv4/IPv6/TCP/UDP/DNS/ICMP parsing.
- Detection engine with declarative JSON rules (thresholds, windows, protocol conditions), hot reload.
- SQLite event store, alert correlation, incident timelines, JSON export.
- Windows/macOS/Linux platform layer; vendored qs_crypt (SHA3-256, ChaCha20-Poly1305 sealed reports).
- GitHub Actions CI (Linux/Windows/macOS) and tag-driven crates.io release workflow.

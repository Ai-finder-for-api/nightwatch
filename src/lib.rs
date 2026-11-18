//! NIGHTWATCH: passive network threat detection engine.
//!
//! Module layout (each independently testable):
//! - `pcap`      capture-file reading/writing (offline analysis)
//! - `parse`     Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / DNS decoding
//! - `rules`     declarative JSON rule format, validation, hot reload
//! - `detect`    detection engine (sliding windows, findings with severity/confidence)
//! - `store`     SQLite event storage
//! - `investigate` incident correlation, timelines, JSON export
//! - `pipeline`  Tokio pipeline: reader -> bounded queue -> detector
//! - `qscrypt`   FFI wrapper for the vendored qs_crypt C library (hash, sealed reports)
//! - `platform`  Linux / macOS / Windows paths, key files, entropy
//! - `fixtures`  synthetic PCAP generation for tests and demos

pub mod detect;
pub mod fixtures;
pub mod investigate;
pub mod parse;
pub mod pcap;
pub mod pipeline;
pub mod platform;
pub mod qscrypt;
pub mod rules;
pub mod store;

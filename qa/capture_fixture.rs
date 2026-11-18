//! Test double (compiled only by qa/smoke.py); no network access.
use std::io::{self, Write};
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["-D"] { println!("1. fixture"); return; }
    assert_eq!(args, ["-i", "1", "-p", "-F", "pcap", "-s", "65535", "-a", "duration:2", "-c", "1000", "-w", "-"]);
    io::stdout().write_all(include_bytes!("../fixtures/sample_attacks.pcap")).unwrap();
    if std::env::var_os("NW_FIXTURE_FAIL").is_some() { std::process::exit(1); }
}

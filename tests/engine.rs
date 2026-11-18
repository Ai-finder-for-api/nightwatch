use nightwatch_ndr::detect::Engine;
use nightwatch_ndr::fixtures::{sample_capture, tcp_frame};
use nightwatch_ndr::parse::{parse_ethernet, parse_frame, Transport, LINKTYPE_ETHERNET, TCP_SYN};
use nightwatch_ndr::pcap::{write_pcap, PcapReader, Record};
use nightwatch_ndr::pipeline::analyze_pcap;
use nightwatch_ndr::rules::RuleSet;
use std::net::Ipv4Addr;

fn default_rules() -> RuleSet {
    RuleSet::parse(include_str!("../rules/default.json")).unwrap()
}

#[test]
fn malformed_frames_never_panic() {
    let mut cut = tcp_frame(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 1, 2, TCP_SYN);
    cut.truncate(30);
    for junk in [
        vec![],
        vec![0u8; 5],
        vec![0x45u8; 20],
        vec![0x60u8; 39],
        cut,
    ] {
        assert!(parse_ethernet(0, &junk).is_err());
    }
}

#[test]
fn parses_tcp_syn() {
    let f = tcp_frame(
        Ipv4Addr::new(10, 1, 1, 1),
        Ipv4Addr::new(10, 1, 1, 2),
        1234,
        80,
        TCP_SYN,
    );
    let p = parse_frame(5, &f, LINKTYPE_ETHERNET).unwrap();
    assert_eq!(p.dst_port(), Some(80));
    assert!(matches!(p.transport, Transport::Tcp { flags, .. } if flags == TCP_SYN));
}

#[test]
fn attack_patterns_detected() {
    let mut engine = Engine::new(default_rules());
    let mut hits = Vec::new();
    for r in &sample_capture() {
        let p = parse_frame(r.ts_us, &r.data, LINKTYPE_ETHERNET).unwrap();
        hits.extend(engine.process(&p));
    }
    for id in ["PS-001", "FC-001", "FC-002", "DNS-002", "ICMP-001"] {
        assert!(hits.iter().any(|f| f.rule_id == id), "{id} missed");
    }
    assert!(hits
        .iter()
        .all(|f| f.confidence > 0.0 && f.confidence <= 1.0));
}

#[test]
fn benign_traffic_is_quiet() {
    let mut engine = Engine::new(default_rules());
    let n: usize = sample_capture()
        .iter()
        .take(10)
        .map(|r| {
            engine
                .process(&parse_frame(r.ts_us, &r.data, LINKTYPE_ETHERNET).unwrap())
                .len()
        })
        .sum();
    assert_eq!(n, 0);
}

#[test]
fn pcap_roundtrip_and_pipeline() {
    let dir = std::env::temp_dir().join(format!("nw-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sample.pcap");
    let recs: Vec<Record> = sample_capture();
    write_pcap(
        std::fs::File::create(&path).unwrap(),
        LINKTYPE_ETHERNET,
        &recs,
    )
    .unwrap();
    let mut rd = PcapReader::new(std::fs::File::open(&path).unwrap()).unwrap();
    let mut count = 0;
    while rd.next_record().unwrap().is_some() {
        count += 1;
    }
    assert_eq!(count, recs.len());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let report = rt.block_on(analyze_pcap(path, default_rules(), 8)).unwrap();
    assert_eq!(report.packets as usize, recs.len());
    assert_eq!(report.malformed, 0);
    assert!(!report.findings.is_empty());
}

#[test]
fn rule_validation_rejects_bad_rules() {
    let bad = r#"{"version":1,"rules":[{"id":"X","title":"t","enabled":true,"severity":"low","confidence":1.5,"kind":"port_scan","distinct_ports":5,"window_secs":10}]}"#;
    assert!(RuleSet::parse(bad).is_err());
    let dup = r#"{"version":1,"rules":[
      {"id":"X","title":"t","enabled":true,"severity":"low","confidence":0.5,"kind":"port_scan","distinct_ports":5,"window_secs":10},
      {"id":"X","title":"t","enabled":true,"severity":"low","confidence":0.5,"kind":"port_scan","distinct_ports":5,"window_secs":10}]}"#;
    assert!(RuleSet::parse(dup).is_err());
}

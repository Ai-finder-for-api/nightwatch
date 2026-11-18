//! Synthetic frame builders. Used by tests, `nightwatch gen-fixtures`, and the benchmark.
//! Traffic uses documentation/private address ranges only.

use crate::parse::{TCP_ACK, TCP_RST, TCP_SYN};
use crate::pcap::Record;
use std::net::Ipv4Addr;

fn checksum_free_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut ip = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0, 0, 64, proto, 0, 0];
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(payload);
    ip
}

fn ethernet(ip: Vec<u8>) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02, 0x08, 0x00];
    f.extend(ip);
    f
}

pub fn tcp_frame(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut t = Vec::with_capacity(20);
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&1u32.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());
    t.push(0x50); // data offset 5
    t.push(flags);
    t.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
    ethernet(checksum_free_ipv4(src, dst, 6, &t))
}

pub fn udp_frame(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    ethernet(checksum_free_ipv4(src, dst, 17, &u))
}

pub fn icmp_frame(src: Ipv4Addr, dst: Ipv4Addr, icmp_type: u8) -> Vec<u8> {
    ethernet(checksum_free_ipv4(src, dst, 1, &[icmp_type, 0, 0, 0, 0, 0, 0, 0]))
}

/// DNS query (or NXDOMAIN response) for a dotted name, as a UDP payload.
pub fn dns_payload(name: &str, response: bool, rcode: u8) -> Vec<u8> {
    let mut m = vec![0x12, 0x34];
    let flags: u16 = if response { 0x8180 | rcode as u16 } else { 0x0100 };
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    m
}

pub fn dns_query(src: Ipv4Addr, dst: Ipv4Addr, ts_us: u64, name: &str) -> Record {
    Record { ts_us, data: udp_frame(src, dst, 40000, 53, &dns_payload(name, false, 0)) }
}

/// A capture mixing benign traffic with each attack pattern the default rules detect.
pub fn sample_capture() -> Vec<Record> {
    let mut out = Vec::new();
    let mut t: u64 = 1_700_000_000_000_000;
    let mut push = |out: &mut Vec<Record>, data: Vec<u8>, step: u64| {
        t += step;
        out.push(Record { ts_us: t, data });
    };
    let attacker = Ipv4Addr::new(192, 0, 2, 66);
    let target = Ipv4Addr::new(10, 0, 0, 5);
    let client = Ipv4Addr::new(10, 0, 0, 9);
    let web = Ipv4Addr::new(10, 0, 0, 80);

    // Benign: established web session and normal DNS.
    for i in 0..5u16 {
        push(&mut out, tcp_frame(client, web, 50000 + i, 443, TCP_SYN), 10_000);
        push(&mut out, tcp_frame(web, client, 443, 50000 + i, TCP_SYN | TCP_ACK), 10_000);
    }
    let ts = out.last().map(|r| r.ts_us).unwrap_or(1_700_000_000_000_000) + 1000;
    out.push(dns_query(client, Ipv4Addr::new(10, 0, 0, 1), ts, "www.example.com"));
    // Horizontal port scan: SYN to 30 distinct ports within a few seconds.
    for port in 1..=30u16 {
        push(&mut out, tcp_frame(attacker, target, 41000, port, TCP_SYN), 100_000);
    }
    // Failed SSH brute force: target answers each attempt with RST.
    for i in 0..12u16 {
        push(&mut out, tcp_frame(target, client, 22, 52000 + i, TCP_RST | TCP_ACK), 2_000_000);
    }
    // DNS tunnelling-style long query name.
    let long = format!("{}.{}.exfil.example.net", "a".repeat(50), "b".repeat(50));
    let ts = out.last().map(|r| r.ts_us).unwrap_or(1_700_000_000_000_000) + 1000;
    out.push(dns_query(client, Ipv4Addr::new(10, 0, 0, 1), ts, &long));
    // ICMP burst.
    for _ in 0..60 {
        push(&mut out, icmp_frame(attacker, target, 8), 20_000);
    }
    out
}


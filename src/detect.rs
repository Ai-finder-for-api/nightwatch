//! Detection engine. Consumes parsed packets, maintains per-rule sliding windows
//! keyed by source/client address, and emits `Finding`s with severity and confidence.
//! Detection is purely passive: it only reads packets it is given.

use crate::parse::{Packet, Transport, TCP_ACK, TCP_RST, TCP_SYN};
use crate::rules::{Rule, RuleKind, RuleSet, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: f32,
    pub ts_us: u64,
    pub actor: String,
    pub target: Option<String>,
    pub summary: String,
    pub observed: usize,
}

/// Per-key sliding window of (timestamp_us, value).
#[derive(Default)]
struct Window {
    events: VecDeque<(u64, String)>,
}

impl Window {
    fn push(&mut self, ts: u64, value: String, window_us: u64) {
        self.events.push_back((ts, value));
        while let Some((t, _)) = self.events.front() {
            if ts.saturating_sub(*t) > window_us {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }
    fn distinct(&self) -> usize {
        self.events
            .iter()
            .map(|(_, v)| v.as_str())
            .collect::<HashSet<_>>()
            .len()
    }
    fn len(&self) -> usize {
        self.events.len()
    }
    fn clear(&mut self) {
        self.events.clear();
    }
}

pub struct Engine {
    rules: RuleSet,
    /// rule id -> key -> window
    state: HashMap<String, HashMap<String, Window>>,
    pub packets_seen: u64,
    pub malformed_seen: u64,
}

impl Engine {
    pub fn new(rules: RuleSet) -> Self {
        Self {
            rules,
            state: HashMap::new(),
            packets_seen: 0,
            malformed_seen: 0,
        }
    }

    /// Swap in a new rule set; window state is kept for rules that still exist.
    pub fn reload(&mut self, rules: RuleSet) {
        let live: HashSet<String> = rules.rules.iter().map(|r| r.id.clone()).collect();
        self.state.retain(|id, _| live.contains(id));
        self.rules = rules;
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn process(&mut self, p: &Packet) -> Vec<Finding> {
        self.packets_seen += 1;
        let rules: Vec<Rule> = self
            .rules
            .rules
            .iter()
            .filter(|r| r.enabled)
            .cloned()
            .collect();
        let mut out = Vec::new();
        for r in &rules {
            if let Some(f) = self.eval(r, p) {
                out.push(f);
            }
        }
        out
    }

    fn window(&mut self, rule: &str, key: &str) -> &mut Window {
        self.state
            .entry(rule.to_string())
            .or_default()
            .entry(key.to_string())
            .or_default()
    }

    fn eval(&mut self, r: &Rule, p: &Packet) -> Option<Finding> {
        let ts = p.ts_us;
        let src = p.src.to_string();
        let dst = p.dst.to_string();
        match &r.kind {
            RuleKind::PortScan {
                protocol,
                distinct_ports,
                window_secs,
                by_host,
            } => {
                // TCP probes are SYN-only (no ACK); UDP counts any datagram.
                let probe = match &p.transport {
                    Transport::Tcp { flags, .. } => flags & TCP_SYN != 0 && flags & TCP_ACK == 0,
                    Transport::Udp { .. } => true,
                    _ => false,
                };
                let proto_ok = match protocol.as_str() {
                    "tcp" => matches!(p.transport, Transport::Tcp { .. }) && probe,
                    "udp" => matches!(p.transport, Transport::Udp { .. }),
                    _ => probe,
                };
                if !proto_ok {
                    return None;
                }
                let value = if *by_host {
                    dst.clone()
                } else {
                    p.dst_port()?.to_string()
                };
                let win_us = window_secs * 1_000_000;
                let w = self.window(&r.id, &src);
                w.push(ts, value, win_us);
                let d = w.distinct();
                if d >= *distinct_ports {
                    let n = w.len();
                    self.window(&r.id, &src).clear();
                    let what = if *by_host { "hosts" } else { "ports" };
                    return Some(finding(
                        r,
                        ts,
                        &src,
                        None,
                        format!("{src} touched {d} distinct {what} within {window_secs}s"),
                        n,
                    ));
                }
                None
            }
            RuleKind::FailedConnections {
                threshold,
                window_secs,
                dst_port,
            } => {
                // A RST sent by the server side (src port = server port) answers a refused attempt.
                let Transport::Tcp {
                    src_port, flags, ..
                } = p.transport
                else {
                    return None;
                };
                if flags & TCP_RST == 0 {
                    return None;
                }
                if let Some(port) = dst_port {
                    if *port != src_port {
                        return None;
                    }
                }
                let client = dst.clone();
                let win_us = window_secs * 1_000_000;
                let w = self.window(&r.id, &client);
                w.push(ts, format!("{src}:{src_port}"), win_us);
                let n = w.len();
                if n >= *threshold {
                    self.window(&r.id, &client).clear();
                    return Some(finding(r, ts, &client, Some(src.clone()), format!("{n} failed connections from {client} to {src}:{src_port} within {window_secs}s"), n));
                }
                None
            }
            RuleKind::DnsAnomaly {
                max_qname_len,
                max_nxdomain,
                max_queries,
                window_secs,
            } => {
                let dns = p.dns.as_ref()?;
                let win_us = window_secs * 1_000_000;
                if !dns.is_response {
                    let qname = dns.qname.clone().unwrap_or_default();
                    if let Some(max) = max_qname_len {
                        if qname.len() > *max {
                            return Some(finding(
                                r,
                                ts,
                                &src,
                                Some(dst),
                                format!(
                                    "DNS query name length {} exceeds {}: {}",
                                    qname.len(),
                                    max,
                                    truncate(&qname, 80)
                                ),
                                1,
                            ));
                        }
                    }
                    if let Some(max) = max_queries {
                        let w = self.window(&r.id, &src);
                        w.push(ts, qname, win_us);
                        let n = w.len();
                        if n > *max {
                            self.window(&r.id, &src).clear();
                            return Some(finding(
                                r,
                                ts,
                                &src,
                                None,
                                format!("{src} issued {n} DNS queries within {window_secs}s"),
                                n,
                            ));
                        }
                    }
                } else if dns.rcode == 3 {
                    if let Some(max) = max_nxdomain {
                        let client = dst.clone();
                        let w = self.window(&r.id, &client);
                        w.push(ts, dns.qname.clone().unwrap_or_default(), win_us);
                        let n = w.len();
                        if n > *max {
                            self.window(&r.id, &client).clear();
                            return Some(finding(
                                r,
                                ts,
                                &client,
                                Some(src),
                                format!("{n} NXDOMAIN responses to {client} within {window_secs}s"),
                                n,
                            ));
                        }
                    }
                }
                None
            }
            RuleKind::PacketThreshold {
                protocol,
                dst_port,
                threshold,
                window_secs,
            } => {
                let proto_ok = match protocol.as_str() {
                    "any" => true,
                    "tcp" => matches!(p.transport, Transport::Tcp { .. }),
                    "udp" => matches!(p.transport, Transport::Udp { .. }),
                    "dns" => p.dns.is_some(),
                    "icmp" => matches!(
                        p.transport,
                        Transport::Icmp { .. } | Transport::Icmpv6 { .. }
                    ),
                    _ => false,
                };
                if !proto_ok {
                    return None;
                }
                if let Some(port) = dst_port {
                    if p.dst_port() != Some(*port) {
                        return None;
                    }
                }
                let win_us = window_secs * 1_000_000;
                let w = self.window(&r.id, &src);
                w.push(ts, p.wire_len.to_string(), win_us);
                let n = w.len();
                if n >= *threshold {
                    self.window(&r.id, &src).clear();
                    return Some(finding(
                        r,
                        ts,
                        &src,
                        Some(dst),
                        format!("{n} {protocol} packets from {src} within {window_secs}s"),
                        n,
                    ));
                }
                None
            }
        }
    }
}

fn finding(
    r: &Rule,
    ts: u64,
    actor: &str,
    target: Option<String>,
    summary: String,
    observed: usize,
) -> Finding {
    Finding {
        rule_id: r.id.clone(),
        title: r.title.clone(),
        severity: r.severity,
        confidence: r.confidence,
        ts_us: ts,
        actor: actor.to_string(),
        target,
        summary,
        observed,
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "..."
    }
}

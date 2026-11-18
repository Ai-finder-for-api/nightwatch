//! Asynchronous processing pipeline. A blocking reader thread decodes capture records
//! and pushes parsed packets into a bounded Tokio channel; the detector task drains it.
//! The bounded queue applies back-pressure so memory stays flat on large captures.

use crate::detect::{Engine, Finding};
use crate::parse::{parse_frame, Packet};
use crate::pcap::PcapReader;
use crate::rules::RuleSet;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Debug, Default)]
pub struct PipelineReport {
    pub packets: u64,
    pub malformed: u64,
    pub findings: Vec<Finding>,
}

pub async fn analyze_pcap(
    path: PathBuf,
    rules: RuleSet,
    queue_capacity: usize,
) -> anyhow::Result<PipelineReport> {
    let (tx, mut rx) = mpsc::channel::<Packet>(queue_capacity.max(1));
    let reader = tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
        let file = File::open(&path)?;
        let mut pr = PcapReader::new(BufReader::new(file))?;
        let link = pr.header.link_type;
        let mut malformed = 0u64;
        while let Some(rec) = pr.next_record()? {
            match parse_frame(rec.ts_us, &rec.data, link) {
                Ok(pkt) => {
                    if tx.blocking_send(pkt).is_err() {
                        break;
                    }
                }
                Err(_) => malformed += 1,
            }
        }
        Ok(malformed)
    });

    let mut engine = Engine::new(rules);
    let mut findings = Vec::new();
    while let Some(pkt) = rx.recv().await {
        findings.extend(engine.process(&pkt));
    }
    let malformed = reader.await??;
    Ok(PipelineReport {
        packets: engine.packets_seen,
        malformed,
        findings,
    })
}

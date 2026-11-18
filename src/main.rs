use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nightwatch::investigate::{correlate, render_timeline};
use nightwatch::pipeline::analyze_pcap;
use nightwatch::rules::{RuleSet, RuleStore};
use nightwatch::store::Store;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "nightwatch", version, about = "Passive network threat detection engine")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyze a PCAP file offline and store findings in SQLite.
    Analyze {
        pcap: PathBuf,
        #[arg(long, default_value = "rules/default.json")]
        rules: PathBuf,
        #[arg(long, default_value = "nightwatch.db")]
        db: String,
        #[arg(long, default_value_t = 4096)]
        queue: usize,
        /// Also write findings as JSON to this path.
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// List local capture interfaces (requires Wireshark dumpcap).
    Interfaces { #[arg(long)] dumpcap: Option<PathBuf> },
    /// Analyze a bounded passive capture; stop at the first time or packet limit.
    Monitor {
        #[arg(long)]
        iface: u32,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u32).range(1..=3600))]
        seconds: u32,
        #[arg(long, default_value_t = 10000, value_parser = clap::value_parser!(u32).range(1..=1000000))]
        count: u32,
        #[arg(long)] dumpcap: Option<PathBuf>,
        #[arg(long, default_value = "rules/default.json")] rules: PathBuf,
        #[arg(long, default_value = "nightwatch.db")] db: String,
    },
    /// Rule management.
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    /// List stored alerts.
    Alerts {
        #[arg(long, default_value = "nightwatch.db")]
        db: String,
        #[arg(long)]
        json: bool,
    },
    /// Correlate alerts into incidents and print timelines.
    Incidents {
        #[arg(long, default_value = "nightwatch.db")]
        db: String,
        #[arg(long, default_value_t = 600)]
        gap_secs: u64,
    },
    /// Export a full JSON report (findings + incidents).
    Report {
        #[arg(long, default_value = "nightwatch.db")]
        db: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 600)]
        gap_secs: u64,
    },
    /// Write the synthetic sample capture to a PCAP file.
    GenFixtures { out: PathBuf },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// Validate a rule file.
    Validate { file: PathBuf },
    /// List rules in a file.
    List { file: PathBuf },
    /// Watch a rule file and reload it when it changes (demo loop, Ctrl-C to stop).
    Watch {
        file: PathBuf,
        #[arg(long, default_value_t = 2)]
        interval_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Analyze { pcap, rules, db, queue, json } => {
            let set = RuleSet::parse(&std::fs::read_to_string(&rules).with_context(|| format!("reading {}", rules.display()))?)?;
            let report = analyze_pcap(pcap.clone(), set, queue).await?;
            let mut store = Store::open(&db)?;
            store.insert_findings(&pcap.display().to_string(), &report.findings)?;
            store.record_run(&pcap.display().to_string(), report.packets, report.malformed, report.findings.len())?;
            println!("packets={} malformed={} findings={}", report.packets, report.malformed, report.findings.len());
            for f in &report.findings {
                println!("[{:?}] {} {} - {}", f.severity, f.rule_id, f.title, f.summary);
            }
            if let Some(path) = json {
                std::fs::write(&path, serde_json::to_string_pretty(&report.findings)?)?;
                println!("wrote {}", path.display());
            }
        }
        Cmd::Interfaces { dumpcap } => nightwatch::capture::interfaces(dumpcap)?,
        Cmd::Monitor { iface, seconds, count, rules, db, dumpcap } => {
            let rules = RuleSet::parse(&std::fs::read_to_string(&rules)?)?;
            let source = format!("interface:{iface}");
            let mut store = Store::open(&db)?;
            let r = nightwatch::capture::monitor(dumpcap, iface, seconds, count, rules).await?;
            store.insert_findings(&source, &r.findings)?;
            store.record_run(&source, r.packets, r.malformed, r.findings.len())?;
            println!("packets={} malformed={} findings={}", r.packets, r.malformed, r.findings.len());
        }
        Cmd::Rules { cmd } => match cmd {
            RulesCmd::Validate { file } => {
                let set = RuleSet::parse(&std::fs::read_to_string(&file)?)?;
                println!("OK: {} rules valid", set.rules.len());
            }
            RulesCmd::List { file } => {
                let set = RuleSet::parse(&std::fs::read_to_string(&file)?)?;
                for r in &set.rules {
                    println!("{:<8} {:<8} {:<7} conf={:.2} enabled={} {}", r.id, format!("{:?}", r.severity), kind_name(&r.kind), r.confidence, r.enabled, r.title);
                }
            }
            RulesCmd::Watch { file, interval_secs } => {
                let mut store = RuleStore::load(&file)?;
                println!("watching {} ({} rules)", file.display(), store.current.rules.len());
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
                    match store.reload_if_changed() {
                        Ok(true) => println!("reloaded {} rules", store.current.rules.len()),
                        Ok(false) => {}
                        Err(e) => eprintln!("reload rejected, keeping previous rules: {e}"),
                    }
                }
            }
        },
        Cmd::Alerts { db, json } => {
            let store = Store::open(&db)?;
            let findings = store.all_findings()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            } else {
                for f in &findings {
                    println!("{:>14}us [{:?}] {} {} - {}", f.ts_us, f.severity, f.rule_id, f.actor, f.summary);
                }
                println!("{} alerts", findings.len());
            }
        }
        Cmd::Incidents { db, gap_secs } => {
            let store = Store::open(&db)?;
            let incidents = correlate(&store.all_findings()?, gap_secs * 1_000_000);
            for inc in &incidents {
                print!("{}", render_timeline(inc));
            }
            println!("{} incidents", incidents.len());
        }
        Cmd::Report { db, out, gap_secs } => {
            let store = Store::open(&db)?;
            let findings = store.all_findings()?;
            let incidents = correlate(&findings, gap_secs * 1_000_000);
            let doc = serde_json::json!({ "generator": "nightwatch", "finding_count": findings.len(), "findings": findings, "incidents": incidents });
            let bytes = serde_json::to_vec_pretty(&doc)?;
            let digest = nightwatch::crypto::sha256_hex(&bytes)?;
            std::fs::write(&out, bytes)?;
            println!("sha256={digest}  {}", out.display());
        }
        Cmd::GenFixtures { out } => {
            let recs = nightwatch::fixtures::sample_capture();
            let f = std::fs::File::create(&out)?;
            nightwatch::pcap::write_pcap(f, nightwatch::parse::LINKTYPE_ETHERNET, &recs)?;
            println!("wrote {} packets to {}", recs.len(), out.display());
        }
    }
    Ok(())
}

fn kind_name(k: &nightwatch::rules::RuleKind) -> &'static str {
    use nightwatch::rules::RuleKind::*;
    match k {
        PortScan { .. } => "portscan",
        FailedConnections { .. } => "failconn",
        DnsAnomaly { .. } => "dns",
        PacketThreshold { .. } => "threshold",
    }
}

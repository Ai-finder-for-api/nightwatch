use anyhow::{bail, Context, Result};
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
    /// Live capture on an interface. Not available in this build (no libpcap/raw-socket backend).
    Monitor {
        #[arg(long)]
        iface: Option<String>,
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
        /// Encrypt+authenticate the report with qs_crypt (ChaCha20-Poly1305) using the key file.
        #[arg(long)]
        seal: bool,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Generate a 256-bit report key file (mode 0600 on Unix; per-user %APPDATA% on Windows).
    Keygen {
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Decrypt and verify a sealed report; prints JSON to stdout.
    Unseal {
        file: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Show platform, crypto backend and capture interfaces.
    Info,
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
        Cmd::Monitor { iface } => {
            bail!("live capture on {:?} is not supported in this build; use `analyze` on a PCAP file", iface);
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
        Cmd::Report { db, out, gap_secs, seal, key } => {
            let store = Store::open(&db)?;
            let findings = store.all_findings()?;
            let incidents = correlate(&findings, gap_secs * 1_000_000);
            let doc = serde_json::json!({ "generator": "nightwatch", "finding_count": findings.len(), "findings": findings, "incidents": incidents });
            let text = serde_json::to_string_pretty(&doc)?;
            println!("sha3-256 {}", nightwatch::qscrypt::sha3_256_hex(text.as_bytes())?);
            if seal {
                let k = load_key(key)?;
                std::fs::write(&out, k.seal(text.as_bytes())?)?;
                println!("wrote sealed report {}", out.display());
            } else {
                std::fs::write(&out, text)?;
                println!("wrote {}", out.display());
            }
        }
        Cmd::Keygen { key } => {
            let path = key.unwrap_or_else(nightwatch::platform::default_key_path);
            nightwatch::platform::write_secret(&path, &nightwatch::qscrypt::random_key_bytes()?)?;
            println!("wrote key {}", path.display());
        }
        Cmd::Unseal { file, key } => {
            let k = load_key(key)?;
            let pt = k.open(&std::fs::read(&file)?)?;
            println!("{}", String::from_utf8_lossy(&pt));
        }
        Cmd::Info => {
            println!("os={} arch={}", nightwatch::platform::OS, std::env::consts::ARCH);
            println!("crypto={}", nightwatch::qscrypt::build_info());
            println!("data_dir={}", nightwatch::platform::data_dir().display());
            println!("interfaces={:?}", nightwatch::platform::list_interfaces());
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

fn load_key(key: Option<PathBuf>) -> Result<nightwatch::qscrypt::Key> {
    let path = key.unwrap_or_else(nightwatch::platform::default_key_path);
    let raw = std::fs::read(&path).with_context(|| format!("reading key {} (run `nightwatch keygen`)", path.display()))?;
    nightwatch::qscrypt::Key::from_bytes(&raw)
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

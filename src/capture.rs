//! Passive capture using Wireshark's local dumpcap, not a shell or raw socket.
use crate::{
    pipeline::{analyze_stream, PipelineReport},
    rules::RuleSet,
};
use anyhow::{ensure, Context, Result};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

fn executable(path: Option<PathBuf>) -> Result<PathBuf> {
    let path = path.unwrap_or_else(|| {
        #[cfg(windows)]
        {
            PathBuf::from(
                std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into()),
            )
            .join(r"Wireshark\dumpcap.exe")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/usr/bin/dumpcap")
        }
    });
    ensure!(
        path.is_absolute(),
        "--dumpcap must be an absolute path to a trusted dumpcap installation"
    );
    Ok(path)
}

pub fn interfaces(path: Option<PathBuf>) -> Result<()> {
    let path = executable(path)?;
    let status = Command::new(&path)
        .arg("-D")
        .status()
        .with_context(|| format!("starting {}", path.display()))?;
    ensure!(
        status.success(),
        "dumpcap -D failed ({status}); check driver and capture permission"
    );
    Ok(())
}

pub async fn monitor(
    path: Option<PathBuf>,
    iface: u32,
    seconds: u32,
    count: u32,
    rules: RuleSet,
) -> Result<PipelineReport> {
    ensure!(
        iface > 0 && seconds > 0 && count > 0,
        "interface, duration and packet count must be positive"
    );
    let path = executable(path)?;
    // Use a numeric local interface, non-promiscuous mode, classic pcap to stdout,
    // and both stop conditions (so even an idle interface eventually returns).
    let mut child = Command::new(&path)
        .args([
            "-i",
            &iface.to_string(),
            "-p",
            "-F",
            "pcap",
            "-s",
            "65535",
            "-a",
            &format!("duration:{seconds}"),
            "-c",
            &count.to_string(),
            "-w",
            "-",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "starting {}; install Wireshark/dumpcap first",
                path.display()
            )
        })?;
    let report = analyze_stream(
        child.stdout.take().expect("piped capture stdout"),
        rules,
        4096,
    )
    .await;
    if report.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let report =
        report.context("reading dumpcap output; check driver, interface and capture permission")?;
    ensure!(
        status.success(),
        "dumpcap failed ({status}); partial capture not committed"
    );
    Ok(report)
}

//! Declarative detection rules (JSON). Each rule has a kind, a severity,
//! a confidence, and kind-specific thresholds / time windows / protocol filters.
//! Rule files can be reloaded at runtime without restarting the engine.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleKind {
    /// One source touching many distinct destination ports (or hosts) within a window.
    PortScan {
        #[serde(default = "default_proto")] protocol: String,
        distinct_ports: usize,
        window_secs: u64,
        #[serde(default)] by_host: bool,
    },
    /// Many failed TCP connection attempts (RST or unanswered SYN) from one source to one destination.
    FailedConnections {
        threshold: usize,
        window_secs: u64,
        #[serde(default)] dst_port: Option<u16>,
    },
    /// Unusual DNS: over-long query names, high NXDOMAIN rate, or excessive query volume.
    DnsAnomaly {
        #[serde(default)] max_qname_len: Option<usize>,
        #[serde(default)] max_nxdomain: Option<usize>,
        #[serde(default)] max_queries: Option<usize>,
        window_secs: u64,
    },
    /// Generic threshold on matching packets: protocol + optional port, count within window.
    PacketThreshold {
        protocol: String,
        #[serde(default)] dst_port: Option<u16>,
        threshold: usize,
        window_secs: u64,
    },
}

fn default_proto() -> String { "any".into() }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub enabled: bool,
    pub severity: Severity,
    /// 0.0..=1.0
    pub confidence: f32,
    #[serde(flatten)]
    pub kind: RuleKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleSet {
    pub version: u32,
    pub rules: Vec<Rule>,
}

#[derive(Debug)]
pub enum RuleError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    Invalid(String),
}
impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::Io(e) => write!(f, "io: {e}"),
            RuleError::Parse(e) => write!(f, "parse: {e}"),
            RuleError::Invalid(m) => write!(f, "invalid rule: {m}"),
        }
    }
}
impl std::error::Error for RuleError {}

impl RuleSet {
    pub fn parse(text: &str) -> Result<RuleSet, RuleError> {
        let set: RuleSet = serde_json::from_str(text).map_err(RuleError::Parse)?;
        set.validate()?;
        Ok(set)
    }

    pub fn validate(&self) -> Result<(), RuleError> {
        let mut seen = std::collections::HashSet::new();
        for r in &self.rules {
            if r.id.trim().is_empty() {
                return Err(RuleError::Invalid("empty id".into()));
            }
            if !seen.insert(r.id.clone()) {
                return Err(RuleError::Invalid(format!("duplicate id {}", r.id)));
            }
            if !(0.0..=1.0).contains(&r.confidence) {
                return Err(RuleError::Invalid(format!("{}: confidence out of range", r.id)));
            }
            let zero_window = match &r.kind {
                RuleKind::PortScan { window_secs, distinct_ports, .. } => *window_secs == 0 || *distinct_ports == 0,
                RuleKind::FailedConnections { window_secs, threshold, .. } => *window_secs == 0 || *threshold == 0,
                RuleKind::DnsAnomaly { window_secs, .. } => *window_secs == 0,
                RuleKind::PacketThreshold { window_secs, threshold, .. } => *window_secs == 0 || *threshold == 0,
            };
            if zero_window {
                return Err(RuleError::Invalid(format!("{}: thresholds and windows must be > 0", r.id)));
            }
        }
        Ok(())
    }
}

/// Hot-reloadable rule source: remembers the file and its mtime.
pub struct RuleStore {
    path: PathBuf,
    mtime: Option<SystemTime>,
    pub current: RuleSet,
}

impl RuleStore {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuleError> {
        let path = path.as_ref().to_path_buf();
        let text = std::fs::read_to_string(&path).map_err(RuleError::Io)?;
        let current = RuleSet::parse(&text)?;
        let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        Ok(Self { path, mtime, current })
    }

    /// Reload only if the file changed. Returns Ok(true) when new rules were applied.
    /// On a parse error the previous good rule set is kept.
    pub fn reload_if_changed(&mut self) -> Result<bool, RuleError> {
        let mtime = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if mtime == self.mtime {
            return Ok(false);
        }
        let text = std::fs::read_to_string(&self.path).map_err(RuleError::Io)?;
        let set = RuleSet::parse(&text)?;
        self.current = set;
        self.mtime = mtime;
        Ok(true)
    }
}

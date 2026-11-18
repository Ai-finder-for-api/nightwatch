//! SQLite event storage for findings and capture runs.

use crate::detect::Finding;
use crate::rules::Severity;
use rusqlite::{params, Connection};

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS findings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 source TEXT NOT NULL,
                 rule_id TEXT NOT NULL,
                 title TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 confidence REAL NOT NULL,
                 ts_us INTEGER NOT NULL,
                 actor TEXT NOT NULL,
                 target TEXT,
                 summary TEXT NOT NULL,
                 observed INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts_us);
             CREATE TABLE IF NOT EXISTS runs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 source TEXT NOT NULL,
                 packets INTEGER NOT NULL,
                 malformed INTEGER NOT NULL,
                 findings INTEGER NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }

    pub fn insert_findings(&mut self, source: &str, findings: &[Finding]) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO findings (source, rule_id, title, severity, confidence, ts_us, actor, target, summary, observed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for f in findings {
                stmt.execute(params![
                    source,
                    f.rule_id,
                    f.title,
                    severity_str(f.severity),
                    f.confidence as f64,
                    f.ts_us as i64,
                    f.actor,
                    f.target,
                    f.summary,
                    f.observed as i64
                ])?;
            }
        }
        tx.commit()
    }

    pub fn record_run(&self, source: &str, packets: u64, malformed: u64, findings: usize) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO runs (source, packets, malformed, findings) VALUES (?1, ?2, ?3, ?4)",
            params![source, packets as i64, malformed as i64, findings as i64],
        )?;
        Ok(())
    }

    pub fn all_findings(&self) -> rusqlite::Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, title, severity, confidence, ts_us, actor, target, summary, observed FROM findings ORDER BY ts_us, id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Finding {
                rule_id: r.get(0)?,
                title: r.get(1)?,
                severity: parse_severity(&r.get::<_, String>(2)?),
                confidence: r.get::<_, f64>(3)? as f32,
                ts_us: r.get::<_, i64>(4)? as u64,
                actor: r.get(5)?,
                target: r.get(6)?,
                summary: r.get(7)?,
                observed: r.get::<_, i64>(8)? as usize,
            })
        })?;
        rows.collect()
    }

    pub fn count(&self) -> rusqlite::Result<i64> {
        self.conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
    }
}

pub fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

pub fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

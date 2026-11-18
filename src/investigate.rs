//! Investigation: correlate findings into incidents and build timelines.
//! Findings that share an actor and occur within `gap_us` of each other join the same incident.

use crate::detect::Finding;
use crate::rules::Severity;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEntry {
    pub ts_us: u64,
    pub rule_id: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Incident {
    pub id: String,
    pub actor: String,
    pub severity: Severity,
    pub confidence: f32,
    pub first_ts_us: u64,
    pub last_ts_us: u64,
    pub rule_ids: Vec<String>,
    pub finding_count: usize,
    pub timeline: Vec<TimelineEntry>,
}

pub fn correlate(findings: &[Finding], gap_us: u64) -> Vec<Incident> {
    let mut by_actor: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_actor.entry(f.actor.as_str()).or_default().push(f);
    }
    let mut incidents = Vec::new();
    for (actor, mut list) in by_actor {
        list.sort_by_key(|f| f.ts_us);
        let mut group: Vec<&Finding> = Vec::new();
        for f in list {
            if let Some(last) = group.last() {
                if f.ts_us.saturating_sub(last.ts_us) > gap_us {
                    incidents.push(build(actor, &group, incidents.len() + 1));
                    group.clear();
                }
            }
            group.push(f);
        }
        if !group.is_empty() {
            incidents.push(build(actor, &group, incidents.len() + 1));
        }
    }
    incidents.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.first_ts_us.cmp(&b.first_ts_us))
    });
    for (i, inc) in incidents.iter_mut().enumerate() {
        inc.id = format!("INC-{:04}", i + 1);
    }
    incidents
}

fn build(actor: &str, group: &[&Finding], n: usize) -> Incident {
    let mut rule_ids: Vec<String> = group.iter().map(|f| f.rule_id.clone()).collect();
    rule_ids.sort();
    rule_ids.dedup();
    let severity = group
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    // Combined confidence: 1 - prod(1 - c_i), so independent corroborating rules raise confidence.
    let confidence = 1.0
        - group
            .iter()
            .fold(1.0f32, |acc, f| acc * (1.0 - f.confidence.clamp(0.0, 1.0)));
    Incident {
        id: format!("INC-{n:04}"),
        actor: actor.to_string(),
        severity,
        confidence,
        first_ts_us: group.first().map(|f| f.ts_us).unwrap_or(0),
        last_ts_us: group.last().map(|f| f.ts_us).unwrap_or(0),
        rule_ids,
        finding_count: group.len(),
        timeline: group
            .iter()
            .map(|f| TimelineEntry {
                ts_us: f.ts_us,
                rule_id: f.rule_id.clone(),
                summary: f.summary.clone(),
            })
            .collect(),
    }
}

pub fn render_timeline(inc: &Incident) -> String {
    let mut out = format!(
        "{} [{:?}] actor={} confidence={:.2} rules={}\n",
        inc.id,
        inc.severity,
        inc.actor,
        inc.confidence,
        inc.rule_ids.join(",")
    );
    for t in &inc.timeline {
        out.push_str(&format!(
            "  {:>14}us  {:<8} {}\n",
            t.ts_us, t.rule_id, t.summary
        ));
    }
    out
}

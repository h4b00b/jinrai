//! # jinrai-metrics — reporting and the audit log (Phase 4)
//!
//! Renders a [`RunReport`] as a human-readable summary and provides the
//! append-only, tamper-evident [`AuditLog`] (see [`mod@audit`]) that records
//! every authorized / completed / refused run.

#![forbid(unsafe_code)]

mod audit;

pub use audit::{verify, AuditError, AuditEvent, AuditLog};

use jinrai_core::RunReport;

/// Render a run report as a plain-text summary line.
///
/// Latency percentiles are appended only when at least one unit completed
/// (stub layers report `units_sent == 0` and have no latency to show).
pub fn render(report: &RunReport) -> String {
    let mut line = format!(
        "[{}] sent={} errors={} aborted_early={}",
        report.layer_label, report.units_sent, report.errors, report.aborted_early
    );
    if report.units_sent > 0 {
        line.push_str(&format!(
            " latency_us(p50={} p90={} p99={} max={})",
            report.p50_micros, report.p90_micros, report.p99_micros, report.max_micros
        ));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_summary() {
        let r = RunReport {
            layer_label: "L7".into(),
            units_sent: 42,
            errors: 1,
            aborted_early: false,
            p50_micros: 1200,
            p90_micros: 3400,
            p99_micros: 9800,
            max_micros: 15000,
        };
        assert_eq!(
            render(&r),
            "[L7] sent=42 errors=1 aborted_early=false \
             latency_us(p50=1200 p90=3400 p99=9800 max=15000)"
        );
    }

    #[test]
    fn omits_latency_when_nothing_sent() {
        let r = RunReport {
            layer_label: "L4 (stub)".into(),
            ..Default::default()
        };
        assert_eq!(render(&r), "[L4 (stub)] sent=0 errors=0 aborted_early=false");
    }
}

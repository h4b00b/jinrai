//! # jinrai-metrics — reporting and the audit log (Phase 4)
//!
//! Renders a [`RunReport`] as a human-readable summary and provides the
//! append-only, tamper-evident [`AuditLog`] (see [`mod@audit`]) that records
//! every authorized / completed / refused run.

#![forbid(unsafe_code)]

mod audit;

pub use audit::{verify, AuditError, AuditEvent, AuditLog};

use jinrai_core::{RunReport, SloVerdict};

/// Render a run report as a plain-text summary line.
///
/// A status-class breakdown is appended when any response was classified, and
/// latency percentiles when at least one unit completed (stub / slow layers
/// report `units_sent == 0` or all-zero status counts and have neither to show).
pub fn render(report: &RunReport) -> String {
    let mut line = format!(
        "[{}] sent={} errors={} aborted_early={}",
        report.layer_label, report.units_sent, report.errors, report.aborted_early
    );
    let classified =
        report.status_2xx + report.status_3xx + report.status_4xx + report.status_5xx;
    if classified > 0 || report.timeouts > 0 {
        line.push_str(&format!(
            " status(2xx={} 3xx={} 4xx={} 5xx={} timeout={})",
            report.status_2xx,
            report.status_3xx,
            report.status_4xx,
            report.status_5xx,
            report.timeouts,
        ));
    }
    if report.aborted_by_watchdog {
        line.push_str(" watchdog=ABORTED");
    }
    if report.units_sent > 0 {
        line.push_str(&format!(
            " latency_us(p50={} p90={} p99={} max={})",
            report.p50_micros, report.p90_micros, report.p99_micros, report.max_micros
        ));
    }
    // Breaking-point discovery result, when a ramp found the capacity knee.
    if let Some(k) = report.knee {
        line.push_str(&format!(
            " knee(sustained={}/s broke_at={}/s)",
            k.sustained_per_sec, k.breached_at_per_sec
        ));
    }
    line
}

/// Render an SLO verdict as a one-line `SLO: PASS` / `SLO: FAIL (...)` summary.
pub fn render_verdict(verdict: &SloVerdict) -> String {
    format!("SLO: {verdict}")
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
            status_2xx: 40,
            status_5xx: 2,
            p50_micros: 1200,
            p90_micros: 3400,
            p99_micros: 9800,
            max_micros: 15000,
            ..Default::default()
        };
        assert_eq!(
            render(&r),
            "[L7] sent=42 errors=1 aborted_early=false \
             status(2xx=40 3xx=0 4xx=0 5xx=2 timeout=0) \
             latency_us(p50=1200 p90=3400 p99=9800 max=15000)"
        );
    }

    #[test]
    fn omits_latency_and_status_when_nothing_sent() {
        let r = RunReport {
            layer_label: "L4 (stub)".into(),
            ..Default::default()
        };
        assert_eq!(render(&r), "[L4 (stub)] sent=0 errors=0 aborted_early=false");
    }

    #[test]
    fn renders_knee_when_present() {
        use jinrai_core::Knee;
        let r = RunReport {
            layer_label: "L7 knee".into(),
            units_sent: 30,
            status_2xx: 20,
            status_5xx: 10,
            knee: Some(Knee { sustained_per_sec: 40, breached_at_per_sec: 60 }),
            ..Default::default()
        };
        assert!(
            render(&r).contains("knee(sustained=40/s broke_at=60/s)"),
            "rendered: {}",
            render(&r)
        );
    }

    #[test]
    fn renders_verdict_pass_and_fail() {
        use jinrai_core::{SloBreach, SloVerdict};
        assert_eq!(render_verdict(&SloVerdict::default()), "SLO: PASS");
        let fail = SloVerdict {
            breaches: vec![SloBreach::ServerErrorRate { observed: 0.2, limit: 0.1 }],
        };
        assert_eq!(render_verdict(&fail), "SLO: FAIL (5xx-rate 20.0% > 10.0%)");
    }
}

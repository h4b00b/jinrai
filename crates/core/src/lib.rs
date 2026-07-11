//! # jinrai-core — shared engine vocabulary and the module contract
//!
//! Defines the types every traffic module speaks (`Layer`, `RateCap`,
//! `RunPlan`, `RunReport`) and the [`StressModule`] trait that `l34` / `l7`
//! implement. Every entry point here consumes [`AuthorizedTarget`]s, so the
//! safety gate cannot be sidestepped by a module author.

#![forbid(unsafe_code)]

use std::time::Duration;

use jinrai_safety::{AuthorizedTarget, KillSwitch};

/// Which OSI layer a module drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Network layer — raw IP/ICMP packet generation.
    L3,
    /// Transport layer — TCP/UDP (SYN, UDP datagrams, …).
    L4,
    /// Application layer — HTTP/API load.
    L7,
}

/// A hard ceiling on emission rate. A safety control, not just a knob:
/// modules must never exceed it, and `0` means "refuse to send".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateCap {
    /// Maximum units per second (packets/sec for L3/L4, requests/sec for L7).
    pub per_second: u64,
}

impl RateCap {
    pub fn new(per_second: u64) -> Self {
        Self { per_second }
    }

    /// Minimum spacing between two emissions to honour this cap.
    /// `None` when the cap is zero (nothing should be sent).
    pub fn min_interval(&self) -> Option<Duration> {
        if self.per_second == 0 {
            None
        } else {
            Some(Duration::from_secs_f64(1.0 / self.per_second as f64))
        }
    }
}

/// Everything a module needs to execute one run, already validated.
///
/// Note the field type: `Vec<AuthorizedTarget>`. A caller physically cannot
/// build a `RunPlan` for an unauthorized target.
#[derive(Debug, Clone)]
pub struct RunPlan {
    pub targets: Vec<AuthorizedTarget>,
    pub rate_cap: RateCap,
    pub duration: Duration,
    /// Shared abort signal; workers must poll it.
    pub kill: KillSwitch,
}

/// Outcome of a run, handed to the metrics/reporting layer.
///
/// The `*_micros` latency fields are plain integers so `core` stays
/// dependency-free (the L7 engine computes them with `hdrhistogram` and copies
/// the resulting percentiles in). They are `0` for layers that do not measure
/// per-unit latency (e.g. the L3/L4 stubs).
///
/// ## Response classification (Phase 5)
///
/// `units_sent` counts every **completed** unit. For L7 that means every HTTP
/// response received *regardless of status* — a `500` is still a completed
/// response, not a transport error. The `status_*` fields break those
/// completions down by status class so a caller can tell a healthy target from
/// one that is answering but failing. `errors` counts **transport-level**
/// failures (connect refused, reset, no response); `timeouts` is the subset of
/// those that were read/connect timeouts. Layers without a response (L3/L4,
/// slow-connection L7) leave the `status_*` fields at zero.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunReport {
    pub layer_label: String,
    pub units_sent: u64,
    pub errors: u64,
    pub aborted_early: bool,
    /// Completed responses with a 2xx status.
    pub status_2xx: u64,
    /// Completed responses with a 3xx status.
    pub status_3xx: u64,
    /// Completed responses with a 4xx status.
    pub status_4xx: u64,
    /// Completed responses with a 5xx status.
    pub status_5xx: u64,
    /// Transport failures that were specifically timeouts (subset of `errors`).
    pub timeouts: u64,
    /// The SLO watchdog tripped the kill-switch on sustained breach (distinct
    /// from `aborted_early`, which is also set by an operator Ctrl-C).
    pub aborted_by_watchdog: bool,
    /// Median (p50) latency of completed units, in microseconds.
    pub p50_micros: u64,
    /// 90th-percentile latency, in microseconds.
    pub p90_micros: u64,
    /// 99th-percentile latency, in microseconds.
    pub p99_micros: u64,
    /// Worst observed latency, in microseconds.
    pub max_micros: u64,
}

impl RunReport {
    /// Total units attempted: completions plus transport errors. The denominator
    /// for every SLO rate.
    pub fn attempts(&self) -> u64 {
        self.units_sent + self.errors
    }
}

/// A Service-Level Objective: the thresholds a run's traffic must stay within
/// for the target to be judged healthy under load. Every threshold is optional
/// (`None` = not evaluated); an all-`None` spec is inert.
///
/// Rates are fractions in `[0.0, 1.0]` of **attempts** (`units_sent + errors`).
/// This is shared vocabulary: the end-of-run verdict ([`SloSpec::evaluate`])
/// and the inline L7 watchdog ([`SloSpec::breaches_rates`]) both read it, and
/// Phase 6's ramp will reuse the same breach signal to find the capacity knee.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SloSpec {
    /// Max fraction of attempts that may be transport errors (incl. timeouts).
    pub max_error_rate: Option<f64>,
    /// Max fraction of attempts that may be 5xx responses.
    pub max_5xx_rate: Option<f64>,
    /// Max fraction of attempts that may be 4xx responses (off by default: a 4xx,
    /// e.g. 429 rate-limiting, is not inherently a failure of the target).
    pub max_4xx_rate: Option<f64>,
    /// Max tolerated p99 latency, in microseconds (end-of-run verdict only; the
    /// watchdog evaluates rates, not latency).
    pub max_p99_micros: Option<u64>,
}

/// One way a run breached its SLO.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SloBreach {
    /// Transport-error rate exceeded the limit.
    ErrorRate { observed: f64, limit: f64 },
    /// 5xx rate exceeded the limit.
    ServerErrorRate { observed: f64, limit: f64 },
    /// 4xx rate exceeded the limit.
    ClientErrorRate { observed: f64, limit: f64 },
    /// p99 latency exceeded the limit.
    LatencyP99 { observed_micros: u64, limit_micros: u64 },
}

impl std::fmt::Display for SloBreach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SloBreach::ErrorRate { observed, limit } => {
                write!(f, "error-rate {:.1}% > {:.1}%", observed * 100.0, limit * 100.0)
            }
            SloBreach::ServerErrorRate { observed, limit } => {
                write!(f, "5xx-rate {:.1}% > {:.1}%", observed * 100.0, limit * 100.0)
            }
            SloBreach::ClientErrorRate { observed, limit } => {
                write!(f, "4xx-rate {:.1}% > {:.1}%", observed * 100.0, limit * 100.0)
            }
            SloBreach::LatencyP99 { observed_micros, limit_micros } => {
                write!(f, "p99 {observed_micros}us > {limit_micros}us")
            }
        }
    }
}

/// The result of evaluating a run against an [`SloSpec`]: the (possibly empty)
/// list of breaches. Empty => the target met the SLO.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SloVerdict {
    pub breaches: Vec<SloBreach>,
}

impl SloVerdict {
    /// True when nothing breached — the target held within its SLO.
    pub fn passed(&self) -> bool {
        self.breaches.is_empty()
    }
}

impl std::fmt::Display for SloVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.passed() {
            return write!(f, "PASS");
        }
        write!(f, "FAIL (")?;
        for (i, b) in self.breaches.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            write!(f, "{b}")?;
        }
        write!(f, ")")
    }
}

impl SloSpec {
    /// True when no threshold is set — the spec evaluates nothing.
    pub fn is_empty(&self) -> bool {
        self.max_error_rate.is_none()
            && self.max_5xx_rate.is_none()
            && self.max_4xx_rate.is_none()
            && self.max_p99_micros.is_none()
    }

    /// True when at least one *rate* threshold is set — i.e. the inline watchdog
    /// has something to evaluate (it does not look at latency).
    pub fn has_rate_thresholds(&self) -> bool {
        self.max_error_rate.is_some() || self.max_5xx_rate.is_some() || self.max_4xx_rate.is_some()
    }

    /// Evaluate the rate thresholds over a sample of `attempts` units. Shared by
    /// the end-of-run verdict and the inline watchdog (which passes the counts
    /// observed in its trailing window). Returns every breached rate. An empty
    /// sample (`attempts == 0`) can breach nothing.
    pub fn breaches_rates(&self, attempts: u64, errors: u64, s5xx: u64, s4xx: u64) -> Vec<SloBreach> {
        let mut breaches = Vec::new();
        if attempts == 0 {
            return breaches;
        }
        let frac = |n: u64| n as f64 / attempts as f64;
        if let Some(limit) = self.max_error_rate {
            let observed = frac(errors);
            if observed > limit {
                breaches.push(SloBreach::ErrorRate { observed, limit });
            }
        }
        if let Some(limit) = self.max_5xx_rate {
            let observed = frac(s5xx);
            if observed > limit {
                breaches.push(SloBreach::ServerErrorRate { observed, limit });
            }
        }
        if let Some(limit) = self.max_4xx_rate {
            let observed = frac(s4xx);
            if observed > limit {
                breaches.push(SloBreach::ClientErrorRate { observed, limit });
            }
        }
        breaches
    }

    /// The end-of-run verdict: the rate thresholds over the whole run plus the
    /// p99 latency threshold. A run that sent nothing cannot breach a latency SLO.
    pub fn evaluate(&self, report: &RunReport) -> SloVerdict {
        let mut breaches = self.breaches_rates(
            report.attempts(),
            report.errors,
            report.status_5xx,
            report.status_4xx,
        );
        if let Some(limit) = self.max_p99_micros {
            if report.units_sent > 0 && report.p99_micros > limit {
                breaches.push(SloBreach::LatencyP99 {
                    observed_micros: report.p99_micros,
                    limit_micros: limit,
                });
            }
        }
        SloVerdict { breaches }
    }
}

/// The contract every traffic module implements.
///
/// Kept synchronous-signature for now; the async L7 engine will wrap its
/// runtime internally when that crate lands (Phase 2), so `core` stays
/// runtime-agnostic and dependency-light.
pub trait StressModule {
    /// Which layer this module drives.
    fn layer(&self) -> Layer;

    /// Human-readable name for logs/reports.
    fn name(&self) -> &str;

    /// Execute the plan and return a report. Implementations MUST:
    ///  - poll `plan.kill` and stop promptly when tripped,
    ///  - never exceed `plan.rate_cap`.
    fn execute(&mut self, plan: &RunPlan) -> RunReport;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_cap_interval() {
        assert_eq!(RateCap::new(0).min_interval(), None);
        assert_eq!(RateCap::new(1000).min_interval(), Some(Duration::from_millis(1)));
    }

    #[test]
    fn empty_slo_evaluates_nothing() {
        let spec = SloSpec::default();
        assert!(spec.is_empty());
        assert!(!spec.has_rate_thresholds());
        let report = RunReport { units_sent: 100, status_5xx: 100, ..Default::default() };
        // Even an all-5xx run passes an inert SLO: no thresholds were declared.
        assert!(spec.evaluate(&report).passed());
    }

    #[test]
    fn error_rate_breach_is_reported() {
        let spec = SloSpec { max_error_rate: Some(0.05), ..Default::default() };
        // 10 completed + 10 errors = 20 attempts, 50% error rate > 5%.
        let report = RunReport { units_sent: 10, errors: 10, ..Default::default() };
        let verdict = spec.evaluate(&report);
        assert!(!verdict.passed());
        assert!(matches!(verdict.breaches[0], SloBreach::ErrorRate { .. }));
    }

    #[test]
    fn five_xx_counts_against_slo_but_2xx_does_not() {
        let spec = SloSpec { max_5xx_rate: Some(0.10), ..Default::default() };
        // 100 completions, 20 of them 5xx => 20% > 10% => breach.
        let bad = RunReport { units_sent: 100, status_2xx: 80, status_5xx: 20, ..Default::default() };
        assert!(!spec.evaluate(&bad).passed());
        // All 2xx => pass.
        let good = RunReport { units_sent: 100, status_2xx: 100, ..Default::default() };
        assert!(spec.evaluate(&good).passed());
    }

    #[test]
    fn four_xx_only_evaluated_when_threshold_set() {
        let report = RunReport { units_sent: 100, status_2xx: 50, status_4xx: 50, ..Default::default() };
        // No 4xx threshold => 50% 4xx is fine.
        assert!(SloSpec::default().evaluate(&report).passed());
        // With a threshold it breaches.
        let spec = SloSpec { max_4xx_rate: Some(0.10), ..Default::default() };
        assert!(matches!(spec.evaluate(&report).breaches[0], SloBreach::ClientErrorRate { .. }));
    }

    #[test]
    fn p99_latency_breach_only_when_units_sent() {
        let spec = SloSpec { max_p99_micros: Some(1000), ..Default::default() };
        let slow = RunReport { units_sent: 10, status_2xx: 10, p99_micros: 5000, ..Default::default() };
        assert!(matches!(spec.evaluate(&slow).breaches[0], SloBreach::LatencyP99 { .. }));
        // A run that sent nothing cannot breach a latency SLO.
        let empty = RunReport { units_sent: 0, p99_micros: 5000, ..Default::default() };
        assert!(spec.evaluate(&empty).passed());
    }

    #[test]
    fn breaches_rates_ignores_empty_sample() {
        // The watchdog passes zero-attempt windows; they must breach nothing.
        let spec = SloSpec { max_error_rate: Some(0.0), ..Default::default() };
        assert!(spec.breaches_rates(0, 0, 0, 0).is_empty());
    }
}

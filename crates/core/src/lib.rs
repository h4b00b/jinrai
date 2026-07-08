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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunReport {
    pub layer_label: String,
    pub units_sent: u64,
    pub errors: u64,
    pub aborted_early: bool,
    /// Median (p50) latency of completed units, in microseconds.
    pub p50_micros: u64,
    /// 90th-percentile latency, in microseconds.
    pub p90_micros: u64,
    /// 99th-percentile latency, in microseconds.
    pub p99_micros: u64,
    /// Worst observed latency, in microseconds.
    pub max_micros: u64,
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
}

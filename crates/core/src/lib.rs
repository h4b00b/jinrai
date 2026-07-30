//! # jinrai-core — shared engine vocabulary and the module contract
//!
//! Defines the types every traffic module speaks (`Layer`, `RateCap`,
//! `RunPlan`, `RunReport`) and the [`StressModule`] trait that `l34` / `l7`
//! implement. Every entry point here consumes [`AuthorizedTarget`]s, so the
//! safety gate cannot be sidestepped by a module author.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
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

    /// This cap clamped so it never exceeds `ceiling`. The load-profile machinery
    /// runs every stage through this so a profile can only ever shape traffic
    /// *up to* the operator's `--rate` safety ceiling, never above it.
    pub fn clamped_to(self, ceiling: RateCap) -> RateCap {
        RateCap::new(self.per_second.min(ceiling.per_second))
    }
}

/// One constant-rate segment of a run. A [`LoadProfile`] compiles to a sequence
/// of these; the engine runs them back-to-back, re-pacing at each boundary, so
/// it needs exactly one mechanism (emit at a fixed rate for a fixed time) to
/// execute every profile shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadStage {
    pub rate: RateCap,
    pub duration: Duration,
}

/// How a run's emission rate varies over time. Each variant compiles to a
/// `Vec<LoadStage>` via [`LoadProfile::stages`]. The rates a profile carries are
/// the *shape*; the engine additionally clamps every stage to the run's
/// [`RateCap`] ceiling (see [`RateCap::clamped_to`]), so a profile can never
/// breach the operator's `--rate` safety cap.
///
/// A [`Ramp`](LoadProfile::Ramp) is also the vehicle for breaking-point
/// discovery: run its stages in order, evaluate the [`SloSpec`] over each, and
/// the first stage that breaches names the capacity knee (see [`Knee`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadProfile {
    /// Flat rate for the whole duration — the historical constant-rate load. A
    /// long hold at a modest rate is the endurance/"soak" case; no separate
    /// mechanism is needed for it.
    Constant { rate: RateCap, duration: Duration },
    /// Step the rate linearly from `start` to `end` over `duration`, in `steps`
    /// equal-length stages (the last stage sits exactly at `end`).
    Ramp { start: RateCap, end: RateCap, duration: Duration, steps: u32 },
    /// Hold `base`, jump to `peak` for `spike`, then fall back to `base`. `base`
    /// fills the two halves of `base_total` around the central `spike`.
    Spike { base: RateCap, peak: RateCap, base_total: Duration, spike: Duration },
}

impl LoadProfile {
    /// Expand the profile into the concrete constant-rate stages the engine runs.
    /// Rates are the profile's raw shape — clamp each to the run ceiling with
    /// [`RateCap::clamped_to`] before pacing.
    pub fn stages(&self) -> Vec<LoadStage> {
        match *self {
            LoadProfile::Constant { rate, duration } => vec![LoadStage { rate, duration }],
            LoadProfile::Ramp { start, end, duration, steps } => {
                let steps = steps.max(1);
                let total_ns = duration.as_nanos().min(u64::MAX as u128) as u64;
                let base = total_ns / steps as u64;
                let rem = total_ns % steps as u64;
                (0..steps)
                    .map(|i| {
                        // Rate reached after completing step (i+1) of `steps`, so
                        // the final stage lands exactly on `end`.
                        let per_second =
                            lerp(start.per_second, end.per_second, i, steps);
                        // Push the division remainder into the last stage so the
                        // stages sum to exactly `duration`.
                        let ns = base + if i == steps - 1 { rem } else { 0 };
                        LoadStage {
                            rate: RateCap::new(per_second),
                            duration: Duration::from_nanos(ns),
                        }
                    })
                    .collect()
            }
            LoadProfile::Spike { base, peak, base_total, spike } => {
                let half = base_total / 2;
                let mut v = Vec::with_capacity(3);
                if !half.is_zero() {
                    v.push(LoadStage { rate: base, duration: half });
                }
                v.push(LoadStage { rate: peak, duration: spike });
                if !half.is_zero() {
                    v.push(LoadStage { rate: base, duration: half });
                }
                v
            }
        }
    }
}

/// Linear interpolation of an emission rate: the value reached after completing
/// step `i+1` of `steps`, moving from `start` to `end`. Done in `i128` so a
/// ramp-down (`end < start`) and large rates are both handled without overflow.
fn lerp(start: u64, end: u64, i: u32, steps: u32) -> u64 {
    let s = start as i128;
    let e = end as i128;
    let v = s + (e - s) * (i as i128 + 1) / steps as i128;
    v.max(0) as u64
}

/// The capacity knee found by a breaking-point (ramp) discovery run: the highest
/// stage rate the target held *within* its SLO, and the stage rate at which the
/// SLO first breached. A discovery run stops as soon as it finds this rather than
/// keep pushing past the breaking point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Knee {
    /// Highest ramp-stage rate (units/sec) that stayed within the SLO.
    pub sustained_per_sec: u64,
    /// The ramp-stage rate (units/sec) at which the SLO first breached.
    pub breached_at_per_sec: u64,
}

/// Which operating-system error caused one attempt to fail.
///
/// A bare `errors=<n>` counter is the same number for four unrelated causes with
/// four different fixes: `EMFILE` is *our own* descriptor ceiling (a local
/// misconfiguration, nothing to do with the target), `EADDRNOTAVAIL` is local
/// ephemeral-port exhaustion, `ENOBUFS` is local kernel memory, while
/// `ECONNREFUSED`/`ETIMEDOUT` are the target actually rejecting or blackholing
/// traffic — the only two that say anything about the system under test. Keeping
/// them apart is what makes the summary line diagnostic rather than merely
/// alarming.
///
/// The derived `Ord` fixes the reporting order: the named buckets in declaration
/// order, then [`Other`](ErrnoBucket::Other) sorted by raw code, then
/// [`Internal`](ErrnoBucket::Internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrnoBucket {
    /// `EMFILE` — the process hit its own open-file-descriptor limit. A local
    /// ceiling, not target behaviour.
    Emfile,
    /// `ENFILE` — the system-wide open-file table is full. Also local.
    Enfile,
    /// `ENOBUFS` — the kernel could not allocate socket buffer space. Local.
    Enobufs,
    /// `EADDRNOTAVAIL` — no local ephemeral port/address left to bind. Local.
    Eaddrnotavail,
    /// `ECONNREFUSED` — the target actively refused the connection (RST). This
    /// is target behaviour.
    Econnrefused,
    /// `ETIMEDOUT` — the kernel's own connection timeout expired (no response).
    /// Target behaviour.
    Etimedout,
    /// `ECONNRESET` — the connection was reset mid-handshake. Target behaviour.
    Econnreset,
    /// `EHOSTUNREACH` / `ENETUNREACH` — no route to the target.
    Eunreach,
    /// Our own configurable attempt timeout expired before the handshake
    /// resolved. Distinct from [`Etimedout`](ErrnoBucket::Etimedout): the OS
    /// reported nothing, *we* gave up first, so the bucket size is a function of
    /// the configured timeout as much as of the target.
    Timeout,
    /// The socket was fine but the exchange failed at the application-protocol
    /// level — most often a version mismatch (an HTTP/2-only client against a
    /// server that only speaks HTTP/1.1, a malformed/refused stream). No errno
    /// exists: the OS delivered the bytes, the peer would not play along. Kept
    /// apart from the socket buckets because the fix is a different flag, not a
    /// different network.
    Protocol,
    /// Any other OS error, carrying the raw code so it stays actionable without
    /// a code change here.
    Other(i32),
    /// The attempt was refused before it reached the OS (a structural mismatch,
    /// e.g. an IPv6 target handed to an IPv4-only primitive). No errno exists.
    Internal,
}

impl ErrnoBucket {
    /// Classify an I/O failure into a reporting bucket.
    ///
    /// Portable [`ErrorKind`](std::io::ErrorKind)s are matched first. `EMFILE` /
    /// `ENFILE` / `ENOBUFS` have no stable `ErrorKind` (they still decode to
    /// `Uncategorized`), so they are recognised by raw code — and telling `EMFILE`
    /// apart from target behaviour is the entire reason this breakdown exists.
    /// Anything unrecognised keeps its raw code via [`Other`](ErrnoBucket::Other),
    /// so no failure is ever reported as an anonymous increment.
    ///
    /// Lives here rather than in a traffic crate so every layer buckets the same
    /// failure the same way — an operator comparing an L4 and an L7 run must not
    /// have to know which crate wrote the number.
    pub fn from_io_error(e: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        match e.kind() {
            ErrorKind::ConnectionRefused => return ErrnoBucket::Econnrefused,
            ErrorKind::ConnectionReset => return ErrnoBucket::Econnreset,
            ErrorKind::AddrNotAvailable => return ErrnoBucket::Eaddrnotavail,
            ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => {
                return ErrnoBucket::Eunreach
            }
            ErrorKind::TimedOut => {
                // `TcpStream::connect_timeout` signals *our* expired deadline with
                // a synthetic TimedOut error that carries no OS code; the kernel's
                // own ETIMEDOUT does carry one. The two have different fixes (raise
                // the timeout vs. the target is not answering), so they get
                // different buckets.
                return match e.raw_os_error() {
                    Some(_) => ErrnoBucket::Etimedout,
                    None => ErrnoBucket::Timeout,
                };
            }
            // A non-blocking connect that has not resolved yet is our timeout too.
            ErrorKind::WouldBlock => return ErrnoBucket::Timeout,
            _ => {}
        }
        match e.raw_os_error() {
            // EMFILE/ENFILE sit in the original low POSIX errno range, whose
            // values are identical across Linux, macOS and the BSDs.
            #[cfg(unix)]
            Some(24) => ErrnoBucket::Emfile,
            #[cfg(unix)]
            Some(23) => ErrnoBucket::Enfile,
            // ENOBUFS is *not* value-stable across unixes (105 on Linux, 55 on
            // macOS), so only Linux's value is claimed by name; elsewhere it falls
            // through to `Other` with its raw code intact.
            #[cfg(target_os = "linux")]
            Some(105) => ErrnoBucket::Enobufs,
            Some(code) => ErrnoBucket::Other(code),
            None => ErrnoBucket::Internal,
        }
    }
}

impl std::fmt::Display for ErrnoBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrnoBucket::Emfile => write!(f, "EMFILE"),
            ErrnoBucket::Enfile => write!(f, "ENFILE"),
            ErrnoBucket::Enobufs => write!(f, "ENOBUFS"),
            ErrnoBucket::Eaddrnotavail => write!(f, "EADDRNOTAVAIL"),
            ErrnoBucket::Econnrefused => write!(f, "ECONNREFUSED"),
            ErrnoBucket::Etimedout => write!(f, "ETIMEDOUT"),
            ErrnoBucket::Econnreset => write!(f, "ECONNRESET"),
            ErrnoBucket::Eunreach => write!(f, "EUNREACH"),
            ErrnoBucket::Timeout => write!(f, "timeout"),
            ErrnoBucket::Protocol => write!(f, "protocol"),
            ErrnoBucket::Other(code) => write!(f, "os:{code}"),
            ErrnoBucket::Internal => write!(f, "internal"),
        }
    }
}

/// A per-[`ErrnoBucket`] tally of failed attempts. Sums to [`RunReport::errors`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrnoTally {
    counts: BTreeMap<ErrnoBucket, u64>,
}

impl ErrnoTally {
    /// Count one failure in `bucket`.
    pub fn record(&mut self, bucket: ErrnoBucket) {
        *self.counts.entry(bucket).or_insert(0) += 1;
    }

    /// Total failures tallied — should equal the run's `errors` count.
    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }

    /// True when nothing failed (or the layer does not classify failures).
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Non-zero buckets in reporting order (see [`ErrnoBucket`]).
    pub fn iter(&self) -> impl Iterator<Item = (ErrnoBucket, u64)> + '_ {
        self.counts.iter().map(|(&b, &n)| (b, n))
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
    /// `errors` broken down by the OS error behind each failure. Layers that
    /// classify their failures fill this (it sums to `errors`); layers that do
    /// not leave it empty and the reporter omits it. See [`ErrnoBucket`] for why
    /// a single `errors` number is not enough to act on.
    pub errno: ErrnoTally,
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
    /// Set by a breaking-point (ramp) discovery run when a load stage first
    /// breached the SLO: the capacity knee. `None` for every non-discovery run
    /// and for a discovery run that never breached (target held the whole ramp).
    pub knee: Option<Knee>,
    /// Completed responses tallied by the HTTP version actually used on the wire
    /// (`"HTTP/1.1"`, `"HTTP/2.0"`, …), as reported by the client.
    ///
    /// This exists because the negotiated version is *not* obvious from the
    /// command line: an `https` target with ALPN can silently answer HTTP/2 for a
    /// run the operator believed was HTTP/1.1, which changes what is being tested
    /// (multiplexing, header compression, per-connection limits). Layers without a
    /// response leave it empty and the reporter omits it. Sums to `units_sent` for
    /// the fast L7 methods.
    pub http_versions: BTreeMap<String, u64>,
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

    #[test]
    fn constant_profile_is_one_stage() {
        let p = LoadProfile::Constant { rate: RateCap::new(100), duration: Duration::from_secs(10) };
        let stages = p.stages();
        assert_eq!(stages, vec![LoadStage { rate: RateCap::new(100), duration: Duration::from_secs(10) }]);
    }

    #[test]
    fn ramp_steps_reach_end_and_sum_to_duration() {
        let p = LoadProfile::Ramp {
            start: RateCap::new(0),
            end: RateCap::new(1000),
            duration: Duration::from_secs(10),
            steps: 10,
        };
        let stages = p.stages();
        assert_eq!(stages.len(), 10);
        // Linear, last stage sits exactly on `end`, first is one step above start.
        assert_eq!(stages[0].rate, RateCap::new(100));
        assert_eq!(stages[9].rate, RateCap::new(1000));
        // Monotonically non-decreasing.
        assert!(stages.windows(2).all(|w| w[0].rate.per_second <= w[1].rate.per_second));
        // Stages sum to exactly the requested duration (remainder folded in).
        let total: Duration = stages.iter().map(|s| s.duration).sum();
        assert_eq!(total, Duration::from_secs(10));
    }

    #[test]
    fn ramp_with_zero_steps_is_treated_as_one() {
        let p = LoadProfile::Ramp {
            start: RateCap::new(0),
            end: RateCap::new(500),
            duration: Duration::from_secs(4),
            steps: 0,
        };
        let stages = p.stages();
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0].rate, RateCap::new(500));
        assert_eq!(stages[0].duration, Duration::from_secs(4));
    }

    #[test]
    fn spike_is_base_peak_base() {
        let p = LoadProfile::Spike {
            base: RateCap::new(50),
            peak: RateCap::new(500),
            base_total: Duration::from_secs(8),
            spike: Duration::from_secs(4),
        };
        let stages = p.stages();
        assert_eq!(stages.len(), 3);
        assert_eq!(stages[0].rate, RateCap::new(50));
        assert_eq!(stages[1].rate, RateCap::new(500));
        assert_eq!(stages[2].rate, RateCap::new(50));
        assert_eq!(stages[0].duration, Duration::from_secs(4));
        assert_eq!(stages[1].duration, Duration::from_secs(4));
    }

    #[test]
    fn errno_tally_sums_and_orders_buckets() {
        let mut t = ErrnoTally::default();
        assert!(t.is_empty());
        t.record(ErrnoBucket::Econnrefused);
        t.record(ErrnoBucket::Emfile);
        t.record(ErrnoBucket::Emfile);
        t.record(ErrnoBucket::Other(99));
        t.record(ErrnoBucket::Internal);
        t.record(ErrnoBucket::Other(13));
        assert_eq!(t.total(), 6);
        assert!(!t.is_empty());
        // Named buckets in declaration order, then Other by raw code, then Internal.
        assert_eq!(
            t.iter().collect::<Vec<_>>(),
            vec![
                (ErrnoBucket::Emfile, 2),
                (ErrnoBucket::Econnrefused, 1),
                (ErrnoBucket::Other(13), 1),
                (ErrnoBucket::Other(99), 1),
                (ErrnoBucket::Internal, 1),
            ]
        );
    }

    #[test]
    fn errno_bucket_labels_distinguish_our_timeout_from_the_kernels() {
        // The whole point of the breakdown: these two must not read the same.
        assert_eq!(ErrnoBucket::Etimedout.to_string(), "ETIMEDOUT");
        assert_eq!(ErrnoBucket::Timeout.to_string(), "timeout");
        assert_eq!(ErrnoBucket::Other(-7).to_string(), "os:-7");
    }

    #[test]
    fn clamp_holds_the_rate_ceiling() {
        // A profile can shape traffic only up to the run's --rate safety ceiling.
        assert_eq!(RateCap::new(5000).clamped_to(RateCap::new(1000)), RateCap::new(1000));
        assert_eq!(RateCap::new(200).clamped_to(RateCap::new(1000)), RateCap::new(200));
    }
}

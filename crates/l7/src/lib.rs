//! # jinrai-l7 — HTTP/API constant-rate load generation
//!
//! Application-layer load: issues real HTTP requests at a fixed, capped rate for
//! a bounded duration, collecting latency percentiles.
//!
//! ## Datum-based authorization (the safety property)
//!
//! The operator supplies a *URL*. [`L7Engine`] validates the **datum** in that
//! URL's host against the gate, matched only against its own rule type:
//!
//!   - if the host is an **IP literal** (`http://10.0.0.5/`), it is authorized
//!     with [`Authorization::authorize`] against the IP/CIDR rules;
//!   - if the host is a **DNS name** (`http://api.staging.internal/`), the
//!     **name string** is authorized with [`Authorization::authorize_host`]
//!     against the DNS rules.
//!
//! For a name target the **DNS name is the trust boundary**: the name is *not*
//! resolved-then-IP-checked. Only *after* the name has been authorized do we
//! resolve it — exactly once — purely to obtain a connect address, and we pin
//! `reqwest` to that single resolution via
//! [`reqwest::ClientBuilder::resolve_to_addrs`]. Resolving once (no second
//! lookup) closes the TOCTOU window within the run. The resolved IP is
//! intentionally **not** re-checked against any IP allowlist — that is the
//! current requirement: a name is judged as a name.
//!
//! ## Wiring choice
//!
//! `L7Engine` is constructed with the [`RequestSpec`] (method GET for the MVP,
//! plus URL and optional headers) and a clone of the [`Authorization`] gate. The
//! intended flow: the CLI calls [`L7Engine::authorize_target`] to obtain the
//! authorized target for `RunPlan.targets`, then hands the plan to
//! [`L7Engine::execute`], which re-authorizes the datum (defense in depth) and
//! runs. An authorized host target is a perfectly good plan target.
//!
//! ## Load profiles & breaking-point discovery (Phase 6)
//!
//! Beyond a flat constant rate, the engine runs a [`LoadProfile`] — a `ramp`,
//! `spike`, or `constant` shape — by compiling it to a sequence of constant-rate
//! stages and re-pacing at each boundary. Every stage is clamped to the plan's
//! [`RateCap`], so a profile can only ever shape traffic *up to* the operator's
//! `--rate` ceiling. A ramp can also drive breaking-point discovery
//! ([`L7Engine::discover_knee`]): evaluate the SLO over each stage and stop at
//! the first breach, reporting the capacity [`Knee`].

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Url;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use jinrai_core::{
    ErrnoBucket, ErrnoTally, Knee, Layer, LoadProfile, LoadStage, ModuleError, RunPlan, RunReport,
    SloSpec, StressModule,
};
use jinrai_safety::{AuthorizedTarget, Authorization, KillSwitch, SafetyError};

pub mod slow;
pub use slow::{L7SlowEngine, SlowConfig, SlowMode};

pub mod rapid_reset;
pub use rapid_reset::H2RapidResetEngine;

mod h2_frames;

pub mod h2_continuation;
pub use h2_continuation::H2ContinuationEngine;

pub mod h2_frame_flood;
pub use h2_frame_flood::{H2FrameFloodEngine, H2FrameKind};

pub mod h2_stream_flood;
pub use h2_stream_flood::{H2StreamFloodEngine, H2StreamKind};

pub mod tls_flood;
pub use tls_flood::TlsHandshakeEngine;

mod tls;

/// Which HTTP request shape to generate. Every variant reuses the *same*
/// constant-rate dispatch, rate-cap, kill-switch and latency histogram — they
/// differ only in how each individual request is built. This is the L7 analogue
/// of [`jinrai_l34::L4Mode`]: a small closed set of request-flood primitives,
/// deliberately *not* a bag of vendor-specific "bypass" presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum L7Method {
    /// Plain GET flood (the historical MVP).
    #[default]
    Get,
    /// POST flood; carries [`RequestSpec::body`] as the request body.
    Post,
    /// HEAD flood — exercises method-specific handling / rate limits.
    Head,
}

impl L7Method {
    fn label(self) -> &'static str {
        match self {
            L7Method::Get => "l7-http-get",
            L7Method::Post => "l7-http-post",
            L7Method::Head => "l7-http-head",
        }
    }
}

/// Which HTTP protocol version the fast request-flood methods must use.
///
/// Without this the version is whatever the client negotiates, and for an
/// `https` target that means ALPN — so a run the operator thought was HTTP/1.1
/// silently becomes HTTP/2 whenever the server offers it. The two are different
/// tests (one connection per request vs. multiplexed streams, plain vs.
/// HPACK-compressed headers, different server-side limits), so which one runs
/// has to be the operator's choice, not the server's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpVersion {
    /// Let the client negotiate: HTTP/1.1 for `http`, ALPN (usually HTTP/2 when
    /// offered) for `https`. The historical behaviour.
    #[default]
    Auto,
    /// Force HTTP/1.1 — never negotiate h2, even when the server offers it.
    Http11,
    /// Force HTTP/2: ALPN `h2` only for `https`, prior-knowledge h2c for `http`.
    /// A server that cannot do h2 makes every request fail rather than silently
    /// downgrading, so the run reports the mismatch instead of hiding it.
    Http2,
}

impl HttpVersion {
    /// Short operator-facing label, or `None` for `Auto` (nothing was forced).
    pub fn forced_label(self) -> Option<&'static str> {
        match self {
            HttpVersion::Auto => None,
            HttpVersion::Http11 => Some("HTTP/1.1 forced"),
            HttpVersion::Http2 => Some("HTTP/2 forced"),
        }
    }
}

/// What to request. A GET/POST/HEAD against one authorized datum, optionally
/// with a body and per-request cache-busting.
#[derive(Debug, Clone)]
pub struct RequestSpec {
    /// Absolute URL, e.g. `http://127.0.0.1:8080/health`.
    pub url: String,
    /// Which request primitive to run.
    pub method: L7Method,
    /// Optional extra request headers as `(name, value)` pairs. This is also the
    /// hook for header-profile techniques (null/oddball User-Agent, a fixed
    /// Cookie, a Referer, …): the operator supplies them here rather than the
    /// engine hard-coding vendor-specific evasion.
    pub headers: Vec<(String, String)>,
    /// Request body sent with each POST (ignored for GET/HEAD).
    pub body: Option<Vec<u8>>,
    /// Cache-buster: append a unique `_cb=<n>` query parameter to every request
    /// so caches/CDNs cannot serve a stored response. Only the **query** is
    /// mutated — never the host — so the datum authorization and the pinned DNS
    /// resolution still hold for every request.
    pub cache_bust: bool,
    /// Which HTTP version to speak (default: whatever the client negotiates).
    pub http_version: HttpVersion,
}

impl RequestSpec {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: L7Method::Get,
            headers: Vec::new(),
            body: None,
            cache_bust: false,
            http_version: HttpVersion::Auto,
        }
    }
}

/// Why an L7 run could not be prepared. Every variant is fail-closed: on any of
/// these, no request is sent.
#[derive(Debug)]
pub enum L7Error {
    /// The URL could not be parsed.
    InvalidUrl(String),
    /// Scheme is not `http`/`https`.
    UnsupportedScheme(String),
    /// URL has no host component.
    MissingHost,
    /// DNS resolution (for the connect address of a name target) failed.
    Dns(String),
    /// Host resolved to zero addresses.
    NoAddresses,
    /// The datum (IP or host) was refused by the safety gate.
    Refused(SafetyError),
    /// A header name/value could not be parsed.
    BadHeader(String),
    /// Building the HTTP client failed.
    Client(String),
}

impl std::fmt::Display for L7Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L7Error::InvalidUrl(s) => write!(f, "invalid URL: {s}"),
            L7Error::UnsupportedScheme(s) => write!(f, "unsupported URL scheme: {s} (want http/https)"),
            L7Error::MissingHost => write!(f, "URL has no host"),
            L7Error::Dns(s) => write!(f, "DNS resolution failed: {s}"),
            L7Error::NoAddresses => write!(f, "host resolved to no addresses"),
            L7Error::Refused(e) => write!(f, "datum refused by safety gate: {e}"),
            L7Error::BadHeader(s) => write!(f, "invalid header: {s}"),
            L7Error::Client(s) => write!(f, "failed to build HTTP client: {s}"),
        }
    }
}

impl std::error::Error for L7Error {}

/// The URL's host after it has been authorized as a datum. `ip` is `Some` when
/// the host was an IP literal (so no DNS is needed at all). Crate-visible so the
/// slow-connection engine ([`slow`]) shares the exact same safety boundary.
pub(crate) struct Datum {
    pub(crate) target: AuthorizedTarget,
    pub(crate) url: Url,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) ip: Option<IpAddr>,
}

/// Authorize a URL's host as a datum: an IP-literal host against the IP/CIDR
/// rules, a DNS-name host against the DNS rules. No DNS resolution happens here
/// for name targets — the name string itself is what is authorized. Shared by
/// [`L7Engine`] and [`slow::L7SlowEngine`] so there is a single trust boundary.
pub(crate) fn authorize_datum(gate: &Authorization, url_str: &str) -> Result<Datum, L7Error> {
    let url = Url::parse(url_str).map_err(|e| L7Error::InvalidUrl(e.to_string()))?;
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(L7Error::UnsupportedScheme(other.to_string())),
    }
    let host = url.host_str().ok_or(L7Error::MissingHost)?.to_string();
    let port = url.port_or_known_default().ok_or(L7Error::MissingHost)?;

    // Datum-based: an IP-literal host is checked as an IP; anything else is
    // checked as a DNS name (its resolved IP is never independently checked).
    let (target, ip) = if let Ok(ip) = host.parse::<IpAddr>() {
        (gate.authorize(ip).map_err(L7Error::Refused)?, Some(ip))
    } else {
        (gate.authorize_host(&host).map_err(L7Error::Refused)?, None)
    };

    Ok(Datum { target, url, host, port, ip })
}

/// Resolve an authorized datum to connect address(es) exactly ONCE: the IP
/// itself for a literal, else a single DNS lookup. This is the only resolution
/// in a run — pinning to it closes the TOCTOU window. Shared by both engines.
pub(crate) fn resolve_addrs(datum: &Datum) -> Result<Vec<SocketAddr>, L7Error> {
    let addrs: Vec<SocketAddr> = match datum.ip {
        Some(ip) => vec![SocketAddr::new(ip, datum.port)],
        None => (datum.host.as_str(), datum.port)
            .to_socket_addrs()
            .map_err(|e| L7Error::Dns(e.to_string()))?
            .collect(),
    };
    if addrs.is_empty() {
        return Err(L7Error::NoAddresses);
    }
    Ok(addrs)
}

/// Inline health-watchdog configuration. When present *and* the [`SloSpec`] has
/// at least one rate threshold, the engine runs a background task that evaluates
/// the trailing `window` of traffic and trips the kill-switch after
/// `max_breaches` consecutive breaching windows. It can only ever **stop**
/// traffic (via the shared [`KillSwitch`]) — never generate it — so it does not
/// touch the authorization invariant. Worst-case time to abort is
/// `window * max_breaches` of sustained breach, which keeps a transient spike
/// from aborting a run.
#[derive(Debug, Clone, Copy)]
pub struct WatchdogConfig {
    /// Trailing sample window evaluated on each tick.
    pub window: Duration,
    /// Consecutive breaching windows before the kill-switch is tripped.
    pub max_breaches: u32,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self { window: Duration::from_secs(5), max_breaches: 3 }
    }
}

/// The L7 HTTP load engine. Holds the request spec and a clone of the safety
/// gate so it is the one deciding — via the gate — which datum it may touch.
#[derive(Debug, Clone)]
pub struct L7Engine {
    gate: Authorization,
    spec: RequestSpec,
    /// The SLO evaluated at end-of-run (verdict) and, if a watchdog is set, live.
    slo: SloSpec,
    /// When set, the inline health-watchdog that can abort a breaching run.
    watchdog: Option<WatchdogConfig>,
    /// The load shape over time. `None` => a single constant-rate stage at the
    /// plan's rate cap for the whole duration (the historical behaviour).
    profile: Option<LoadProfile>,
    /// When true (ramp profiles only), stop as soon as a stage breaches the SLO
    /// and report the capacity knee instead of running the whole ramp.
    discover_knee: bool,
    /// Cap on concurrent in-flight requests (≈ concurrent keep-alive
    /// connections). `None` => unbounded (the historical behaviour: a task per
    /// dispatch tick). `Some(n)` pins the load to at most `n` simultaneous
    /// connections, the controlled form of keep-alive connection exhaustion:
    /// probe a server's connection-slot / worker-pool limit by holding a fixed
    /// number of connections busy rather than an unbounded rate-driven fan-out.
    max_conns: Option<usize>,
    /// How long one request may stay unresolved before the client gives up and
    /// counts it in the `timeout` bucket.
    request_timeout: Duration,
    /// How long the engine waits for still-in-flight requests *after* the run's
    /// window closes, before cancelling them. See [`DEFAULT_DRAIN_GRACE`].
    drain_grace: Duration,
}

/// Default per-request timeout: how long one request may stay unresolved before
/// the client abandons it. Deliberately generous — a target slow enough to hit
/// this is itself the finding.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Default drain grace: how long the engine waits for in-flight requests after
/// the run's window closes.
///
/// This exists because `--duration` is a **safety control**, not a hint. Dispatch
/// stops at the deadline, but requests already on the wire have not resolved, and
/// waiting all of them out means a run's real traffic window is
/// `duration + request_timeout` — for the defaults, a 3-second run that keeps
/// generating traffic for 13. That is a window the operator never declared and
/// the audit log never recorded.
///
/// So the drain is bounded: in-flight requests get this long to land, and
/// whatever is still outstanding is cancelled and counted under
/// [`ErrnoBucket::Abandoned`]. One second is long enough that a healthy target
/// abandons nothing, and short enough that the declared window still means
/// something.
pub const DEFAULT_DRAIN_GRACE: Duration = Duration::from_secs(1);

impl L7Engine {
    pub fn new(gate: Authorization, spec: RequestSpec) -> Self {
        Self {
            gate,
            spec,
            slo: SloSpec::default(),
            watchdog: None,
            profile: None,
            discover_knee: false,
            max_conns: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            drain_grace: DEFAULT_DRAIN_GRACE,
        }
    }

    /// Attach an SLO. On its own this only produces an end-of-run verdict; pair
    /// it with [`with_watchdog`](Self::with_watchdog) to also abort live.
    pub fn with_slo(mut self, slo: SloSpec) -> Self {
        self.slo = slo;
        self
    }

    /// Enable the inline health-watchdog (auto-abort on sustained SLO breach).
    pub fn with_watchdog(mut self, cfg: WatchdogConfig) -> Self {
        self.watchdog = Some(cfg);
        self
    }

    /// Shape the load over time (ramp / spike / constant). Every stage rate is
    /// clamped to the plan's rate cap, so a profile can only ever emit *up to*
    /// the operator's `--rate` ceiling.
    pub fn with_profile(mut self, profile: LoadProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Turn a ramp profile into a breaking-point discovery run: evaluate the SLO
    /// over each stage and stop at the first breach, reporting the capacity knee.
    /// Inert without a ramp profile and a rate-threshold SLO (nothing breaches).
    /// The live watchdog is suppressed during discovery — the run is *meant* to
    /// reach a breach and stop cleanly, not abort.
    pub fn discover_knee(mut self, on: bool) -> Self {
        self.discover_knee = on;
        self
    }

    /// Cap the number of concurrent in-flight requests (≈ concurrent keep-alive
    /// connections). A dispatch tick that would exceed the cap is skipped rather
    /// than queued, so the load holds at most `n` connections busy — the
    /// controlled form of keep-alive connection exhaustion. `n == 0` is treated
    /// as no cap (unbounded), matching the historical behaviour. The `--rate`
    /// ceiling still applies on top: connections are held busy *up to* that rate.
    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_conns = (n > 0).then_some(n);
        self
    }

    /// How long one request may stay unresolved before it is abandoned and
    /// counted in the `timeout` bucket (default: [`DEFAULT_REQUEST_TIMEOUT`]).
    /// Zero is treated as "keep the default" rather than "give up instantly",
    /// which would make every request fail.
    pub fn with_request_timeout(mut self, d: Duration) -> Self {
        if !d.is_zero() {
            self.request_timeout = d;
        }
        self
    }

    /// How long to wait for in-flight requests once the run's window closes,
    /// before cancelling them (default: [`DEFAULT_DRAIN_GRACE`]). Zero means
    /// cancel immediately at the deadline — the strictest reading of
    /// `--duration`, at the cost of counting every in-flight request as
    /// abandoned.
    pub fn with_drain_grace(mut self, d: Duration) -> Self {
        self.drain_grace = d;
        self
    }

    /// Authorize the URL's host as a datum: IP literal against IP/CIDR rules, or
    /// DNS name against DNS rules. Public so the CLI can validate + report before
    /// building a plan. No DNS resolution happens here for name targets — the
    /// name string is the thing being authorized.
    pub fn authorize_target(&self) -> Result<Vec<AuthorizedTarget>, L7Error> {
        Ok(vec![self.authorize_datum()?.target])
    }

    fn authorize_datum(&self) -> Result<Datum, L7Error> {
        authorize_datum(&self.gate, &self.spec.url)
    }

    fn headers(&self) -> Result<HeaderMap, L7Error> {
        let mut map = HeaderMap::new();
        for (k, v) in &self.spec.headers {
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| L7Error::BadHeader(format!("{k}: {e}")))?;
            let value =
                HeaderValue::from_str(v).map_err(|e| L7Error::BadHeader(format!("{k}: {e}")))?;
            map.insert(name, value);
        }
        Ok(map)
    }

    /// Authorize the datum, then resolve ONCE (for name targets) to build a
    /// client pinned to that single resolution. Returns the client and the URL
    /// to hammer.
    fn prepare(&self) -> Result<(reqwest::Client, Url), L7Error> {
        let datum = self.authorize_datum()?;

        // Connect address(es): the only resolution in the whole run (see
        // `resolve_addrs`).
        let addrs = resolve_addrs(&datum)?;

        let headers = self.headers()?;
        let mut builder = reqwest::Client::builder()
            .resolve_to_addrs(&datum.host, &addrs)
            .default_headers(headers)
            .timeout(self.request_timeout);
        // Pin the protocol version when the operator asked for one. `Auto` leaves
        // reqwest's negotiation alone (h1 for http, ALPN for https).
        builder = match self.spec.http_version {
            HttpVersion::Auto => builder,
            HttpVersion::Http11 => builder.http1_only(),
            // Prior knowledge: h2 with no negotiation and no h1 fallback — for
            // https reqwest offers only `h2` in ALPN, for http it sends the h2c
            // preface directly.
            HttpVersion::Http2 => builder.http2_prior_knowledge(),
        };
        let client = builder.build().map_err(|e| L7Error::Client(e.to_string()))?;

        Ok((client, datum.url))
    }

    /// This primitive could not start. See [`crate::module_error`] for why the
    /// distinction between a refusal and a setup failure is kept.
    fn refusal(&self, e: L7Error) -> ModuleError {
        crate::module_error(format!("L7 {}", self.spec.method.label()), e)
    }
}

impl StressModule for L7Engine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        self.spec.method.label()
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        // Re-authorize the datum + resolve-once + build the pinned client. The
        // gate is the sole authority even if a caller hand-built the plan.
        let (client, url) = match self.prepare() {
            Ok(pair) => pair,
            Err(e) => return Err(self.refusal(e)),
        };

        // Rate cap 0 => refuse to send, whatever the profile asks for.
        if plan.rate_cap.min_interval().is_none() {
            return Ok(RunReport {
                layer_label: format!(
                    "L7 {} {} (rate cap 0 — sent nothing)",
                    self.spec.method.label(),
                    self.spec.url
                ),
                aborted_early: false,
                ..Default::default()
            });
        }

        // Compile the load profile into constant-rate stages (default: one flat
        // stage at the rate cap for the whole duration — the historical load).
        // Every stage is clamped to the plan's rate cap: a profile shapes traffic
        // only *up to* the operator's `--rate` ceiling, never above it. Stages
        // that would emit nothing (rate 0 or zero duration) are dropped.
        let profile = self
            .profile
            .unwrap_or(LoadProfile::Constant { rate: plan.rate_cap, duration: plan.duration });
        let stages: Vec<LoadStage> = profile
            .stages()
            .into_iter()
            .map(|s| LoadStage { rate: s.rate.clamped_to(plan.rate_cap), duration: s.duration })
            .filter(|s| s.rate.per_second > 0 && !s.duration.is_zero())
            .collect();

        // Build the runtime here so `core` stays runtime-agnostic.
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => return Err(self.refusal(L7Error::Client(e.to_string()))),
        };

        let sent = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        // Response classification (Phase 5): every completed response is bucketed
        // by status class so the report can tell a healthy target from one that is
        // answering but failing. `timeouts` is the subset of `errors` that were
        // read/connect timeouts.
        let s2xx = Arc::new(AtomicU64::new(0));
        let s3xx = Arc::new(AtomicU64::new(0));
        let s4xx = Arc::new(AtomicU64::new(0));
        let s5xx = Arc::new(AtomicU64::new(0));
        let timeouts = Arc::new(AtomicU64::new(0));
        // Total time attempts spent holding a concurrency slot, successes and
        // failures alike. The histogram below sees only responses that arrived,
        // but a request that times out holds its permit for the full
        // `--request-timeout-ms` — so it is the failures, not the completions,
        // that decide how much load the concurrency budget could offer. Summed
        // here because the mean is what Little's law needs; see
        // `RunReport::mean_micros`.
        let residency = Arc::new(AtomicU64::new(0));
        // Bounds: 1 microsecond .. 60 seconds (well above the default request
        // timeout), 3 significant figures. Explicit bounds so `saturating_record`
        // clamps only pathological values rather than a fresh histogram's tiny
        // default ceiling. A `--request-timeout-ms` beyond 60 s would clamp the
        // slowest samples to the ceiling; percentiles stay meaningful because a
        // target that slow is the finding, not the measurement.
        let hist = Arc::new(Mutex::new(
            Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).expect("valid histogram bounds"),
        ));
        // Which HTTP version each response actually arrived on. Recorded even for
        // `HttpVersion::Auto` (especially then): it is the only way an operator can
        // see that an https run they read as HTTP/1.1 was negotiated up to h2.
        let protos: Arc<Mutex<BTreeMap<String, u64>>> = Arc::new(Mutex::new(BTreeMap::new()));
        // Why each failed attempt failed — refused / unanswered / protocol / a
        // local ceiling of ours. See `classify_reqwest`.
        let errno = Arc::new(Mutex::new(ErrnoTally::default()));

        let kill = plan.kill.clone();
        let discover_knee = self.discover_knee;
        let max_conns = self.max_conns;
        let drain_grace = self.drain_grace;
        // The watchdog runs only when there is a config, a rate threshold for it
        // to evaluate (it ignores latency), AND we are not in knee-discovery — a
        // discovery run is meant to reach a breach and stop cleanly, not abort.
        let watchdog = self
            .watchdog
            .filter(|_| self.slo.has_rate_thresholds() && !discover_knee);
        let slo = self.slo;
        let aborted_by_watchdog = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Per-request shape, captured once and shared across dispatched tasks.
        let method = self.spec.method;
        let body = self.spec.body.clone().map(Arc::new);
        let cache_bust = self.spec.cache_bust;
        let cb_counter = Arc::new(AtomicU64::new(0));

        // Clones move into the runtime; the originals are read back afterwards.
        let sent_w = sent.clone();
        let errors_w = errors.clone();
        let s2xx_w = s2xx.clone();
        let s3xx_w = s3xx.clone();
        let s4xx_w = s4xx.clone();
        let s5xx_w = s5xx.clone();
        let timeouts_w = timeouts.clone();
        let residency_w = residency.clone();
        let hist_w = hist.clone();
        let protos_w = protos.clone();
        let errno_w = errno.clone();
        let wd_flag = aborted_by_watchdog.clone();

        let (aborted, knee) = rt.block_on(async move {
            // Inline health-watchdog: a background task that trips the shared
            // kill-switch on sustained SLO breach. It only STOPS traffic. (Off
            // during knee discovery — see the `watchdog` filter above.)
            let watchdog_task = watchdog.map(|cfg| {
                tokio::spawn(run_watchdog(
                    slo,
                    cfg,
                    kill.clone(),
                    wd_flag.clone(),
                    sent_w.clone(),
                    errors_w.clone(),
                    s5xx_w.clone(),
                    s4xx_w.clone(),
                ))
            });

            let mut tasks: JoinSet<()> = JoinSet::new();
            let mut aborted = false;
            let mut knee: Option<Knee> = None;

            // Concurrency cap (≈ concurrent keep-alive connections). A tick that
            // cannot get a permit is skipped, not queued, so the load holds at
            // most `n` connections busy. `None` => unbounded (historical).
            let sem = max_conns.map(|n| Arc::new(Semaphore::new(n)));

            // Knee discovery diffs the cumulative counters across each stage
            // boundary (like the watchdog does per window). `stage_start` holds
            // the snapshot at the start of the current stage; `sustained` is the
            // highest stage rate that stayed within the SLO.
            let snapshot = |sent: &AtomicU64, err: &AtomicU64, s5: &AtomicU64, s4: &AtomicU64| {
                (
                    sent.load(Ordering::Relaxed),
                    err.load(Ordering::Relaxed),
                    s5.load(Ordering::Relaxed),
                    s4.load(Ordering::Relaxed),
                )
            };
            let mut stage_start = snapshot(&sent_w, &errors_w, &s5xx_w, &s4xx_w);
            let mut sustained: u64 = 0;

            // `--duration` bounds the whole run, not each stage: a profile whose
            // stages happen to sum to more than the plan asked for gets cut here
            // rather than generating an undeclared extra window of traffic. The
            // profile builders keep their stages inside the duration, but this is
            // the layer that owns the operator's promise, so it enforces it.
            let run_deadline = deadline_in(plan.duration);

            // Run each constant-rate stage back-to-back, re-pacing at each
            // boundary. One mechanism executes every profile shape.
            'stages: for stage in stages {
                let Some(interval_dur) = stage.rate.min_interval() else { continue };
                let stage_deadline = deadline_in(stage.duration).min(run_deadline);
                let mut interval = tokio::time::interval(interval_dur);
                // Never exceed the cap: on a missed tick, delay rather than burst.
                interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

                loop {
                    tokio::select! {
                        _ = interval.tick() => {}
                        _ = wait_for_kill(kill.clone()) => { aborted = true; break 'stages; }
                    }
                    if kill.is_tripped() {
                        aborted = true;
                        break 'stages;
                    }
                    if Instant::now() >= stage_deadline {
                        break;
                    }

                    // Concurrency cap: if all `n` connection slots are busy, skip
                    // this tick rather than pile on. The permit is held for the
                    // request's lifetime and released when it completes, so at
                    // most `n` requests (connections) are ever in flight.
                    let permit = match &sem {
                        Some(sem) => match sem.clone().try_acquire_owned() {
                            Ok(p) => Some(p),
                            Err(_) => continue,
                        },
                        None => None,
                    };

                    let client = client.clone();
                    let url = url.clone();
                    let sent = sent_w.clone();
                    let errors = errors_w.clone();
                    let s2xx = s2xx_w.clone();
                    let s3xx = s3xx_w.clone();
                    let s4xx = s4xx_w.clone();
                    let s5xx = s5xx_w.clone();
                    let timeouts = timeouts_w.clone();
                    let residency = residency_w.clone();
                    let hist = hist_w.clone();
                    let protos = protos_w.clone();
                    let errno = errno_w.clone();
                    let body = body.clone();
                    let cb_counter = cb_counter.clone();
                    tasks.spawn(async move {
                        // Hold the connection-cap permit for the whole request;
                        // dropping it at task end frees a slot for the next tick.
                        let _permit = permit;
                        // Cache-buster touches ONLY the query string, so the host
                        // remains the gate-authorized, DNS-pinned one.
                        let req_url = if cache_bust {
                            let mut u = url;
                            let n = cb_counter.fetch_add(1, Ordering::Relaxed);
                            u.query_pairs_mut().append_pair("_cb", &n.to_string());
                            u
                        } else {
                            url
                        };
                        let req = match method {
                            L7Method::Get => client.get(req_url),
                            L7Method::Head => client.head(req_url),
                            L7Method::Post => match &body {
                                Some(bytes) => client.post(req_url).body(bytes.as_ref().clone()),
                                None => client.post(req_url),
                            },
                        };
                        let started = Instant::now();
                        match req.send().await {
                            Ok(resp) => {
                                let micros = started.elapsed().as_micros() as u64;
                                residency.fetch_add(micros, Ordering::Relaxed);
                                // A response of ANY status is a completed unit; the
                                // status class is what tells health from failure.
                                sent.fetch_add(1, Ordering::Relaxed);
                                let counter = match resp.status().as_u16() {
                                    s if s >= 500 => &s5xx,
                                    400..=499 => &s4xx,
                                    300..=399 => &s3xx,
                                    _ => &s2xx,
                                };
                                counter.fetch_add(1, Ordering::Relaxed);
                                // The version actually used on the wire, not the
                                // one we asked for.
                                *protos
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .entry(format!("{:?}", resp.version()))
                                    .or_insert(0) += 1;
                                hist.lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .saturating_record(micros);
                            }
                            Err(e) => {
                                // A failed request held its slot too — for the full
                                // timeout, in the case that matters most.
                                residency.fetch_add(
                                    started.elapsed().as_micros() as u64,
                                    Ordering::Relaxed,
                                );
                                errors.fetch_add(1, Ordering::Relaxed);
                                if e.is_timeout() {
                                    timeouts.fetch_add(1, Ordering::Relaxed);
                                }
                                errno
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .record(classify_reqwest(&e));
                            }
                        }
                    });
                }

                // Breaking-point check at the stage boundary: did the traffic in
                // THIS stage breach the SLO? Boundary lag is inherent — requests
                // dispatched near a stage's end may complete into the next stage's
                // window (the same property the watchdog has) — so the knee is a
                // coarse capacity estimate, not an exact threshold.
                if discover_knee {
                    let now = snapshot(&sent_w, &errors_w, &s5xx_w, &s4xx_w);
                    let d_sent = now.0.saturating_sub(stage_start.0);
                    let d_err = now.1.saturating_sub(stage_start.1);
                    let d_5xx = now.2.saturating_sub(stage_start.2);
                    let d_4xx = now.3.saturating_sub(stage_start.3);
                    stage_start = now;
                    let attempts = d_sent + d_err;
                    if attempts > 0 && !slo.breaches_rates(attempts, d_err, d_5xx, d_4xx).is_empty() {
                        knee = Some(Knee {
                            sustained_per_sec: sustained,
                            breached_at_per_sec: stage.rate.per_second,
                        });
                        break 'stages;
                    }
                    sustained = stage.rate.per_second;
                }
            }

            // The dispatch window is closed; now bound the tail.
            //
            // `--duration` is a safety control, so it has to bound the *traffic*,
            // not merely the dispatching of it. Waiting every in-flight request
            // out means the real window is `duration + request_timeout` — with the
            // defaults, a 3-second run against a slow target keeps generating
            // traffic for 13 seconds, a window the operator never declared and the
            // audit log never recorded.
            //
            // So: on kill, cancel immediately (an abort must be prompt); otherwise
            // give in-flight requests `drain_grace` to land, then cancel the rest.
            // Either way the cancelled attempts are COUNTED, never dropped — a
            // silently discarded attempt would understate the offered load and
            // flatter the target.
            // An abort must be prompt, so a killed run skips the grace entirely
            // (short-circuit) and cancels straight away.
            let all_landed = !aborted
                && tokio::time::timeout(drain_grace, async {
                    while tasks.join_next().await.is_some() {}
                })
                .await
                .is_ok();
            if !all_landed {
                tasks.abort_all();
            }
            let mut abandoned: u64 = 0;
            while let Some(joined) = tasks.join_next().await {
                // A task that finished on its own already recorded its outcome;
                // only the ones we cancelled are unaccounted for.
                if joined.is_err_and(|e| e.is_cancelled()) {
                    abandoned += 1;
                }
            }
            if abandoned > 0 {
                errors_w.fetch_add(abandoned, Ordering::Relaxed);
                let mut tally = errno_w.lock().unwrap_or_else(|p| p.into_inner());
                for _ in 0..abandoned {
                    tally.record(ErrnoBucket::Abandoned);
                }
            }
            if let Some(handle) = watchdog_task {
                handle.abort();
            }
            (aborted, knee)
        });

        // Every traffic task is joined or cancelled by now, so nothing is left to
        // wait for — but dropping a multi-thread runtime *blocks* until its worker
        // and blocking threads wind down, which for a run that ended with tens of
        // thousands of cancelled requests is seconds of pure teardown charged to
        // the run's wall clock. Release it in the background instead: the run is
        // over, and the process either exits or moves on to reporting.
        rt.shutdown_background();

        let hist = hist.lock().unwrap_or_else(|p| p.into_inner());
        let http_versions =
            std::mem::take(&mut *protos.lock().unwrap_or_else(|p| p.into_inner()));
        let errno = std::mem::take(&mut *errno.lock().unwrap_or_else(|p| p.into_inner()));
        let by_watchdog = aborted_by_watchdog.load(Ordering::Relaxed);
        let note = match (by_watchdog, knee.is_some(), self.spec.http_version.forced_label()) {
            (true, _, Some(v)) => format!(" ({v}, SLO watchdog abort)"),
            (true, _, None) => " (SLO watchdog abort)".to_string(),
            (_, true, Some(v)) => format!(" ({v}, knee found)"),
            (_, true, None) => " (knee found)".to_string(),
            (_, _, Some(v)) => format!(" ({v})"),
            (_, _, None) => String::new(),
        };
        let label = format!("L7 {} {}{note}", self.spec.method.label(), self.spec.url);
        let units_sent = sent.load(Ordering::Relaxed);
        let errors = errors.load(Ordering::Relaxed);
        let resolved = units_sent + errors;
        Ok(RunReport {
            layer_label: label,
            units_sent,
            errors,
            aborted_early: aborted,
            status_2xx: s2xx.load(Ordering::Relaxed),
            status_3xx: s3xx.load(Ordering::Relaxed),
            status_4xx: s4xx.load(Ordering::Relaxed),
            status_5xx: s5xx.load(Ordering::Relaxed),
            timeouts: timeouts.load(Ordering::Relaxed),
            errno,
            aborted_by_watchdog: by_watchdog,
            p50_micros: hist.value_at_quantile(0.5),
            p90_micros: hist.value_at_quantile(0.9),
            p99_micros: hist.value_at_quantile(0.99),
            max_micros: hist.max(),
            mean_micros: residency.load(Ordering::Relaxed).checked_div(resolved).unwrap_or(0),
            knee,
            http_versions,
        })
    }
}

/// The inline health-watchdog. Every `window` it diffs the cumulative counters
/// to get the traffic in that trailing window, evaluates the SLO's *rate*
/// thresholds over it, and counts consecutive breaching windows. After
/// `max_breaches` in a row it trips the kill-switch (and records that the abort
/// was watchdog-driven). A window with no attempts resets the streak — a lull
/// is not a breach. This task can only ever STOP traffic; it never emits any.
#[allow(clippy::too_many_arguments)]
async fn run_watchdog(
    slo: SloSpec,
    cfg: WatchdogConfig,
    kill: KillSwitch,
    aborted_by_watchdog: Arc<std::sync::atomic::AtomicBool>,
    sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    s5xx: Arc<AtomicU64>,
    s4xx: Arc<AtomicU64>,
) {
    let snapshot = |s: &AtomicU64, e: &AtomicU64, f: &AtomicU64, t: &AtomicU64| {
        (
            s.load(Ordering::Relaxed),
            e.load(Ordering::Relaxed),
            f.load(Ordering::Relaxed),
            t.load(Ordering::Relaxed),
        )
    };
    let mut prev = snapshot(&sent, &errors, &s5xx, &s4xx);
    let mut consecutive = 0u32;

    loop {
        // Wake on the window OR promptly if the run is already ending.
        tokio::select! {
            _ = tokio::time::sleep(cfg.window) => {}
            _ = wait_for_kill(kill.clone()) => return,
        }
        let now = snapshot(&sent, &errors, &s5xx, &s4xx);
        let d_sent = now.0.saturating_sub(prev.0);
        let d_err = now.1.saturating_sub(prev.1);
        let d_5xx = now.2.saturating_sub(prev.2);
        let d_4xx = now.3.saturating_sub(prev.3);
        prev = now;

        let attempts = d_sent + d_err;
        if attempts == 0 {
            consecutive = 0;
            continue;
        }
        if slo.breaches_rates(attempts, d_err, d_5xx, d_4xx).is_empty() {
            consecutive = 0;
        } else {
            consecutive += 1;
            if consecutive >= cfg.max_breaches {
                aborted_by_watchdog.store(true, Ordering::Relaxed);
                kill.trip();
                return;
            }
        }
    }
}

/// Bucket one failed HTTP attempt by *why* it failed.
///
/// `errors=100` is the same number whether the target refused every connection,
/// never answered, or answered fine over a protocol version the operator forced
/// it not to speak — three findings with three different next steps. reqwest wraps
/// the real cause, so this walks the source chain down to the underlying
/// [`std::io::Error`] and reuses the shared classifier; a failure with no I/O
/// cause is a protocol-level one.
fn classify_reqwest(e: &reqwest::Error) -> ErrnoBucket {
    // Our own request timeout (`Client::timeout`) first: it can surface with or
    // without an I/O cause, and either way *we* gave up, not the OS.
    if e.is_timeout() {
        return ErrnoBucket::Timeout;
    }
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(err) = src {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            return ErrnoBucket::from_io_error(io);
        }
        src = err.source();
    }
    ErrnoBucket::Protocol
}

/// The instant `d` from now, saturating instead of panicking.
///
/// `Instant + Duration` panics on overflow, and every engine here computes its
/// deadline that way. The CLI caps `--duration` long before that is reachable,
/// but `RunPlan` is a public type: a library caller with an outsized duration
/// should get a run that never voluntarily ends (the kill switch still stops it),
/// not a panic with sockets already open.
pub(crate) fn deadline_in(d: Duration) -> Instant {
    Instant::now().checked_add(d).unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400))
}

/// Map a prepare-time L7 failure onto the module contract's error, keeping the
/// primitive's own name (`what`) in the message.
///
/// The split matters to whoever reads the audit log: `Refused` is jinrai saying
/// no to what was asked for (an unauthorized datum, a scheme it will not drive),
/// `Setup` is the host or the network failing to provide what the run needed.
/// The first is a policy event, the second an operational one.
pub(crate) fn module_error(what: String, e: L7Error) -> ModuleError {
    let msg = format!("{what}: {e}");
    match e {
        L7Error::Refused(_)
        | L7Error::InvalidUrl(_)
        | L7Error::UnsupportedScheme(_)
        | L7Error::MissingHost
        | L7Error::BadHeader(_) => ModuleError::Refused(msg),
        L7Error::Dns(_) | L7Error::NoAddresses | L7Error::Client(_) => ModuleError::Setup(msg),
    }
}

/// How long one frame write may make no progress before the raw-frame engines
/// give up on the connection. Long enough that ordinary backpressure on a busy
/// target is not mistaken for a stall, short enough that a wedged connection is
/// reported rather than sat on for the rest of the run.
pub(crate) const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(5);

/// What became of one frame write.
pub(crate) enum FrameWrite {
    /// The bytes went out.
    Wrote,
    /// The write errored, or made no progress for [`WRITE_STALL_TIMEOUT`].
    /// Both mean the connection is finished; both are the peer's doing, so both
    /// count as an error against the run.
    Failed,
    /// The run ended underneath the write — kill switch or deadline. Not an
    /// error: the write simply did not get to finish.
    Stopped,
}

/// Write `buf`, but never let a stalled peer own the run.
///
/// `write_all` on a socket whose peer has stopped reading pends forever once the
/// kernel send buffer fills, and that is not hypothetical here: several of these
/// primitives exist *precisely* to make a server stop draining. Awaiting it bare
/// inside a loop body parks the task outside the `select!` — past `--duration`,
/// deaf to Ctrl-C — which would make the peer, not the operator, the authority on
/// when a run ends. Racing the write against both keeps that authority where it
/// belongs.
pub(crate) async fn write_or_stop<IO>(
    io: &mut IO,
    buf: &[u8],
    kill: &KillSwitch,
    deadline: Instant,
) -> FrameWrite
where
    IO: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let till_deadline = deadline.saturating_duration_since(Instant::now());
    // Whichever comes first bounds the wait; remember which one it was, so a
    // wedged connection is reported as a failure while a run that simply reached
    // its deadline mid-write is not.
    let stalling = WRITE_STALL_TIMEOUT < till_deadline;
    let wait = WRITE_STALL_TIMEOUT.min(till_deadline);
    tokio::select! {
        r = io.write_all(buf) => {
            if r.is_ok() { FrameWrite::Wrote } else { FrameWrite::Failed }
        }
        _ = wait_for_kill(kill.clone()) => FrameWrite::Stopped,
        _ = tokio::time::sleep(wait) => {
            if stalling { FrameWrite::Failed } else { FrameWrite::Stopped }
        }
    }
}

/// Resolve when the kill switch trips. Polled at a fine granularity so a run
/// stops promptly even when the dispatch interval is coarse (low rates).
pub(crate) async fn wait_for_kill(kill: jinrai_safety::KillSwitch) {
    loop {
        if kill.is_tripped() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    use jinrai_core::{RateCap, SloSpec};
    use jinrai_safety::{Allowlist, KillSwitch};

    fn gate_cidrs(cidrs: &[&str]) -> Authorization {
        Authorization::new(Allowlist::from_cidrs(cidrs).unwrap(), KillSwitch::new())
    }

    /// A throwaway HTTP/1.1 server that answers every connection with a fixed
    /// status line and closes. Enough for reqwest to receive and classify a real
    /// response without pulling in an HTTP-server dependency.
    fn spawn_http_server(status_line: &'static str) -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = stop.clone();
        let handle = thread::spawn(move || {
            while !stop_srv.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
                        let mut buf = [0u8; 1024];
                        let _ = s.read(&mut buf); // best-effort: drain the request line/headers
                        let resp = format!(
                            "HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = s.write_all(resp.as_bytes());
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        (port, stop, handle)
    }

    #[test]
    fn classifies_completed_responses_by_status_class() {
        // A target that answers 500 to everything: those are COMPLETED responses
        // (units_sent), not transport errors, and must land in status_5xx.
        let (port, stop, handle) = spawn_http_server("500 Internal Server Error");
        let url = format!("http://127.0.0.1:{port}/");
        let mut engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url));
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(50),
            duration: Duration::from_millis(400),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.units_sent > 0, "should have completed some responses");
        assert_eq!(report.status_5xx, report.units_sent, "every completion was a 500");
        assert_eq!(report.status_2xx, 0);
        assert_eq!(report.errors, 0, "a 500 is a response, not a transport error");
    }

    /// Build a spec for `url` with a forced protocol version.
    fn spec_with_version(url: &str, v: HttpVersion) -> RequestSpec {
        RequestSpec { http_version: v, ..RequestSpec::new(url) }
    }

    #[test]
    fn records_the_http_version_responses_actually_used() {
        // The test server speaks HTTP/1.1 only; forcing 1.1 must succeed and the
        // report must name the version rather than leaving the operator guessing.
        let (port, stop, handle) = spawn_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/");
        let mut engine = L7Engine::new(
            gate_cidrs(&["127.0.0.0/8"]),
            spec_with_version(&url, HttpVersion::Http11),
        );
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(50),
            duration: Duration::from_millis(400),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.units_sent > 0, "HTTP/1.1 should work against an h1 server");
        assert_eq!(
            report.http_versions.get("HTTP/1.1").copied(),
            Some(report.units_sent),
            "every completion should be tallied as HTTP/1.1: {:?}",
            report.http_versions
        );
        assert!(
            report.layer_label.contains("HTTP/1.1 forced"),
            "label should state the forced version: {}",
            report.layer_label
        );
    }

    #[test]
    fn forcing_http2_against_an_h1_server_fails_as_protocol_not_as_success() {
        // Prior-knowledge h2 against an HTTP/1.1-only server: every attempt must
        // fail, and land in the `protocol` bucket — not be silently downgraded to
        // h1 and reported as a healthy run.
        let (port, stop, handle) = spawn_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/");
        let mut engine = L7Engine::new(
            gate_cidrs(&["127.0.0.0/8"]),
            spec_with_version(&url, HttpVersion::Http2),
        );
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(50),
            duration: Duration::from_millis(400),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert_eq!(report.units_sent, 0, "an h1 server cannot answer prior-knowledge h2");
        assert!(report.errors > 0, "the attempts must be counted as failures");
        assert!(report.http_versions.is_empty(), "no response, so no version tally");
        let buckets: Vec<ErrnoBucket> = report.errno.iter().map(|(b, _)| b).collect();
        assert!(
            buckets.contains(&ErrnoBucket::Protocol),
            "a version mismatch is a protocol failure, got {buckets:?}"
        );
        assert_eq!(report.errno.total(), report.errors, "the breakdown must sum to errors");
    }

    #[test]
    fn refused_connections_are_bucketed_as_econnrefused() {
        // Nothing listening: the failures must name the target's refusal, so an
        // operator can tell it from a local limit of ours.
        let port = {
            // Bind and drop to get a port that is (almost certainly) closed.
            let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            l.local_addr().unwrap().port()
        };
        let url = format!("http://127.0.0.1:{port}/");
        let mut engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url));
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(30),
            duration: Duration::from_millis(300),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");

        assert_eq!(report.units_sent, 0);
        assert!(report.errors > 0);
        let buckets: Vec<ErrnoBucket> = report.errno.iter().map(|(b, _)| b).collect();
        assert!(
            buckets.contains(&ErrnoBucket::Econnrefused),
            "closed port should be ECONNREFUSED, got {buckets:?}"
        );
    }

    #[test]
    fn auto_version_leaves_the_label_and_negotiation_alone() {
        let (port, stop, handle) = spawn_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/");
        let mut engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url));
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(30),
            duration: Duration::from_millis(300),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.units_sent > 0);
        assert!(!report.layer_label.contains("forced"), "label: {}", report.layer_label);
        assert_eq!(HttpVersion::default(), HttpVersion::Auto);
        // Even unforced, the negotiated version is reported.
        assert!(!report.http_versions.is_empty());
    }

    #[test]
    fn watchdog_aborts_on_sustained_slo_breach() {
        // All-5xx traffic against a 0% 5xx SLO must trip the watchdog well before
        // the (deliberately long) deadline.
        let (port, stop, handle) = spawn_http_server("500 Internal Server Error");
        let url = format!("http://127.0.0.1:{port}/");
        let slo = SloSpec { max_5xx_rate: Some(0.0), ..Default::default() };
        let mut engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url))
            .with_slo(slo)
            .with_watchdog(WatchdogConfig { window: Duration::from_millis(100), max_breaches: 2 });
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(100),
            duration: Duration::from_secs(10),
            kill: KillSwitch::new(),
        };
        let start = Instant::now();
        let report = engine.execute(&plan).expect("the run should execute");
        let elapsed = start.elapsed();
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.aborted_by_watchdog, "watchdog should trip on all-5xx traffic");
        assert!(report.aborted_early, "a watchdog trip is also an early abort");
        assert!(elapsed < Duration::from_secs(5), "should abort early, took {elapsed:?}");
        assert!(report.layer_label.contains("watchdog"), "label: {}", report.layer_label);
    }

    #[test]
    fn watchdog_leaves_a_healthy_run_untouched() {
        // A 2xx target against the same 0% 5xx SLO must run to completion.
        let (port, stop, handle) = spawn_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/");
        let slo = SloSpec { max_5xx_rate: Some(0.0), ..Default::default() };
        let mut engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url))
            .with_slo(slo)
            .with_watchdog(WatchdogConfig { window: Duration::from_millis(100), max_breaches: 2 });
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(100),
            duration: Duration::from_millis(400),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(!report.aborted_by_watchdog, "healthy run must not be aborted");
        assert_eq!(report.status_2xx, report.units_sent);
        assert!(slo.evaluate(&report).passed(), "healthy run should meet the SLO");
    }

    fn gate_patterns(entries: &[&str]) -> Authorization {
        Authorization::new(Allowlist::from_patterns(entries).unwrap(), KillSwitch::new())
    }

    #[test]
    fn ip_literal_url_authorized_against_cidr_rule() {
        let engine =
            L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new("http://127.0.0.1:9/"));
        let targets = engine.authorize_target().expect("should authorize");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].as_ip(), Some(IpAddr::from([127, 0, 0, 1])));
    }

    #[test]
    fn ip_literal_url_outside_cidr_refused() {
        // 127.0.0.1 is NOT inside 10.0.0.0/8 => fail-closed refusal.
        let engine =
            L7Engine::new(gate_cidrs(&["10.0.0.0/8"]), RequestSpec::new("http://127.0.0.1:9/"));
        assert!(matches!(
            engine.authorize_target(),
            Err(L7Error::Refused(SafetyError::NotAllowlisted(_)))
        ));
    }

    #[test]
    fn name_url_authorized_by_exact_dns_rule() {
        let engine = L7Engine::new(
            gate_patterns(&["api.staging.internal"]),
            RequestSpec::new("http://api.staging.internal/health"),
        );
        let targets = engine.authorize_target().expect("name should authorize");
        assert_eq!(targets[0].host(), Some("api.staging.internal"));
    }

    #[test]
    fn name_url_authorized_by_wildcard_rule() {
        let engine = L7Engine::new(
            gate_patterns(&["*.staging.internal"]),
            RequestSpec::new("http://api.staging.internal/"),
        );
        assert!(engine.authorize_target().is_ok());
    }

    #[test]
    fn name_not_in_dns_allowlist_refused_even_if_it_would_resolve_to_allowlisted_ip() {
        // 'localhost' resolves to 127.0.0.1 which IS inside the IP rule, but the
        // datum is a NAME and matches no DNS rule => refused. The resolved IP is
        // never consulted (that's the new requirement).
        let engine = L7Engine::new(
            gate_patterns(&["127.0.0.0/8", "*.staging.internal"]),
            RequestSpec::new("http://localhost:9/"),
        );
        assert!(matches!(
            engine.authorize_target(),
            Err(L7Error::Refused(SafetyError::NotAllowlistedHost(_)))
        ));
    }

    #[test]
    fn name_authorized_when_only_dns_rules_exist() {
        let engine = L7Engine::new(
            gate_patterns(&["*.staging.internal"]),
            RequestSpec::new("http://api.staging.internal/"),
        );
        assert!(engine.authorize_target().is_ok());
    }

    #[test]
    fn empty_allowlist_refuses() {
        let engine = L7Engine::new(gate_cidrs(&[]), RequestSpec::new("http://127.0.0.1:9/"));
        assert!(matches!(
            engine.authorize_target(),
            Err(L7Error::Refused(SafetyError::EmptyAllowlist))
        ));
    }

    #[test]
    fn ip_literal_url_refused_when_only_dns_rules_exist() {
        // Crux (other direction): an IP datum is judged only by CIDR rules, so an
        // IP-literal URL is refused when the allowlist holds DNS rules alone.
        let engine = L7Engine::new(
            gate_patterns(&["*.staging.internal"]),
            RequestSpec::new("http://127.0.0.1:9/"),
        );
        assert!(matches!(
            engine.authorize_target(),
            Err(L7Error::Refused(SafetyError::NotAllowlisted(_)))
        ));
    }

    #[test]
    fn rate_cap_zero_sends_nothing() {
        // `--rate 0` => min_interval None => the engine emits no requests at all.
        let g = gate_cidrs(&["127.0.0.0/8"]);
        let mut engine = L7Engine::new(g, RequestSpec::new("http://127.0.0.1:9/"));
        let plan = RunPlan {
            targets: engine.authorize_target().expect("loopback authorizes"),
            rate_cap: jinrai_core::RateCap::new(0),
            duration: Duration::from_millis(50),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        assert_eq!(report.units_sent, 0);
        assert_eq!(report.errors, 0);
        assert!(!report.aborted_early);
        assert!(report.layer_label.contains("sent nothing"));
    }

    #[test]
    fn pre_tripped_kill_switch_aborts_without_sending() {
        let g = gate_cidrs(&["127.0.0.0/8"]);
        let mut engine = L7Engine::new(g, RequestSpec::new("http://127.0.0.1:9/"));
        let kill = KillSwitch::new();
        kill.trip();
        let plan = RunPlan {
            targets: engine.authorize_target().expect("loopback authorizes"),
            rate_cap: jinrai_core::RateCap::new(1000),
            duration: Duration::from_secs(30),
            kill,
        };
        let report = engine.execute(&plan).expect("the run should execute");
        assert_eq!(report.units_sent, 0);
        assert!(report.aborted_early);
    }

    #[test]
    fn method_surfaces_in_engine_name() {
        // The chosen primitive must be visible in the module name (logs/reports)
        // and default to GET, preserving the historical behaviour.
        for (method, want) in [
            (L7Method::Get, "l7-http-get"),
            (L7Method::Post, "l7-http-post"),
            (L7Method::Head, "l7-http-head"),
        ] {
            let spec = RequestSpec { method, ..RequestSpec::new("http://127.0.0.1:9/") };
            let engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), spec);
            assert_eq!(engine.name(), want);
        }
        assert_eq!(RequestSpec::new("http://127.0.0.1:9/").method, L7Method::Get);
    }

    #[test]
    fn non_http_scheme_refused() {
        let engine =
            L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new("ftp://127.0.0.1/"));
        assert!(matches!(
            engine.authorize_target(),
            Err(L7Error::UnsupportedScheme(_))
        ));
    }

    use jinrai_core::LoadProfile;

    /// Build a plan against a loopback server on `port` at the given ceiling.
    fn loopback_plan(engine: &L7Engine, rate: u64, ms: u64) -> RunPlan {
        RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(rate),
            duration: Duration::from_millis(ms),
            kill: KillSwitch::new(),
        }
    }

    #[test]
    fn ramp_profile_healthy_runs_every_stage() {
        // A 200 target with a ramp profile: no discovery, so it runs the whole
        // ramp and never records a knee.
        let (port, stop, handle) = spawn_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/");
        let profile = LoadProfile::Ramp {
            start: RateCap::new(0),
            end: RateCap::new(60),
            duration: Duration::from_millis(600),
            steps: 3,
        };
        let mut engine =
            L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url)).with_profile(profile);
        let plan = loopback_plan(&engine, 1000, 600);
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.units_sent > 0, "ramp should have sent something");
        assert!(report.knee.is_none(), "no discovery => no knee");
        assert!(!report.aborted_early);
    }

    #[test]
    fn discover_knee_stops_at_first_breaching_stage() {
        // A target that answers 500 to everything, ramped under a 0% 5xx SLO with
        // knee discovery on: the very first stage breaches, so the knee is that
        // stage's rate with a sustained rate of 0. The run stops CLEANLY (not an
        // abort) — discovery is meant to find the breaking point, not fail.
        let (port, stop, handle) = spawn_http_server("500 Internal Server Error");
        let url = format!("http://127.0.0.1:{port}/");
        let slo = SloSpec { max_5xx_rate: Some(0.0), ..Default::default() };
        // start=0,end=60,steps=3 => stage rates 20, 40, 60; first stage = 20/s.
        let profile = LoadProfile::Ramp {
            start: RateCap::new(0),
            end: RateCap::new(60),
            duration: Duration::from_millis(900),
            steps: 3,
        };
        let mut engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url))
            .with_slo(slo)
            .with_profile(profile)
            .discover_knee(true);
        let plan = loopback_plan(&engine, 1000, 900);
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        let knee = report.knee.expect("all-5xx traffic should trip the knee");
        assert_eq!(knee.breached_at_per_sec, 20, "first ramp stage rate");
        assert_eq!(knee.sustained_per_sec, 0, "nothing held the SLO");
        assert!(!report.aborted_early, "a knee stop is clean, not an abort");
        assert_eq!(report.status_5xx, report.units_sent);
        assert!(report.layer_label.contains("knee"), "label: {}", report.layer_label);
    }

    #[test]
    fn discover_knee_healthy_target_finds_no_knee() {
        // A 200 target under a 0% 5xx SLO: no stage breaches, so discovery runs
        // the full ramp and reports no knee (the target held the whole way up).
        let (port, stop, handle) = spawn_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/");
        let slo = SloSpec { max_5xx_rate: Some(0.0), ..Default::default() };
        let profile = LoadProfile::Ramp {
            start: RateCap::new(0),
            end: RateCap::new(60),
            duration: Duration::from_millis(600),
            steps: 3,
        };
        let mut engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url))
            .with_slo(slo)
            .with_profile(profile)
            .discover_knee(true);
        let plan = loopback_plan(&engine, 1000, 600);
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.knee.is_none(), "healthy target has no knee");
        assert_eq!(report.status_2xx, report.units_sent);
        assert!(!report.aborted_early);
    }

    #[test]
    fn spike_profile_executes_all_three_stages() {
        // Sanity: a spike (base→peak→base) runs to completion against a 200 target.
        let (port, stop, handle) = spawn_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/");
        let profile = LoadProfile::Spike {
            base: RateCap::new(20),
            peak: RateCap::new(100),
            base_total: Duration::from_millis(200),
            spike: Duration::from_millis(200),
        };
        let mut engine =
            L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url)).with_profile(profile);
        let plan = loopback_plan(&engine, 1000, 400);
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.units_sent > 0, "spike should have sent something");
        assert!(report.knee.is_none());
        assert!(!report.aborted_early);
    }

    #[test]
    fn profile_stage_rates_are_clamped_to_the_ceiling() {
        // A profile asking for 10_000/s under a --rate 50 ceiling must never pace
        // faster than 50/s: the ceiling is a safety cap, not a suggestion. Over a
        // 300ms constant stage at <=50/s we can send at most ~16 units; assert we
        // stayed well under the profile's unclamped demand.
        let (port, stop, handle) = spawn_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/");
        let profile = LoadProfile::Constant {
            rate: RateCap::new(10_000),
            duration: Duration::from_millis(300),
        };
        let mut engine =
            L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url)).with_profile(profile);
        let plan = loopback_plan(&engine, 50, 300);
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        // At 50/s for 300ms the cap allows ~16 dispatches; 10_000/s would be
        // thousands. A generous bound proves the clamp held without being flaky.
        assert!(report.units_sent > 0);
        assert!(report.attempts() < 100, "clamp failed: {} attempts", report.attempts());
    }

    #[test]
    fn max_connections_caps_concurrency() {
        use std::sync::atomic::AtomicUsize;
        // Server: each handler bumps a live counter, records the peak, holds
        // briefly, then responds and closes. With the engine capped at N and a
        // high rate, the peak number of simultaneous handlers must never exceed
        // N — uncapped, the 120ms handler + 500/s rate would reach dozens.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let (stop_srv, live_srv, peak_srv) = (stop.clone(), live.clone(), peak.clone());
        let handle = thread::spawn(move || {
            let mut workers = Vec::new();
            while !stop_srv.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let (live, peak) = (live_srv.clone(), peak_srv.clone());
                        workers.push(thread::spawn(move || {
                            let n = live.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(n, Ordering::SeqCst);
                            let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
                            let mut buf = [0u8; 1024];
                            let _ = s.read(&mut buf);
                            thread::sleep(Duration::from_millis(120));
                            let _ = s.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                            live.fetch_sub(1, Ordering::SeqCst);
                        }));
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
            for w in workers {
                let _ = w.join();
            }
        });

        let url = format!("http://127.0.0.1:{port}/");
        let cap = 3usize;
        let mut engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url))
            .with_max_connections(cap);
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(500),
            duration: Duration::from_millis(700),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.units_sent > 0, "should complete some requests");
        let observed = peak.load(Ordering::SeqCst);
        assert!(observed > 0 && observed <= cap, "peak concurrency {observed} must be <= cap {cap}");
    }

    /// A server that accepts every connection and never answers, holding the
    /// socket open until told to stop. Every request against it stays in flight
    /// until the client's own timeout — which is exactly the condition that used
    /// to stretch a run past its declared window.
    fn spawn_blackhole_server() -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = stop.clone();
        let handle = thread::spawn(move || {
            // Hold every accepted socket: dropping them would send a FIN and let
            // the client resolve the request early, defeating the point.
            let mut held = Vec::new();
            while !stop_srv.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((s, _)) => held.push(s),
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        (port, stop, handle)
    }

    /// `--duration` must bound the traffic, not just the dispatching of it.
    ///
    /// Against a target that never answers, every dispatched request sits in
    /// flight until the request timeout. Draining them all would make the real
    /// traffic window `duration + request_timeout`; the bounded drain caps the
    /// overshoot at the grace period instead.
    #[test]
    fn run_does_not_outlive_its_window_when_the_target_never_answers() {
        let (port, stop, handle) = spawn_blackhole_server();
        let url = format!("http://127.0.0.1:{port}/");
        let duration = Duration::from_millis(500);
        let grace = Duration::from_millis(300);
        // A request timeout far longer than the whole run: if the drain were
        // unbounded, execute() could not return before it expires.
        let request_timeout = Duration::from_secs(8);

        let mut engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url))
            .with_request_timeout(request_timeout)
            .with_drain_grace(grace);
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(50),
            duration,
            kill: KillSwitch::new(),
        };

        let wall = Instant::now();
        let report = engine.execute(&plan).expect("the run should execute");
        let elapsed = wall.elapsed();
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        // Generous headroom for runtime shutdown, but nowhere near the 8s that an
        // unbounded drain would have taken.
        let ceiling = duration + grace + Duration::from_millis(1500);
        assert!(
            elapsed < ceiling,
            "run took {elapsed:?}, must stay under {ceiling:?} (duration {duration:?} \
             + grace {grace:?}); an unbounded drain would have waited {request_timeout:?}"
        );

        // Nothing could have completed against a blackhole, and every attempt the
        // engine gave up on must still be accounted for.
        assert_eq!(report.units_sent, 0, "a blackhole cannot complete a request");
        assert!(report.attempts() > 0, "the run must have offered some load");
        let abandoned = report
            .errno
            .iter()
            .find(|(b, _)| *b == ErrnoBucket::Abandoned)
            .map(|(_, n)| n)
            .unwrap_or(0);
        assert!(abandoned > 0, "cancelled attempts must be counted, not dropped: {:?}", report.errno);
        assert_eq!(
            report.errno.total(),
            report.errors,
            "the errno breakdown must still sum to the error count"
        );
    }

    /// The bounded drain must not cost a healthy target anything: when responses
    /// land well inside the grace period, nothing is abandoned.
    #[test]
    fn healthy_target_abandons_nothing_at_the_deadline() {
        let (port, stop, handle) = spawn_http_server("200 OK");
        let url = format!("http://127.0.0.1:{port}/");
        let mut engine = L7Engine::new(gate_cidrs(&["127.0.0.0/8"]), RequestSpec::new(&url));
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(50),
            duration: Duration::from_millis(400),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.units_sent > 0, "should complete requests against a live server");
        assert!(
            !report.errno.iter().any(|(b, _)| b == ErrnoBucket::Abandoned),
            "a responsive target must not have attempts abandoned: {:?}",
            report.errno
        );
    }
}

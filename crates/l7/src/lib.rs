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
//! ## Deferred (later phases)
//!
//! MVP is a single **constant-rate** GET load. TODO(phase-later): ramp-up / soak
//! / spike load profiles, non-GET methods and request bodies. Not built now.

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Url;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use jinrai_core::{Layer, RunPlan, RunReport, StressModule};
use jinrai_safety::{AuthorizedTarget, Authorization, SafetyError};

/// What to request. Method is GET for the MVP (see module-level TODO).
#[derive(Debug, Clone)]
pub struct RequestSpec {
    /// Absolute URL, e.g. `http://127.0.0.1:8080/health`.
    pub url: String,
    /// Optional extra request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
}

impl RequestSpec {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), headers: Vec::new() }
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
/// the host was an IP literal (so no DNS is needed at all).
struct Datum {
    target: AuthorizedTarget,
    url: Url,
    host: String,
    port: u16,
    ip: Option<IpAddr>,
}

/// The L7 HTTP load engine. Holds the request spec and a clone of the safety
/// gate so it is the one deciding — via the gate — which datum it may touch.
#[derive(Debug, Clone)]
pub struct L7Engine {
    gate: Authorization,
    spec: RequestSpec,
}

impl L7Engine {
    pub fn new(gate: Authorization, spec: RequestSpec) -> Self {
        Self { gate, spec }
    }

    /// Authorize the URL's host as a datum: IP literal against IP/CIDR rules, or
    /// DNS name against DNS rules. Public so the CLI can validate + report before
    /// building a plan. No DNS resolution happens here for name targets — the
    /// name string is the thing being authorized.
    pub fn authorize_target(&self) -> Result<Vec<AuthorizedTarget>, L7Error> {
        Ok(vec![self.authorize_datum()?.target])
    }

    fn authorize_datum(&self) -> Result<Datum, L7Error> {
        let url = Url::parse(&self.spec.url).map_err(|e| L7Error::InvalidUrl(e.to_string()))?;
        match url.scheme() {
            "http" | "https" => {}
            other => return Err(L7Error::UnsupportedScheme(other.to_string())),
        }
        let host = url.host_str().ok_or(L7Error::MissingHost)?.to_string();
        let port = url.port_or_known_default().ok_or(L7Error::MissingHost)?;

        // Datum-based: an IP-literal host is checked as an IP; anything else is
        // checked as a DNS name (its resolved IP is never independently checked).
        let (target, ip) = if let Ok(ip) = host.parse::<IpAddr>() {
            (self.gate.authorize(ip).map_err(L7Error::Refused)?, Some(ip))
        } else {
            (self.gate.authorize_host(&host).map_err(L7Error::Refused)?, None)
        };

        Ok(Datum { target, url, host, port, ip })
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

        // Connect address(es): the IP itself for a literal, else a single DNS
        // lookup. This is the only resolution in the whole run.
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

        let headers = self.headers()?;
        let client = reqwest::Client::builder()
            .resolve_to_addrs(&datum.host, &addrs)
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| L7Error::Client(e.to_string()))?;

        Ok((client, datum.url))
    }

    fn refusal_report(&self, e: L7Error) -> RunReport {
        RunReport {
            layer_label: format!("L7 REFUSED: {e}"),
            aborted_early: true,
            ..Default::default()
        }
    }
}

impl StressModule for L7Engine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        "l7-http"
    }

    fn execute(&mut self, plan: &RunPlan) -> RunReport {
        // Re-authorize the datum + resolve-once + build the pinned client. The
        // gate is the sole authority even if a caller hand-built the plan.
        let (client, url) = match self.prepare() {
            Ok(pair) => pair,
            Err(e) => return self.refusal_report(e),
        };

        // Rate cap: min spacing between dispatches. `None` => refuse to send.
        let Some(interval_dur) = plan.rate_cap.min_interval() else {
            return RunReport {
                layer_label: format!("L7 http GET {} (rate cap 0 — sent nothing)", self.spec.url),
                aborted_early: false,
                ..Default::default()
            };
        };

        // Build the runtime here so `core` stays runtime-agnostic.
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => return self.refusal_report(L7Error::Client(e.to_string())),
        };

        let sent = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        // Bounds: 1 microsecond .. 60 seconds (well above the 10 s request
        // timeout), 3 significant figures. Explicit bounds so `saturating_record`
        // clamps only pathological values rather than a fresh histogram's tiny
        // default ceiling.
        let hist = Arc::new(Mutex::new(
            Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).expect("valid histogram bounds"),
        ));

        let kill = plan.kill.clone();
        let duration = plan.duration;

        // Clones move into the runtime; the originals are read back afterwards.
        let sent_w = sent.clone();
        let errors_w = errors.clone();
        let hist_w = hist.clone();

        let aborted = rt.block_on(async move {
            let deadline = Instant::now() + duration;
            let mut interval = tokio::time::interval(interval_dur);
            // Never exceed the cap: on a missed tick, delay rather than burst.
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

            let mut tasks: JoinSet<()> = JoinSet::new();
            let mut aborted = false;

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = wait_for_kill(kill.clone()) => { aborted = true; break; }
                }
                if kill.is_tripped() {
                    aborted = true;
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }

                let client = client.clone();
                let url = url.clone();
                let sent = sent_w.clone();
                let errors = errors_w.clone();
                let hist = hist_w.clone();
                tasks.spawn(async move {
                    let started = Instant::now();
                    match client.get(url).send().await {
                        Ok(_resp) => {
                            let micros = started.elapsed().as_micros() as u64;
                            sent.fetch_add(1, Ordering::Relaxed);
                            hist.lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .saturating_record(micros);
                        }
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }

            // Stop promptly on kill: abort in-flight rather than waiting them out.
            if aborted {
                tasks.abort_all();
            }
            while tasks.join_next().await.is_some() {}
            aborted
        });

        let hist = hist.lock().unwrap_or_else(|p| p.into_inner());
        RunReport {
            layer_label: format!("L7 http GET {}", self.spec.url),
            units_sent: sent.load(Ordering::Relaxed),
            errors: errors.load(Ordering::Relaxed),
            aborted_early: aborted,
            p50_micros: hist.value_at_quantile(0.5),
            p90_micros: hist.value_at_quantile(0.9),
            p99_micros: hist.value_at_quantile(0.99),
            max_micros: hist.max(),
        }
    }
}

/// Resolve when the kill switch trips. Polled at a fine granularity so a run
/// stops promptly even when the dispatch interval is coarse (low rates).
async fn wait_for_kill(kill: jinrai_safety::KillSwitch) {
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
    use jinrai_safety::{Allowlist, KillSwitch};

    fn gate_cidrs(cidrs: &[&str]) -> Authorization {
        Authorization::new(Allowlist::from_cidrs(cidrs).unwrap(), KillSwitch::new())
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
        let report = engine.execute(&plan);
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
        let report = engine.execute(&plan);
        assert_eq!(report.units_sent, 0);
        assert!(report.aborted_early);
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
}

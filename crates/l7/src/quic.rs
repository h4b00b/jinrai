//! # QUIC / HTTP-3 primitives — isolated-lab / authorized use.
//!
//! The two QUIC-layer resilience tests, and the first thing in jinrai that could
//! not be hand-rolled the way the raw HTTP/2 framing and the TLS ClientHello
//! bytes were. QUIC carries its handshake *inside* AEAD-protected packets: header
//! protection, packet-number spaces, CRYPTO-frame reassembly and loss recovery
//! all have to exist before a single byte reaches the server's TLS state machine.
//! See `Cargo.toml` for why `quinn` is the dependency that buys that.
//!
//!   - [`QuicKind::Handshake`] — **QUIC handshake flood.** Open a QUIC connection,
//!     complete the handshake, drop it, repeat, concurrently. The same CPU
//!     asymmetry [`crate::tls_flood`] measures over TCP, except QUIC moves the
//!     work *further forward*: the server must decrypt the Initial, parse a
//!     ClientHello and produce a signature before anything resembling a session
//!     exists, and it does so for a client that has proved nothing beyond being
//!     able to receive one round trip. What this measures is whether the target's
//!     HTTP/3 endpoint is rate-limited and sized for that, or whether it will
//!     sign for anyone who asks.
//!
//!   - [`QuicKind::Quicloris`] — **QUICLORIS**, Slowloris carried to HTTP/3. Hold
//!     connections open, each with one request stream that never finishes: a
//!     `HEADERS` frame whose declared length is far larger than what will ever
//!     arrive, dribbled a byte per tick. The server keeps per-connection and
//!     per-stream state waiting for the rest of a request that is always
//!     *almost* there.
//!
//! ## Why QUICLORIS is not just Slowloris again
//!
//! An HTTP/1.1 Slowloris is retired by a request-header read timeout, which is
//! why every mainstream server grew one. QUIC's equivalent budget is the **idle
//! timeout**, and a connection dribbling bytes is never idle — so the timeout
//! that closes an abandoned QUIC connection does not fire here. Whether anything
//! *else* closes it is exactly the question the run answers.
//!
//! ## Amplification: deliberately none
//!
//! QUIC is the protocol where a traffic generator most easily turns into a
//! reflector, so the boundary is worth stating. jinrai sends from a real,
//! OS-assigned UDP source address on an ordinary client socket — there is no
//! source-address option anywhere in this module, and a spoofed Initial is what
//! every reflection variant needs. Because the source is real, RFC 9000's
//! anti-amplification limit is not being evaded but simply satisfied: the server
//! answers *us*. Retry/token-replay amplification is out of scope by design.
//!
//! ## Same safety boundary as every other L7 engine
//!
//! The URL host is authorized as a **datum** ([`crate::authorize_datum`]) and
//! resolved **once** to a pinned connect address ([`crate::resolve_addrs`]); every
//! connection only ever goes there. `https` only — there is no plaintext QUIC.
//! The run is bounded by `duration`, capped by the rate cap and by `max_conns`,
//! and aborts promptly on the kill switch.
//!
//! ## What a run tells you
//!
//! Three outcomes, kept apart because they are three different findings — QUIC
//! makes the distinction sharper than TCP does, since a target with no UDP
//! listener and one that is filtered upstream look identical from a connect()
//! that never had a connect() to fail:
//!
//!   - **completed / held** — the handshake finished. The server did the work.
//!   - **refused** — the peer answered in QUIC and said no. Almost always ALPN:
//!     the target speaks QUIC but not `h3`. A run that is all refusals is a
//!     finding about the endpoint, not about its capacity.
//!   - **errors** — nothing came back at all: no UDP listener, a dropped Initial,
//!     or a path that does not carry QUIC. Read this as "not reached", never as
//!     "withstood".

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{ClientConfig, Endpoint, TransportConfig};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use jinrai_core::{Layer, ModuleError, RunPlan, RunReport, StressModule};
use jinrai_safety::{Authorization, AuthorizedTarget, KillSwitch};

use crate::{authorize_datum, resolve_addrs, wait_for_kill, L7Error};

/// Which QUIC primitive to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicKind {
    /// Complete a full QUIC handshake, drop it, repeat.
    Handshake,
    /// Hold connections open, each with one request stream that never finishes.
    Quicloris,
}

impl QuicKind {
    fn label(self) -> &'static str {
        match self {
            QuicKind::Handshake => "l7-quic-handshake",
            QuicKind::Quicloris => "l7-quicloris",
        }
    }

    /// How the summary names a connection that reached the point the primitive
    /// was after, singular and plural. Two forms rather than a suffix because
    /// "connection held" pluralises in the middle.
    fn success_noun(self, n: u64) -> &'static str {
        match (self, n) {
            (QuicKind::Handshake, 1) => "handshake",
            (QuicKind::Handshake, _) => "handshakes",
            (QuicKind::Quicloris, 1) => "connection held",
            (QuicKind::Quicloris, _) => "connections held",
        }
    }
}

/// Runtime configuration for a QUIC run.
#[derive(Debug, Clone, Copy)]
pub struct QuicConfig {
    pub kind: QuicKind,
    /// Concurrent connection ceiling. For [`QuicKind::Handshake`] this bounds
    /// handshakes in flight; for [`QuicKind::Quicloris`] it is the number of
    /// connections opened and then held.
    pub max_conns: usize,
    /// Dribble interval for [`QuicKind::Quicloris`] — one byte of the unfinished
    /// request per tick. Unused by the handshake flood. Clamped to [`MIN_TICK`].
    pub tick: Duration,
}

/// Floor on [`QuicConfig::tick`]. Same reasoning as [`crate::long_lived::MIN_TICK`]:
/// the rate cap governs how fast connections are *opened*, never how fast an open
/// one is written to, so an unpaced dribble loop would be a stream-data flood that
/// `--rate` does not bound.
pub const MIN_TICK: Duration = Duration::from_millis(1);

/// Idle timeout announced to the peer. Generous on purpose: a QUICLORIS run wants
/// the connection to survive as long as the *server* is willing to keep it, so the
/// limit under test is the server's, not one jinrai imposed on itself.
const MAX_IDLE: Duration = Duration::from_secs(30);

/// Keep-alive PING interval, well inside [`MAX_IDLE`]. The dribble already keeps
/// the connection non-idle at a normal `--drip-ms`; this covers the case where the
/// operator sets a tick longer than the idle timeout.
const KEEP_ALIVE: Duration = Duration::from_secs(10);

/// How long the endpoint may spend closing after the run window ends. Enough for
/// a `CONNECTION_CLOSE` to reach a live target, short enough that the elapsed
/// time in the report still means what the operator asked for.
const CLOSE_GRACE: Duration = Duration::from_millis(500);

/// ALPN for HTTP/3 (RFC 9114).
const ALPN_H3: &[u8] = b"h3";

/// The QUIC engine. Holds a clone of the gate (the sole authority), the target
/// URL, and the run config.
#[derive(Debug, Clone)]
pub struct QuicEngine {
    gate: Authorization,
    url: String,
    cfg: QuicConfig,
}

impl QuicEngine {
    pub fn new(gate: Authorization, url: impl Into<String>, cfg: QuicConfig) -> Self {
        Self { gate, url: url.into(), cfg }
    }

    /// Authorize the datum (public so the CLI can fail-closed before any run).
    pub fn authorize_target(&self) -> Result<Vec<AuthorizedTarget>, L7Error> {
        Ok(vec![authorize_datum(&self.gate, &self.url)?.target])
    }

    fn prepare(&self) -> Result<Prepared, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
        // https-only. Not a hardening choice — QUIC has no plaintext mode at all,
        // so an http URL here is a request for something that does not exist.
        if datum.url.scheme() != "https" {
            return Err(L7Error::UnsupportedScheme(format!(
                "{} — QUIC needs https (there is no plaintext QUIC)",
                datum.url.scheme()
            )));
        }
        let addr = resolve_addrs(&datum)?.primary();
        // The name offered in the ClientHello's SNI. Certificate identity is not
        // the safety boundary here (see `crate::tls`), but the name still has to
        // be well-formed for the handshake to be built at all.
        let server_name = match datum.ip {
            Some(ip) => ip.to_string(),
            None => datum.host.clone(),
        };
        Ok(Prepared { addr, server_name })
    }

    /// This primitive could not start. See [`crate::module_error`] for why the
    /// distinction between a refusal and a setup failure is kept.
    fn refusal(&self, e: L7Error) -> ModuleError {
        crate::module_error(format!("L7 {}", self.cfg.kind.label()), e)
    }
}

struct Prepared {
    addr: SocketAddr,
    server_name: String,
}

/// The three outcomes a connection attempt can have — see the module docs.
#[derive(Default)]
struct Tally {
    /// Every attempt started, counted at spawn. Kept because QUIC gives a silent
    /// target no way to fail fast: a dropped Initial is indistinguishable from a
    /// slow one until the handshake times out, which is usually *after* the run
    /// ends. Without this, attempts still in flight at the deadline would be
    /// cancelled having tallied nothing, and a run that reached nothing at all
    /// would report `0 attempts, 0 failed` — a hollow success.
    attempted: AtomicU64,
    /// The handshake completed (and, for QUICLORIS, the stream was held).
    completed: AtomicU64,
    /// The peer answered in QUIC and declined — usually no `h3` ALPN.
    refused: AtomicU64,
    /// Nothing came back: no listener, dropped Initial, unusable path.
    errors: AtomicU64,
}

impl Tally {
    /// Attempts that were still in flight when the run ended. They completed
    /// nothing, so they are errors — see [`Tally::attempted`].
    fn unresolved(&self) -> u64 {
        self.attempted
            .load(Ordering::Relaxed)
            .saturating_sub(self.completed.load(Ordering::Relaxed))
            .saturating_sub(self.refused.load(Ordering::Relaxed))
            .saturating_sub(self.errors.load(Ordering::Relaxed))
    }
}

/// Build the QUIC client config: accept-any-cert TLS 1.3 with the `h3` ALPN, plus
/// a transport config that lets the *server* decide how long a connection lives.
fn client_config() -> Result<ClientConfig, L7Error> {
    let tls = crate::tls::tls13_client_config(vec![ALPN_H3.to_vec()])?;
    // `(*tls).clone()` rather than unwrapping the Arc: the config builder hands
    // back an Arc for the TCP engines that share one, and QUIC needs an owned copy.
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from((*tls).clone())
        .map_err(|e| L7Error::Client(format!("QUIC TLS config: {e}")))?;
    let mut cfg = ClientConfig::new(Arc::new(quic_tls));

    let mut transport = TransportConfig::default();
    let idle = quinn::IdleTimeout::try_from(MAX_IDLE)
        .map_err(|e| L7Error::Client(format!("QUIC idle timeout: {e}")))?;
    transport.max_idle_timeout(Some(idle));
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

/// Bind a local UDP socket of the target's address family. `:0` — the OS picks
/// the port and, with it, the source address. There is no way to ask for another
/// one, which is what keeps this a direct test rather than a reflector.
fn bind_addr_for(target: SocketAddr) -> SocketAddr {
    match target.ip() {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    }
}

impl StressModule for QuicEngine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        self.cfg.kind.label()
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        let Prepared { addr, server_name } = match self.prepare() {
            Ok(p) => p,
            Err(e) => return Err(self.refusal(e)),
        };
        let client_cfg = match client_config() {
            Ok(c) => c,
            Err(e) => return Err(self.refusal(e)),
        };

        let kind = self.cfg.kind;

        // Rate cap: min spacing between connection attempts. `None` => open nothing.
        let Some(interval) = plan.rate_cap.min_interval() else {
            return Ok(RunReport {
                layer_label: format!(
                    "L7 {} {} (rate cap 0 — opened nothing)",
                    kind.label(),
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
        let tick = self.cfg.tick.max(MIN_TICK);
        let max_conns = self.cfg.max_conns.max(1);
        let duration = plan.duration;
        let kill = plan.kill.clone();
        let server_name = Arc::new(server_name);

        // The endpoint is built inside the runtime: quinn's tokio driver needs a
        // reactor to register the UDP socket with. Setup failure here is a refusal,
        // not a run with zero results, so it is carried back out.
        let outcome: Result<bool, L7Error> = rt.block_on(async move {
            let mut endpoint = Endpoint::client(bind_addr_for(addr))
                .map_err(|e| L7Error::Client(format!("QUIC endpoint bind: {e}")))?;
            endpoint.set_default_client_config(client_cfg);

            let deadline = crate::deadline_in(duration);
            let mut opener = tokio::time::interval(interval);
            // Never exceed the cap: on a missed tick, delay rather than burst.
            opener.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut tasks: JoinSet<()> = JoinSet::new();
            let mut aborted = false;
            // QUICLORIS opens up to the ceiling once and then holds; the handshake
            // flood keeps opening for the whole run, bounded by what is in flight.
            let sem = (kind == QuicKind::Handshake)
                .then(|| Arc::new(tokio::sync::Semaphore::new(max_conns)));
            let mut opened = 0usize;

            loop {
                if kind == QuicKind::Quicloris && opened >= max_conns {
                    break;
                }
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

                // Reap finished attempts every tick: a `JoinSet` retains each
                // completed task's output until joined, so collecting only at the
                // end would grow our own memory with `rate × duration`.
                while tasks.try_join_next().is_some() {}

                // Saturated: skip this tick rather than pile on. The permit is held
                // for the whole attempt and released when the task ends. Only the
                // handshake flood needs it — QUICLORIS is bounded by `opened`.
                let permit = match &sem {
                    Some(sem) => match sem.clone().try_acquire_owned() {
                        Ok(p) => Some(p),
                        Err(_) => continue,
                    },
                    None => None,
                };

                opened += 1;
                tally_w.attempted.fetch_add(1, Ordering::Relaxed);
                let endpoint = endpoint.clone();
                let server_name = server_name.clone();
                let tally = tally_w.clone();
                let kill = kill.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    one_connection(&endpoint, addr, &server_name, kind, tick, deadline, kill, &tally)
                        .await;
                });
            }

            // QUICLORIS: the connections are open, now hold them to the deadline.
            if kind == QuicKind::Quicloris && !aborted {
                let remaining = deadline.saturating_duration_since(Instant::now());
                tokio::select! {
                    _ = tokio::time::sleep(remaining) => {}
                    _ = wait_for_kill(kill.clone()) => { aborted = true; }
                }
            }

            // Deadline or kill: stop in-flight work rather than waiting it out.
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            // Let the endpoint send CONNECTION_CLOSE for anything still open, so the
            // target reclaims state promptly instead of waiting out its idle timer.
            endpoint.close(0u32.into(), b"jinrai run complete");
            // Bounded: `wait_idle` waits out the QUIC draining period (three PTOs)
            // for every connection, which against a target that never answered is
            // several seconds of nothing — and a run that outlives its `--duration`
            // is a run whose window no longer means what the report says it does.
            let _ = tokio::time::timeout(CLOSE_GRACE, endpoint.wait_idle()).await;
            Ok(aborted)
        });

        let aborted = match outcome {
            Ok(a) => a,
            Err(e) => return Err(self.refusal(e)),
        };

        let completed = tally.completed.load(Ordering::Relaxed);
        let refused = tally.refused.load(Ordering::Relaxed);
        // An attempt still handshaking when the window closed reached nothing, so
        // it counts as an error like any other — see [`Tally::attempted`].
        let errors = tally.errors.load(Ordering::Relaxed) + tally.unresolved();

        let mut label = format!(
            "L7 {} {} ({} {}",
            kind.label(),
            self.url,
            completed,
            kind.success_noun(completed)
        );
        // Only mentioned when it happened, so a working endpoint reads as tersely
        // as the other engines'.
        if refused > 0 {
            label.push_str(&format!(", {refused} refused by the peer"));
        }
        label.push(')');

        Ok(RunReport {
            layer_label: label,
            units_sent: completed,
            // A refusal is a failed attempt, so it counts in the attempt arithmetic;
            // `detail` says which kind it was, because "the peer said no" and "the
            // peer never answered" are findings about entirely different things.
            errors: refused + errors,
            aborted_early: aborted,
            detail: (refused > 0).then(|| {
                format!(
                    "{refused} refused by the peer (QUIC answered and declined — \
                     usually the target does not offer the h3 ALPN, not a capacity limit)"
                )
            }),
            ..Default::default()
        })
    }
}

/// Open one QUIC connection and do whatever the primitive asks of it. Every
/// outcome lands in exactly one bucket of [`Tally`].
#[allow(clippy::too_many_arguments)]
async fn one_connection(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
    kind: QuicKind,
    tick: Duration,
    deadline: Instant,
    kill: KillSwitch,
    tally: &Tally,
) {
    let connecting = match endpoint.connect(addr, server_name) {
        Ok(c) => c,
        // A local build failure (bad server name, unusable address family) — never
        // an answer from the peer.
        Err(_) => {
            tally.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let conn = match connecting.await {
        Ok(conn) => conn,
        Err(e) => {
            if peer_answered(&e) {
                tally.refused.fetch_add(1, Ordering::Relaxed);
            } else {
                tally.errors.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    };

    match kind {
        // The handshake was the whole point: count it and drop the connection,
        // which sends CONNECTION_CLOSE on the way out.
        QuicKind::Handshake => {
            tally.completed.fetch_add(1, Ordering::Relaxed);
        }
        QuicKind::Quicloris => {
            match hold_unfinished_request(&conn, tick, deadline, kill, tally).await {
                Ok(()) => {}
                // The handshake worked and the streams did not: the peer is
                // speaking QUIC and refusing what we asked of it.
                Err(()) => {
                    tally.refused.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Whether a connection error means the peer sent us QUIC packets. The distinction
/// the report rests on: a declining peer is a different finding from a silent one.
fn peer_answered(e: &quinn::ConnectionError) -> bool {
    use quinn::ConnectionError::*;
    match e {
        // All four mean bytes came back from the far end.
        VersionMismatch | TransportError(_) | ConnectionClosed(_) | ApplicationClosed(_) => true,
        // A stateless reset is also the peer, even though it is refusing to talk.
        Reset => true,
        // Nothing arrived, or we gave up locally.
        TimedOut | LocallyClosed | CidsExhausted => false,
    }
}

/// HTTP/3 unidirectional stream type for the control stream (RFC 9114 §6.2.1).
const H3_STREAM_TYPE_CONTROL: u8 = 0x00;
/// HTTP/3 `SETTINGS` frame type (RFC 9114 §7.2.4).
const H3_FRAME_SETTINGS: u8 = 0x04;
/// HTTP/3 `HEADERS` frame type (RFC 9114 §7.2.2).
const H3_FRAME_HEADERS: u8 = 0x01;

/// Declared payload length of the `HEADERS` frame that never arrives.
///
/// Large enough that a byte-per-tick dribble cannot finish it inside any sane
/// run, small enough to stay under the field-section limits servers actually
/// advertise — a frame the server rejects outright as too large would be closed
/// immediately and hold nothing.
const HEADERS_DECLARED_LEN: u64 = 4096;

/// One byte of QPACK that is legal to receive and cheap to repeat: an Indexed
/// Field Line referencing static-table entry 0 (RFC 9204 §4.5.2). It is only ever
/// *decoded* once the whole field section has arrived, which is precisely what is
/// being prevented — so the dribble stays syntactically defensible without ever
/// forming a request.
const QPACK_DRIBBLE_BYTE: u8 = 0xC0;

/// Encode a QUIC variable-length integer (RFC 9000 §16).
fn varint(v: u64) -> Vec<u8> {
    match v {
        0..=63 => vec![v as u8],
        64..=16_383 => {
            let x = (v as u16) | 0x4000;
            x.to_be_bytes().to_vec()
        }
        16_384..=1_073_741_823 => {
            let x = (v as u32) | 0x8000_0000;
            x.to_be_bytes().to_vec()
        }
        _ => {
            let x = v | 0xC000_0000_0000_0000;
            x.to_be_bytes().to_vec()
        }
    }
}

/// The opening bytes of the request stream: a `HEADERS` frame header promising
/// [`HEADERS_DECLARED_LEN`] bytes, then the two-byte QPACK field-section prefix
/// (Required Insert Count 0, Delta Base 0 — no dynamic-table dependency, so the
/// server has nothing to block on and simply waits for the rest).
fn request_stream_prologue() -> Vec<u8> {
    let mut out = vec![H3_FRAME_HEADERS];
    out.extend_from_slice(&varint(HEADERS_DECLARED_LEN));
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

/// The client control stream: stream type, then an empty `SETTINGS` frame.
///
/// RFC 9114 requires it before anything else on a connection, and a server that
/// enforces that would close a connection whose first frame was a request. Sending
/// it is what makes this a slow *HTTP/3 client* rather than a malformed one — the
/// point of QUICLORIS is to be indistinguishable from a legitimate peer on a bad
/// network.
fn control_stream_bytes() -> Vec<u8> {
    vec![H3_STREAM_TYPE_CONTROL, H3_FRAME_SETTINGS, 0x00]
}

/// Establish a well-formed HTTP/3 client on `conn`, open a request stream, and
/// dribble its never-ending `HEADERS` frame until the deadline or the kill switch.
/// `Err(())` means the peer refused the streams — the connection came up but would
/// not carry a request.
async fn hold_unfinished_request(
    conn: &quinn::Connection,
    tick: Duration,
    deadline: Instant,
    kill: KillSwitch,
    tally: &Tally,
) -> Result<(), ()> {
    // Control stream first, and held open for the connection's life: closing it is
    // an HTTP/3 error, which would get the whole connection torn down.
    let mut control = conn.open_uni().await.map_err(|_| ())?;
    control.write_all(&control_stream_bytes()).await.map_err(|_| ())?;

    let (mut send, _recv) = conn.open_bi().await.map_err(|_| ())?;
    send.write_all(&request_stream_prologue()).await.map_err(|_| ())?;

    // Counted here, not when the dribble ends: the connection is being held from
    // this point on, and a run stopped by the kill switch held it just as much as
    // one that ran to its deadline. Tallying at the end would report zero for
    // every aborted run — and the dribble loop is cancelled at the deadline, so it
    // would race even on a clean one.
    tally.completed.fetch_add(1, Ordering::Relaxed);

    let mut ticker = tokio::time::interval(tick);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = wait_for_kill(kill.clone()) => break,
        }
        if kill.is_tripped() || Instant::now() >= deadline {
            break;
        }
        // A write failure means the peer closed the stream or the connection —
        // it held for a while, which is the measurement, so stop rather than
        // reclassify the whole attempt.
        if send.write_all(&[QPACK_DRIBBLE_BYTE]).await.is_err() {
            break;
        }
    }
    // Deliberately never `finish()`: an unfinished stream is the entire primitive.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jinrai_core::RateCap;
    use jinrai_safety::{Allowlist, KillSwitch};

    fn gate_cidrs(cidrs: &[&str]) -> Authorization {
        Authorization::new(Allowlist::from_cidrs(cidrs).unwrap(), KillSwitch::new())
    }

    fn engine(kind: QuicKind, allow: &[&str], url: &str) -> QuicEngine {
        QuicEngine::new(
            gate_cidrs(allow),
            url,
            QuicConfig { kind, max_conns: 4, tick: Duration::from_millis(10) },
        )
    }

    #[test]
    fn authorizes_https_datum() {
        let e = engine(QuicKind::Handshake, &["127.0.0.0/8"], "https://127.0.0.1:9/");
        assert!(e.authorize_target().is_ok());
    }

    #[test]
    fn unauthorized_target_refused() {
        let e = engine(QuicKind::Handshake, &["10.0.0.0/8"], "https://127.0.0.1:9/");
        assert!(e.authorize_target().is_err());
    }

    #[test]
    fn names_and_layer() {
        for (kind, name) in
            [(QuicKind::Handshake, "l7-quic-handshake"), (QuicKind::Quicloris, "l7-quicloris")]
        {
            let e = engine(kind, &["127.0.0.0/8"], "https://127.0.0.1:9/");
            assert_eq!(e.name(), name);
            assert_eq!(e.layer(), Layer::L7);
        }
    }

    #[test]
    fn http_url_refused_no_plaintext_quic() {
        for kind in [QuicKind::Handshake, QuicKind::Quicloris] {
            let mut e = engine(kind, &["127.0.0.0/8"], "http://127.0.0.1:9/");
            let plan = RunPlan {
                targets: e.authorize_target().unwrap(),
                rate_cap: RateCap::new(50),
                duration: Duration::from_millis(100),
                kill: KillSwitch::new(),
            };
            match e.execute(&plan) {
                Err(ModuleError::Refused(msg)) => {
                    assert!(msg.contains("needs https"), "got: {msg}")
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn rate_cap_zero_opens_nothing() {
        let mut e = engine(QuicKind::Handshake, &["127.0.0.0/8"], "https://127.0.0.1:9/");
        let plan = RunPlan {
            targets: e.authorize_target().unwrap(),
            rate_cap: RateCap::new(0),
            duration: Duration::from_millis(50),
            kill: KillSwitch::new(),
        };
        let report = e.execute(&plan).expect("the run should execute");
        assert_eq!(report.units_sent, 0);
        assert!(!report.aborted_early);
        assert!(report.layer_label.contains("opened nothing"));
    }

    /// Nothing listens on UDP/9 on loopback, so every attempt must land in
    /// `errors` — never in `refused`, which would claim a peer answered.
    ///
    /// The `errors > 0` half is the regression guard that matters: QUIC gives a
    /// silent target no way to fail fast, so every attempt is still handshaking
    /// when the window closes. Counting only *resolved* attempts reported this run
    /// as `0 attempts, 0 failed` — a target that was never reached reading as a
    /// clean sweep.
    #[test]
    fn silent_target_counts_as_error_not_refusal() {
        let mut e = engine(QuicKind::Handshake, &["127.0.0.0/8"], "https://127.0.0.1:9/");
        let plan = RunPlan {
            targets: e.authorize_target().unwrap(),
            rate_cap: RateCap::new(20),
            duration: Duration::from_millis(300),
            kill: KillSwitch::new(),
        };
        let report = e.execute(&plan).expect("the run should execute");
        assert_eq!(report.units_sent, 0, "nothing can complete against a dead port");
        assert!(report.errors > 0, "every attempt must be accounted for: {report:?}");
        assert!(report.detail.is_none(), "a silent target is not a refusal: {report:?}");
    }

    /// A run must not outlive its window. QUIC's draining period is three PTOs per
    /// connection, so waiting for a silent target's connections to close added
    /// seconds to a two-second run — and an elapsed time that does not match the
    /// planned one makes every rate in the report a different number than it says.
    #[test]
    fn run_does_not_outlive_its_window_against_a_silent_target() {
        let mut e = engine(QuicKind::Handshake, &["127.0.0.0/8"], "https://127.0.0.1:9/");
        let plan = RunPlan {
            targets: e.authorize_target().unwrap(),
            rate_cap: RateCap::new(40),
            duration: Duration::from_millis(400),
            kill: KillSwitch::new(),
        };
        let started = Instant::now();
        let report = e.execute(&plan).expect("the run should execute");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(400) + CLOSE_GRACE + Duration::from_millis(500),
            "run overshot its window by too much: {elapsed:?} ({report:?})"
        );
    }

    /// The kill switch must stop a run well inside its duration.
    #[test]
    fn kill_switch_aborts_promptly() {
        let mut e = engine(QuicKind::Quicloris, &["127.0.0.0/8"], "https://127.0.0.1:9/");
        let kill = KillSwitch::new();
        let plan = RunPlan {
            targets: e.authorize_target().unwrap(),
            rate_cap: RateCap::new(50),
            duration: Duration::from_secs(30),
            kill: kill.clone(),
        };
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            kill.trip();
        });
        let started = Instant::now();
        let report = e.execute(&plan).expect("the run should execute");
        assert!(report.aborted_early, "the kill switch must be reported");
        assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
    }

    #[test]
    fn varint_matches_rfc9000_boundaries() {
        // One byte below/at/above each of the three encodable boundaries.
        assert_eq!(varint(0), vec![0x00]);
        assert_eq!(varint(63), vec![0x3F]);
        assert_eq!(varint(64), vec![0x40, 0x40]);
        assert_eq!(varint(16_383), vec![0x7F, 0xFF]);
        assert_eq!(varint(16_384), vec![0x80, 0x00, 0x40, 0x00]);
        assert_eq!(varint(1_073_741_823), vec![0xBF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(varint(1_073_741_824), vec![0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
        // The two-bit prefix is what a decoder reads first; every form must carry
        // the right one or the peer mis-frames everything after it.
        for (v, prefix) in [(1u64, 0b00), (100, 0b01), (100_000, 0b10), (2u64.pow(31), 0b11)] {
            assert_eq!(varint(v)[0] >> 6, prefix, "wrong varint form for {v}");
        }
    }

    #[test]
    fn request_prologue_is_a_headers_frame_that_never_completes() {
        let p = request_stream_prologue();
        assert_eq!(p[0], H3_FRAME_HEADERS);
        // 4096 fits the 2-byte varint form: 0x4000 | 4096.
        assert_eq!(&p[1..3], &[0x50, 0x00]);
        // QPACK prefix: no dynamic-table dependency, so the server waits for bytes
        // rather than blocking on an encoder stream that will never send.
        assert_eq!(&p[3..], &[0x00, 0x00]);
        // The declared length is what the whole primitive rests on: the prologue
        // must promise far more than a byte-per-tick dribble can ever deliver.
        assert_eq!(HEADERS_DECLARED_LEN, 4096);
    }

    #[test]
    fn control_stream_announces_an_http3_client() {
        assert_eq!(control_stream_bytes(), vec![0x00, 0x04, 0x00]);
    }

    #[test]
    fn bind_address_matches_the_target_family() {
        let v4: SocketAddr = "10.1.2.3:443".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert!(bind_addr_for(v4).is_ipv4());
        assert!(bind_addr_for(v6).is_ipv6());
        // Port 0 in both: the OS picks the source, and nothing here can ask for
        // another one. That is the no-spoofing guarantee, as a test.
        assert_eq!(bind_addr_for(v4).port(), 0);
        assert_eq!(bind_addr_for(v6).port(), 0);
        assert!(bind_addr_for(v4).ip().is_unspecified());
        assert!(bind_addr_for(v6).ip().is_unspecified());
    }

    #[test]
    fn quic_client_config_builds_with_h3_alpn() {
        assert!(client_config().is_ok(), "the QUIC client config must build");
    }

    /// Every peer-side error must read as an answer, every local one as silence.
    /// Getting this backwards would report an unreachable target as a refusal.
    #[test]
    fn answered_and_silent_errors_are_told_apart() {
        assert!(peer_answered(&quinn::ConnectionError::VersionMismatch));
        assert!(peer_answered(&quinn::ConnectionError::Reset));
        assert!(!peer_answered(&quinn::ConnectionError::TimedOut));
        assert!(!peer_answered(&quinn::ConnectionError::LocallyClosed));
        assert!(!peer_answered(&quinn::ConnectionError::CidsExhausted));
    }

    // ---- against a real QUIC listener -------------------------------------
    //
    // The byte-level tests above prove jinrai *builds* the right HTTP/3 frames.
    // These prove the frames survive a real handshake and arrive at a server that
    // decoded them — which for QUIC cannot be checked any other way, since no
    // stream byte exists before the handshake completes.

    /// A QUIC listener with a self-signed cert, offering `alpn`. Returns its
    /// address and the endpoint (dropping the endpoint stops the server).
    fn test_server(alpn: &[&[u8]]) -> (SocketAddr, Endpoint) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let cert_der = tokio_rustls::rustls::pki_types::CertificateDer::from(cert.cert);
        let key_der = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(
            cert.key_pair.serialize_der(),
        )
        .expect("key der");

        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let mut sc = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
            .expect("tls13 server config")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server cert");
        sc.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();

        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(sc).expect("quic server config");
        let endpoint = Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(qsc)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .expect("bind quic server");
        (endpoint.local_addr().expect("local addr"), endpoint)
    }

    /// Read a stream until it ends, appending everything into `sink`. Returns
    /// `true` if the peer **finished** the stream — the one thing QUICLORIS must
    /// never do — and `false` if it was reset or the connection went away.
    async fn drain_into(mut recv: quinn::RecvStream, sink: Arc<tokio::sync::Mutex<Vec<u8>>>) -> bool {
        let mut buf = [0u8; 256];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => sink.lock().await.extend_from_slice(&buf[..n]),
                Ok(None) => return true,
                Err(_) => return false,
            }
        }
    }

    fn plan_for(e: &QuicEngine, rate: u64, ms: u64) -> RunPlan {
        RunPlan {
            targets: e.authorize_target().unwrap(),
            rate_cap: RateCap::new(rate),
            duration: Duration::from_millis(ms),
            kill: KillSwitch::new(),
        }
    }

    /// The handshake flood against a listener that speaks h3: handshakes must
    /// actually complete. This is the one test that proves the primitive does the
    /// thing it claims — everything else only proves it fails cleanly.
    #[test]
    fn handshake_flood_completes_against_a_real_quic_listener() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let (addr, server) = test_server(&[ALPN_H3]);
        // Accept and immediately drop: the server-side work under test is the
        // handshake, which is already done by the time `accept` yields.
        rt.spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    let _ = incoming.await;
                });
            }
        });

        let mut e = engine(QuicKind::Handshake, &["127.0.0.0/8"], &format!("https://{addr}/"));
        let report = e.execute(&plan_for(&e, 50, 600)).expect("the run should execute");
        assert!(report.units_sent > 0, "no handshake completed: {report:?}");
        assert_eq!(report.errors, 0, "a live listener should produce no errors: {report:?}");
        assert!(report.detail.is_none(), "nothing was refused: {report:?}");
    }

    /// A listener that speaks QUIC but not `h3` must land in `refused`, not
    /// `errors`: "the target has no HTTP/3" and "the target is unreachable" are
    /// the two findings the report exists to keep apart.
    #[test]
    fn alpn_mismatch_is_reported_as_refused_not_unreachable() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let (addr, server) = test_server(&[b"hq-interop"]);
        rt.spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    let _ = incoming.await;
                });
            }
        });

        let mut e = engine(QuicKind::Handshake, &["127.0.0.0/8"], &format!("https://{addr}/"));
        let report = e.execute(&plan_for(&e, 30, 500)).expect("the run should execute");
        assert_eq!(report.units_sent, 0, "no h3 means no completed handshake: {report:?}");
        assert!(report.errors > 0, "the attempts must be counted: {report:?}");
        let detail = report.detail.as_deref().unwrap_or_default();
        assert!(detail.contains("refused by the peer"), "got detail: {detail:?}");
        assert!(detail.contains("h3"), "the detail must name the likely cause: {detail:?}");
    }

    /// QUICLORIS end to end: the server must receive a well-formed HTTP/3 control
    /// stream, then a request stream carrying a HEADERS frame that promises far
    /// more than it delivers — and still be waiting when the run ends.
    #[test]
    fn quicloris_sends_http3_that_never_completes_its_request() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let (addr, server) = test_server(&[ALPN_H3]);

        let control = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
        let request = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
        let finished = Arc::new(AtomicU64::new(0));
        let (control_w, request_w, finished_w) =
            (control.clone(), request.clone(), finished.clone());

        rt.spawn(async move {
            while let Some(incoming) = server.accept().await {
                let (control, request, finished) =
                    (control_w.clone(), request_w.clone(), finished_w.clone());
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    // The client's uni control stream.
                    let c = conn.clone();
                    let control_task = tokio::spawn(async move {
                        if let Ok(uni) = c.accept_uni().await {
                            drain_into(uni, control).await;
                        }
                    });
                    // The request stream. `read` yields `Ok(None)` only when the
                    // peer FINISHES the stream — which QUICLORIS never does, so
                    // that arm firing at all would be the primitive failing.
                    if let Ok((_send, recv)) = conn.accept_bi().await {
                        if drain_into(recv, request).await {
                            finished.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    let _ = control_task.await;
                });
            }
        });

        let mut e = QuicEngine::new(
            gate_cidrs(&["127.0.0.0/8"]),
            format!("https://{addr}/"),
            QuicConfig {
                // One connection, so the captured buffers belong to exactly one
                // stream and can be compared byte for byte.
                kind: QuicKind::Quicloris,
                max_conns: 1,
                tick: Duration::from_millis(20),
            },
        );
        let report = e.execute(&plan_for(&e, 50, 800)).expect("the run should execute");
        assert!(report.units_sent > 0, "no connection was held: {report:?}");

        let control = rt.block_on(control.lock()).clone();
        let request = rt.block_on(request.lock()).clone();
        assert_eq!(
            control,
            control_stream_bytes(),
            "the server must see a real HTTP/3 control stream with SETTINGS"
        );
        let prologue = request_stream_prologue();
        assert!(
            request.starts_with(&prologue),
            "the request stream must open with the HEADERS frame: {request:02x?}"
        );
        // The dribble is running: more arrived than the prologue alone.
        assert!(
            request.len() > prologue.len(),
            "the dribble should have added bytes: {request:02x?}"
        );
        // And the promise is still unmet — this is the whole primitive.
        assert!(
            (request.len() as u64) < HEADERS_DECLARED_LEN,
            "the HEADERS frame must stay unfinished, got {} bytes",
            request.len()
        );
        assert_eq!(
            finished.load(Ordering::Relaxed),
            0,
            "the request stream must never be finished"
        );
    }
}

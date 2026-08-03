//! jinrai CLI — the operator entry point.
//!
//! Wires the safety gate to the traffic modules end-to-end. **This emits real
//! traffic**; every step below exists to make sure it only ever goes where the
//! operator said it could:
//!   1. Refuse a run with no audit trail (`--audit-log`, or `--no-audit` to say
//!      so out loud) and no lab acknowledgement (`--ack-lab`).
//!   2. Parse the operator-supplied allowlist (`--allow <CIDR|name>`, repeatable).
//!   3. Parse targets (`--target <IP>`, or the `--url` datum for l7).
//!   4. Authorize every target through the gate — refuse the whole run if any
//!      target is not allowlisted (fail-closed).
//!   5. Install the kill switch on SIGINT/SIGTERM, refusing to start if it could
//!      not be installed — a run that cannot be stopped is not started.
//!   6. Build a `RunPlan` and hand it to the selected module, which generates
//!      the load. `--dry-run` stops exactly here, after everything refusable has
//!      been done and before anything is sent.

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

use jinrai_core::{
    Layer, LoadProfile, ModuleError, RateCap, RunPlan, RunReport, SloSpec, SloVerdict,
    StressModule,
};
use jinrai_l34::{L34Config, L34Engine, L4Mode, PortOrder, PortSet};
use jinrai_l7::{
    H2ContinuationEngine, H2FrameFloodEngine, H2FrameKind, H2RapidResetEngine, H2StreamFloodEngine,
    H2StreamKind, HttpVersion, L7Engine, L7Method, L7SlowEngine, LongLivedConfig, LongLivedEngine,
    LongLivedKind, RequestSpec, SlowConfig, SlowMode, TlsHandshakeEngine, TlsHelloEngine,
    TlsHelloKind, WatchdogConfig,
};
use jinrai_metrics::{AuditEvent, AuditLog, RunContext};
use jinrai_safety::{Allowlist, AuthorizedTarget, Authorization, KillSwitch};

const USAGE: &str = "\
jinrai — internal network resilience tester

USAGE:
    jinrai --allow <RULE> [--allow <RULE> ...] (--url <URL> | --target <IP> ...) [OPTIONS]

REQUIRED:
    --allow <RULE>     Authorized rule (repeatable). Either an IP/CIDR
                       (e.g. 10.0.0.0/8, 127.0.0.1) OR a DNS pattern
                       (e.g. api.staging.internal, *.staging.internal).
                       No default: an empty allowlist authorizes nothing.

    For --layer l7:
    --url <URL>        Target URL. The URL host is validated as a DATUM against
                       its own rule type: an IP-literal host against the CIDR
                       rules, a DNS-name host against the DNS rules. A name is
                       NOT resolved-then-IP-checked. No match => refused.

    For --layer l3/l4:
    --target <IP>      Target address (repeatable). Must match an IP/CIDR --allow.
                       Several targets in one run is the carpet-bombing shape:
                       the load is spread over all of them, so no single
                       destination address carries the whole run.
    --port <SPEC>      Target port(s) (required for l3/l4, except --l4-mode icmp).
                       A single port (443), a comma list (80,443,8080), an
                       inclusive range (1000-2000), or a mix (80,8000-8100).
                       Port 0 is refused. A range is how the random-port and
                       carpet-bombing shapes are driven: most of it has no
                       listener, so the target must generate a refusal (RST /
                       ICMP port-unreachable) and track a flow per port.

REQUIRED FOR ANY RUN THAT EMITS TRAFFIC:
    --ack-lab          Acknowledgement that this run targets an authorized,
                       isolated-lab system. Every layer, not just l3/l4 — an l7
                       run needs no privileges and is the easiest to fire by
                       accident. (--ack-l34-lab is the old spelling, still
                       accepted.) Not needed with --dry-run.
    --audit-log <PATH> Append-only, hash-chained record of this run. A run with
                       neither this nor --no-audit is refused: the trail is only
                       worth something if it cannot be quietly skipped.
    --no-audit         Run without a trail, deliberately. Says on the command
                       line what omitting --audit-log used to say silently.
    --dry-run          Validate, authorize, print the plan — send nothing. Does
                       the whole refusable path (allowlist, gate, preflight), so
                       what it prints is the run that was about to happen. Exempt
                       from --ack-lab and the audit requirement.

OPTIONS:
    --layer <l3|l4|l7>    Module to run (default: l7). l3 and l4 are the same
                          module — the ICMP modes report as L3, the rest as L4 —
                          so either spelling selects it.
    --l4-mode <MODE>      L3/L4 primitive (default: udp). One of:
                            udp | tcp | data     no privilege needed (data =
                                                 PSH-ACK data flood: real OS
                                                 connections filled with app data;
                                                 --payload-size sets the write size)
                            syn | ack | fin | rst | urg | cwr | ece
                                                 raw TCP flag floods; each sets one
                                                 flag, needs CAP_NET_RAW/root,
                                                 IPv4-only, real source IP (never
                                                 spoofed). urg/cwr/ece send an
                                                 otherwise-empty segment carrying
                                                 only that (rarely-standalone) bit
                            syn-ack              raw unsolicited SYN-ACK flood: a
                                                 legal handshake *response* to a SYN
                                                 the target never sent, so each one
                                                 must be matched against connection
                                                 state or answered with an RST
                            syn-fin | syn-rst | xmas | null
                                                 raw TCP anomalous-flag floods:
                                                 syn-fin/syn-rst set contradictory
                                                 combos, xmas sets FIN+PSH+URG, null
                                                 sets no flags — probe stateful
                                                 firewall / IDS / TCP-stack handling
                                                 of illegal control fields (same
                                                 raw-socket / no-spoof constraints)
                            tcp-options          raw SYN flood carrying the maximal
                                                 40-byte TCP option block (MSS +
                                                 SACK + timestamp + window scale,
                                                 NOP-padded) — stresses the target's
                                                 option parser / SACK+timestamp
                                                 state (same raw-socket constraints)
                            icmp | icmp-timestamp | icmp-address-mask
                                                 L3 ICMPv4 query floods (echo type 8,
                                                 timestamp type 13, address-mask
                                                 type 17) — each forces the target to
                                                 answer directly; needs CAP_NET_RAW/
                                                 root, IPv4-only, real source IP (never
                                                 spoofed), no --port needed
    --l7-method <METHOD>  L7 primitive (default: get). One of:
                            get | post | head   fast request flood
                            slowloris            slow partial headers (Slowloris)
                            slowbody             slow trickled POST body (RUDY)
                            slow-read            complete request, then drain the
                                                 response one small chunk per tick
                                                 with a shrunken receive window so
                                                 the server cannot flush it (the
                                                 read-side mirror of slowbody)
                            h2-rapid-reset       HTTP/2 rapid-reset (CVE-2023-44487):
                                                 open a stream, immediately
                                                 RST_STREAM; rate cap = resets/sec
                            h2-continuation      HTTP/2 CONTINUATION flood
                                                 (CVE-2024-27316): HEADERS without
                                                 END_HEADERS + endless CONTINUATION
                                                 frames; rate cap = frames/sec
                            tls-handshake        TLS handshake flood (THC-SSL-DoS):
                                                 full handshake then drop, repeat;
                                                 https-only; rate cap = handshakes/sec
                            tls-big-hello        TLS ClientHello parser stress: one
                                                 well-formed hello inflated to the
                                                 16 KiB record ceiling (2048-entry
                                                 cipher list the server must
                                                 intersect + RFC 7685 padding), no
                                                 handshake completed
                            tls-sni-bomb         the same, isolating the SNI: a
                                                 12 KiB server_name of legal DNS
                                                 labels, so it survives syntax
                                                 checks and reaches the vhost
                                                 lookup. Both are https-only, rate
                                                 cap = hellos/sec, and report the
                                                 answer split (parsed / alerted /
                                                 silent) — an alert is the HEALTHY
                                                 result: the parser refused
                            h2-settings          HTTP/2 SETTINGS flood
                                                 (CVE-2019-9515): empty SETTINGS
                                                 frames the server must ACK
                            h2-ping              HTTP/2 PING flood (CVE-2019-9512):
                                                 PING frames the server must PONG
                            h2-window-update     HTTP/2 WINDOW_UPDATE flood
                                                 (CVE-2019-9514): connection-level
                                                 flow-control updates on stream 0
                            h2-priority          HTTP/2 PRIORITY flood
                                                 (CVE-2019-9513, Resource Loop):
                                                 frames that reshuffle the priority
                                                 tree; all four rate cap = frames/sec
                            h2-made-you-reset    HTTP/2 MadeYouReset (CVE-2025-8671):
                                                 complete request then a 0-increment
                                                 WINDOW_UPDATE so the SERVER resets
                                                 the stream (evades rapid-reset
                                                 mitigations); rate cap = cycles/sec
                            h2-empty-data        HTTP/2 empty-DATA flood
                                                 (CVE-2019-9518): open a stream, then
                                                 flood 0-length DATA frames without
                                                 END_STREAM; rate cap = frames/sec
                            h2-bomb              HTTP/2 Bomb (CVE-2026-49975): HPACK
                                                 1-byte-reference header amplification
                                                 + zero initial window so the
                                                 amplified memory stays pinned; rate
                                                 cap = bomb frames/sec
                            websocket            WebSocket connection exhaustion: do
                                                 the RFC 6455 upgrade properly, then
                                                 hold the session with an empty Ping
                                                 every --drip-ms. Nothing is slow or
                                                 malformed, so no header/body read
                                                 timeout retires it — this measures
                                                 the concurrent-session ceiling
                            sse                  Server-Sent-Events connection
                                                 exhaustion: a normal
                                                 Accept: text/event-stream GET, held
                                                 open (the server keeps it open by
                                                 design) and drained
                          websocket/sse take http(s) URLs, not ws(s): the handshake
                          IS an HTTP/1.1 request, so use https:// for wss. Both use
                          --slow-connections as the concurrent ceiling and --drip-ms
                          as the keep-alive tick, and the run summary separates a
                          server DECLINING the transport (wrong path / not supported)
                          from a connection that never got an answer.
                          For slow modes the rate cap is connections-opened/sec,
                          and https targets are supported (slow-TLS; the handshake
                          accepts any server certificate — see README). h2-rapid-reset
                          and h2-continuation use ALPN h2 for https and
                          prior-knowledge h2c for http.
    --http-version <V>    HTTP version for the fast get/post/head flood:
                            auto  (default) negotiate: HTTP/1.1 for http://,
                                  ALPN for https:// — which means an https target
                                  that offers h2 IS TESTED OVER HTTP/2
                            1.1   force HTTP/1.1, never negotiate h2
                            2     force HTTP/2 (ALPN h2 only for https,
                                  prior-knowledge h2c for http). A target that
                                  cannot do h2 fails every request instead of
                                  silently downgrading
                          Whatever is chosen, the run summary reports the version
                          the responses actually came back on. Slow modes are
                          HTTP/1.1 by construction and the h2-* methods are HTTP/2
                          by construction, so this flag does not apply to them.
    --body <STRING>       Request body sent with each POST (l7-method post)
    --cache-bust          Append a unique _cb=<n> query to every l7 request so
                          caches/CDNs cannot serve a stored response (query only;
                          the host is never altered)
    --max-connections <N> Cap concurrent in-flight requests (~concurrent keep-alive
                          connections) for the fast get/post/head flood and the
                          one-connection-per-unit TLS methods (tls-handshake,
                          tls-big-hello, tls-sni-bomb) (default: 1024). Pins the load to at
                          most N connections held busy — the controlled form of
                          keep-alive connection exhaustion (probe a server's
                          connection-slot / worker limit); --rate still caps the
                          request rate on top. --rate does NOT bound concurrency
                          by itself: against a target that answers slowly, rate x
                          latency is the socket count, so this is what keeps a run
                          from becoming a descriptor self-test on YOUR box. 0
                          means unbounded — an explicit choice, never the default
    --request-timeout-ms <MS>  How long one l7 request may stay unresolved before
                          it is abandoned and counted in the `timeout` errno
                          bucket (default: 10000). Applies to the fast
                          get/post/head flood.
    --drain-timeout-ms <MS>  How long to wait for still-in-flight l7 requests once
                          --duration expires, before cancelling them (default:
                          1000). --duration bounds the TRAFFIC, not just the
                          dispatching of it: without this bound a run's real
                          window would be --duration plus the request timeout.
                          Requests cancelled here are counted in the `abandoned`
                          errno bucket, never silently dropped. 0 = cancel at the
                          deadline itself.
    --slow-connections <N>  Concurrent connection ceiling for the slow modes and
                          for websocket/sse (default: 100)
    --drip-ms <MS>        Per-tick interval for the connection-holding l7 methods
                          (default: 10000): the keep-alive write interval for
                          slowloris/slowbody, the read interval draining one chunk
                          for slow-read, or the Ping interval for websocket
    --concurrency <N>     Max SIMULTANEOUSLY OPEN sockets for the connection-
                          holding l4 modes (tcp, data) (default: 256). This is the
                          run's local footprint, and it is independent of
                          --duration: --rate is the offered load (attempts/sec),
                          --concurrency is how many connections are held at once,
                          --duration is only wall-clock length. Once N are open,
                          admitting a new attempt closes the oldest connection.
                          For l4-mode tcp the count covers sockets mid-handshake
                          too, so N is also how many handshakes run in parallel
                          (capped at 4096 threads): the reachable rate is about
                          N / mean-attempt-time. That mean is NOT the round-trip:
                          an attempt that times out holds its slot for the whole
                          --connect-timeout-ms, so once a meaningful share of
                          attempts fail, lowering that timeout raises the
                          reachable rate far more than raising N does. When a run
                          falls short of the --rate cap, the summary's `bound by`
                          line says which of the two to reach for.
    --connect-timeout-ms <MS>  How long one l4 connection attempt may stay
                          unresolved before it is abandoned and counted in the
                          `timeout` errno bucket (default: 500)
    --port-order <ORD>    How an l3/l4 run walks a multi-port --port spec:
                            sequential  (default) in the order written, advancing
                                        once per pass over the targets, so the
                                        run enumerates the whole target x port
                                        cross-product. Deterministic; identical
                                        to previous releases for a single port
                            random      draw a port per packet. This is what a
                                        test plan means by 'random ports':
                                        consecutive packets are unrelated, so a
                                        rule keyed on one port sees a trickle
                                        rather than the run
                          Only the DESTINATION port varies. The source address is
                          never spoofed and the source port stays deterministic —
                          see the no-spoofing guardrail in the README.
    --payload-size <N>    Payload bytes per unit (default: 64) — UDP datagram size
                          (l4-mode udp) or PSH-ACK write size (l4-mode data)
    --rate <N>            Rate cap, units/sec (default: 100, max 10000000). This
                          is a hard SAFETY CEILING: every load profile shapes
                          traffic only UP TO this rate, never above it.
    --duration <SECS>     Run duration (default: 10, max 86400)
    --header <K: V>       Extra request header for l7 (repeatable). Also the hook
                          for header-profile tests (User-Agent, Cookie, Referer…)

    Load profiles (l7 fast methods; --rate is the peak/ceiling for every shape):
    --profile <SHAPE>     constant  flat at the ceiling (default)
                          soak      long flat hold — set a long --duration
                          ramp      step up from --ramp-start to the ceiling
                          spike     hold --spike-base, jump to the ceiling, fall
    --ramp-start <N>      Ramp starting rate, units/sec (default: 0)
    --ramp-steps <N>      Number of equal-length ramp stages (default: 10)
    --spike-base <N>      Spike baseline rate (default: ceiling/5)
    --spike-secs <SECS>   Spike peak duration (default: 10). Carved OUT of
                          --duration, never added to it: the baseline fills the
                          rest of the window.
    --discover-knee       Breaking-point discovery: ramp to the ceiling and stop
                          at the first stage that breaches the SLO, reporting the
                          capacity knee. Requires a --slo-max-*-rate to detect the
                          knee. Finding the knee is a success (exit 0).

    SLO / health-watchdog (l7 fast methods; classifies each response):
    --slo-max-error-rate <F>  FAIL if transport-error rate exceeds F (0.0–1.0)
    --slo-max-5xx-rate <F>    FAIL if 5xx-response rate exceeds F
    --slo-max-4xx-rate <F>    FAIL if 4xx-response rate exceeds F (off by default)
    --slo-max-p99-ms <MS>     FAIL if end-of-run p99 latency exceeds MS
                          A run that misses any declared SLO exits non-zero.
    --watchdog                Auto-abort the run when a rate SLO is breached for
                          several consecutive windows (only STOPS traffic). Needs
                          at least one --slo-max-*-rate to have something to watch.
    --watchdog-window <SECS>  Watchdog sample window (default: 5)
    --watchdog-breaches <K>   Consecutive breaching windows before abort (default: 3)
    --output <FORM>       End-of-run report form:
                            human  (default) a readable block: offered vs.
                                   achieved load, status/protocol breakdown with
                                   percentages, who ended the run, and what the
                                   failures mean
                            line   the single machine-friendly summary line
                                   (stable for scripts/log scraping)
    --audit-log <PATH>    Append a tamper-evident audit record for this run to
                          PATH (authorized/completed/refused). Operator identity
                          comes from $JINRAI_OPERATOR (else the OS user).
    -h, --help            Show this help

AUDIT:
    --verify-audit <PATH> Verify the hash chain of an existing audit log and print
                          every record in readable form, then exit (0 = intact,
                          non-zero = tampered/corrupt). Runs nothing.
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// The selected L7 primitive: either a fast request-flood method (reqwest-based)
/// or a slow-connection primitive (raw TCP, connection-holding).
#[derive(Debug, Clone, Copy)]
enum L7Kind {
    Fast(L7Method),
    Slow(SlowMode),
    /// HTTP/2 rapid-reset (open stream, immediate RST_STREAM).
    RapidReset,
    /// HTTP/2 CONTINUATION flood (HEADERS + endless CONTINUATION, never END_HEADERS).
    Continuation,
    /// TLS handshake flood (THC-SSL-DoS: full handshake, immediate drop, repeat).
    TlsHandshake,
    /// HTTP/2 control-frame flood (SETTINGS / PING / WINDOW_UPDATE / PRIORITY).
    H2Frame(H2FrameKind),
    /// HTTP/2 stream-based flood (MadeYouReset / empty-DATA / HTTP/2 Bomb).
    H2Stream(H2StreamKind),
    /// Long-lived transport connection flood (WebSocket / SSE): hold sessions a
    /// protocol is *meant* to keep open, so no read timeout retires them.
    LongLived(LongLivedKind),
    /// TLS ClientHello parser stress (oversized hello / SNI bomb): the work the
    /// server does on bytes it has not yet decided to trust.
    TlsHello(TlsHelloKind),
}

/// The load shape over time (fast L7 methods only). `--rate` is the peak/ceiling
/// for every shape; the profile only varies the rate *up to* it.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ProfileKind {
    /// Flat rate at the ceiling for the whole duration (the default).
    Constant,
    /// Endurance hold: mechanically a long constant run — set a long --duration.
    Soak,
    /// Step the rate up from --ramp-start to the ceiling over --duration.
    Ramp,
    /// Hold --spike-base, jump to the ceiling for --spike-secs, fall back.
    Spike,
}

/// How the end-of-run report is printed. Two forms rather than one because the
/// two readers are different: an operator needs the reasoning, a script needs a
/// stable single line.
#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputForm {
    /// Multi-line readable block (default).
    Human,
    /// The historical one-line summary.
    Line,
}

#[derive(Debug)]
struct Args {
    allow: Vec<String>,
    targets: Vec<IpAddr>,
    url: Option<String>,
    headers: Vec<(String, String)>,
    l7_kind: L7Kind,
    http_version: HttpVersion,
    output: OutputForm,
    body: Option<String>,
    cache_bust: bool,
    slow_connections: usize,
    drip_ms: u64,
    max_connections: usize,
    request_timeout_ms: u64,
    drain_timeout_ms: u64,
    layer: Layer,
    l4_mode: L4Mode,
    /// The `--port` spec as typed (single port, list, or ranges), kept as a
    /// string so the run's audit record and error messages quote what the
    /// operator wrote. Validated at parse time; turned into a `PortSet` once
    /// `--port-order` is also known.
    port: Option<String>,
    port_order: PortOrder,
    payload_size: usize,
    concurrency: usize,
    connect_timeout_ms: u64,
    ack_lab: bool,
    dry_run: bool,
    no_audit: bool,
    rate: u64,
    duration_secs: u64,
    profile: ProfileKind,
    ramp_start: u64,
    ramp_steps: u32,
    spike_base: Option<u64>,
    spike_secs: u64,
    discover_knee: bool,
    slo: SloSpec,
    watchdog: bool,
    watchdog_window_secs: u64,
    watchdog_breaches: u32,
    audit_log: Option<String>,
    verify_audit: Option<String>,
}

/// Raise this process's open-file-descriptor soft limit to its hard limit and log
/// the resulting ceiling.
///
/// Done here rather than left to the caller because `ulimit -n` is *shell-local*:
/// it does not exist under systemd, cron, or any other non-shell exec, so a run's
/// descriptor headroom must not depend on how it happened to be launched.
///
/// This is headroom, not a fix. The connection-holding L4 modes bound their own
/// footprint with `--concurrency`; a run that needs a raised ceiling to avoid
/// EMFILE is misconfigured, and the `errno(EMFILE=…)` bucket exists to say so out
/// loud rather than let a local limit masquerade as target behaviour.
#[cfg(unix)]
fn raise_nofile_limit() {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};

    let (soft, hard) = match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: could not read RLIMIT_NOFILE: {e}");
            return;
        }
    };
    let mut ceiling = soft;
    if soft < hard {
        match setrlimit(Resource::RLIMIT_NOFILE, hard, hard) {
            Ok(()) => ceiling = hard,
            Err(e) => eprintln!(
                "warning: could not raise RLIMIT_NOFILE from {soft} to {hard}: {e}"
            ),
        }
    }
    println!("fd ceiling: {ceiling} (hard limit {hard})");
}

/// No RLIMIT_NOFILE concept on non-unix targets; descriptor limits are handled by
/// the platform.
#[cfg(not(unix))]
fn raise_nofile_limit() {}

fn run() -> Result<(), String> {
    // `None` => `--help` was printed; there is nothing to run.
    let Some(args) = parse_args()? else { return Ok(()) };

    // A verify-only invocation checks an existing log's integrity and exits
    // without touching the allowlist, the gate, or any traffic path.
    if let Some(path) = &args.verify_audit {
        // Verify AND show. "The chain is intact" answers a question nobody asked
        // on its own; what the log is for is reading what was fired at whom.
        let records = jinrai_metrics::verify_and_read(path).map_err(|e| e.to_string())?;
        println!("audit log {path}");
        // Report the sequence range, not just "INTACT". A hash chain proves the
        // records present are unaltered and in order; it cannot prove that none
        // were cut off the end, because a record links backwards only. Showing
        // the range is what lets an operator who knows how many runs happened
        // notice that the log stops short.
        match (records.first(), records.last()) {
            (Some(f), Some(l)) => println!(
                "hash chain: INTACT ({} record(s), seq {}..={})\n\
                 note: a chain cannot detect records removed from the END of the file.\n",
                records.len(),
                f.seq,
                l.seq
            ),
            _ => println!("hash chain: INTACT (0 records)\n"),
        }
        for r in &records {
            println!("  #{:<4} {}  {:<16} {}", r.seq, r.ts, r.operator, r.summary);
        }
        if records.is_empty() {
            println!("  (no records)");
        }
        return Ok(());
    }

    // Before anything opens a socket: take whatever descriptor headroom the OS
    // will grant, and say what it is.
    raise_nofile_limit();

    // Refused before the log exists, for the obvious reason.
    audit_trail_required(&args)?;

    // Open the audit log (if requested) up front so an unusable log aborts the
    // run BEFORE any authorization or traffic — no untracked runs.
    let operator = operator_identity();
    let mut audit = match &args.audit_log {
        Some(path) => Some(AuditLog::open(path, &operator).map_err(|e| e.to_string())?),
        None => None,
    };

    // Audited like every other pre-gate refusal: an operator who forgot the
    // acknowledgement is an event a reviewer wants to see attempted.
    if let Err(reason) = lab_ack_required(&args) {
        return Err(audit_refusal(&mut audit.as_mut(), "acknowledgement", &reason)?);
    }

    // 1. Build the allowlist from operator parameters (mixed CIDRs + DNS names).
    //    A malformed or missing allowlist is a safety-relevant refusal like any
    //    other, so it is recorded before returning: an audit trail that only
    //    contains the refusals reaching the gate would suggest nothing else was
    //    ever attempted.
    let allowlist = match Allowlist::from_patterns(&args.allow) {
        Ok(a) if !a.is_empty() => a,
        other => {
            let reason = match other {
                Ok(_) => "no --allow rules given; refusing to run (fail-closed)".to_string(),
                Err(e) => format!("bad --allow value: {e}"),
            };
            audit_record(
                &mut audit.as_mut(),
                AuditEvent::RunRefused { stage: "allowlist".into(), reason: reason.clone() },
            )?;
            return Err(reason);
        }
    };

    // 2. The gate. Kill switch is shared with the run plan.
    let kill = KillSwitch::new();

    // Wire the termination signals to the shared kill-switch so a live run can be
    // aborted gracefully: workers poll it and stop within ~50ms, and the run
    // reports what it managed to send. Without this, the advertised abort control
    // is inert. This covers Ctrl-C (SIGINT) *and* SIGTERM/SIGHUP — an unattended
    // run under systemd, docker or K8s is stopped by SIGTERM, and that is exactly
    // the case where an audited, drained shutdown matters most.
    //
    // A failure here is fail-closed, not a warning: continuing would start a live
    // flood whose only advertised stop control does not exist. A run you cannot
    // abort is precisely the run not to start. (A dry run has nothing to abort,
    // so it is exempt.)
    {
        let kill = kill.clone();
        if let Err(e) = ctrlc::set_handler(move || kill.trip()) {
            if !args.dry_run {
                let reason = format!(
                    "could not install the abort (SIGINT/SIGTERM) handler: {e} — refusing \
                     to start traffic that could not then be stopped"
                );
                return Err(audit_refusal(&mut audit.as_mut(), "kill-switch", &reason)?);
            }
            eprintln!("warning: could not install the abort handler: {e} (dry run — nothing to abort)");
        }
    }

    let gate = Authorization::new(allowlist, kill.clone());
    let rate_cap = RateCap::new(args.rate);
    let duration = Duration::from_secs(args.duration_secs);

    match args.layer {
        Layer::L7 => run_l7(&args, gate, kill, rate_cap, duration, audit.as_mut()),
        Layer::L4 | Layer::L3 => run_l4(&args, gate, kill, rate_cap, duration, audit.as_mut()),
    }
}

/// Who a run is attributed to in the audit log: `$JINRAI_OPERATOR` if set, else
/// the OS user, else "unknown". Never fails — an audit trail with a best-effort
/// identity beats no trail.
fn operator_identity() -> String {
    std::env::var("JINRAI_OPERATOR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("USERNAME").ok())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// A human-readable descriptor for an authorized target (IP literal or host).
fn target_label(t: &AuthorizedTarget) -> String {
    match t.as_ip() {
        Some(ip) => ip.to_string(),
        None => t.host().unwrap_or("<target>").to_string(),
    }
}

/// Record a refusal decided before the gate was ever consulted (a missing
/// acknowledgement, a missing target) and produce its operator-facing message.
///
/// Same shape as [`audit_module_failure`]: `Ok` carries the message to fail with,
/// `Err` means the audit write itself failed and the run must abort on that.
fn audit_refusal(
    audit: &mut Option<&mut AuditLog>,
    stage: &str,
    reason: &str,
) -> Result<String, String> {
    audit_record(
        audit,
        AuditEvent::RunRefused { stage: stage.into(), reason: reason.to_string() },
    )?;
    Ok(reason.to_string())
}

/// A live run must be accountable.
///
/// The audit machinery is fail-closed once a log is open — opened before any
/// traffic, a write failure aborts the run — but all of that was worth nothing
/// while the flag was optional, because the one command an operator would rather
/// not have on record is exactly the one that omits it. So: name a log, or say
/// out loud that this run will not be recorded. `--dry-run` is exempt because it
/// emits nothing to account for.
fn audit_trail_required(args: &Args) -> Result<(), String> {
    if args.audit_log.is_none() && !args.no_audit && !args.dry_run {
        return Err(
            "refusing to run without an audit trail: pass --audit-log <PATH> to record \
             this run, or --no-audit to run untracked on purpose"
                .to_string(),
        );
    }
    Ok(())
}

/// The lab acknowledgement, for **every** layer that emits traffic.
///
/// It used to cover the raw-socket layers only. But l7 is the default layer and
/// by far the most reachable — an ordinary URL and an allowlist are enough to
/// put real load on something, no privileges required — so leaving it as the one
/// layer that fires with no confirmation had it exactly backwards.
fn lab_ack_required(args: &Args) -> Result<(), String> {
    if !args.ack_lab && !args.dry_run {
        return Err(
            "refusing to emit traffic: pass --ack-lab to confirm this targets an \
             authorized, isolated-lab system (or --dry-run to validate without sending)"
                .to_string(),
        );
    }
    Ok(())
}

/// `--dry-run`: everything up to the first packet, and then stop.
///
/// By this point the run has done all of its refusable work — allowlist parsed,
/// datum authorized through the gate, engine constructed, preflight passed — so
/// what it prints is not a guess about what *would* happen, it is the plan that
/// was about to execute. That is the point: the way to check a jinrai command
/// line was previously to run it, which for a mistyped `--rate` or an `--allow`
/// that is wider than intended is a poor way to find out.
///
/// Recorded as a refusal at stage `dry-run` so the trail cannot be misread: the
/// `RunAuthorized` record above it is real, and this is what says no traffic
/// followed it.
/// `ports` is the l3/l4 destination-port label (`None` for l7, which targets with
/// a URL, and for the portless ICMP modes). A dry run's whole job is to print the
/// run that was about to happen, and once `--port` can name a whole range that is
/// not answered by the mode name alone.
fn dry_run_summary(
    audit: &mut Option<&mut AuditLog>,
    module: &dyn StressModule,
    plan: &RunPlan,
    args: &Args,
    ports: Option<&str>,
) -> Result<(), String> {
    audit_record(
        audit,
        AuditEvent::RunRefused {
            stage: "dry-run".into(),
            reason: "--dry-run: validated and authorized, no traffic emitted".into(),
        },
    )?;
    println!("\nDRY RUN — validated and authorized, nothing was sent.");
    println!("  module      {} ({:?})", module.name(), module.layer());
    println!(
        "  targets     {}",
        plan.targets.iter().map(target_label).collect::<Vec<_>>().join(", ")
    );
    if let Some(ports) = ports {
        println!("  destination {ports}");
    }
    println!("  allow rules {}", args.allow.join(", "));
    println!("  rate        {}/sec (ceiling)", args.rate);
    println!("  duration    {}s", args.duration_secs);
    println!("\nRe-run with --ack-lab (and without --dry-run) to send it.");
    Ok(())
}

/// Audit a module that refused or could not start, and produce the operator-facing
/// error for it.
///
/// The `Ok` type is the error message because every caller is on its way out:
/// `return Err(audit_module_failure(...)?)` propagates an audit-write failure
/// (fail-closed) and otherwise hands back the message to fail the run with.
fn audit_module_failure(
    audit: &mut Option<&mut AuditLog>,
    layer: &str,
    e: ModuleError,
) -> Result<String, String> {
    audit_record(
        audit,
        AuditEvent::RunRefused { stage: e.stage().into(), reason: format!("{layer}: {e}") },
    )?;
    Ok(format!("{layer} run did not start — {e}"))
}

/// Record an event if auditing is on; a write failure aborts (fail-closed on the
/// trail — we do not want traffic that outran its own audit record).
fn audit_record(audit: &mut Option<&mut AuditLog>, event: AuditEvent) -> Result<(), String> {
    if let Some(log) = audit.as_deref_mut() {
        log.record(&event).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Build the fast-L7 load profile from the operator's flags, or `None` for a
/// flat constant run at the ceiling (the engine default). `--rate` is the
/// peak/ceiling for every shape. `--discover-knee` always ramps to the ceiling
/// regardless of `--profile`, since a knee is found by ramping until it breaks.
fn l7_profile(args: &Args, rate_cap: RateCap, duration: Duration) -> Option<LoadProfile> {
    if args.discover_knee || args.profile == ProfileKind::Ramp {
        return Some(LoadProfile::Ramp {
            start: RateCap::new(args.ramp_start),
            end: rate_cap,
            duration,
            steps: args.ramp_steps,
        });
    }
    match args.profile {
        ProfileKind::Spike => {
            // Base defaults to a fifth of the peak (>=1) when unspecified.
            let base = args.spike_base.unwrap_or((rate_cap.per_second / 5).max(1));
            // The spike is carved *out of* --duration, not added to it: the
            // baseline fills what is left around it. Passing the full duration as
            // `base_total` made a 30s run generate 40s of traffic — an undeclared
            // window, which is precisely what the drain accounting exists to
            // prevent. A spike at least as long as the run is the whole run.
            let spike = Duration::from_secs(args.spike_secs).min(duration);
            Some(LoadProfile::Spike {
                base: RateCap::new(base),
                peak: rate_cap,
                base_total: duration - spike,
                spike,
            })
        }
        // Constant / Soak: flat at the ceiling — use the engine default.
        //
        // `Ramp` returned early above, so it cannot reach here. It shares this
        // arm rather than getting an `unreachable!()`: with `panic = "abort"`
        // that macro is a process death, and the invariant protecting it is
        // "an early return several lines up still exists" — exactly the kind a
        // later edit breaks silently. Falling back to the flat default would be
        // a wrong load shape, which is a bug worth fixing; it is not worth
        // killing a run over.
        ProfileKind::Constant | ProfileKind::Soak | ProfileKind::Ramp => None,
    }
}

/// L7: the operator supplies a URL. The engine validates the URL's host as a
/// *datum* — an IP literal against the CIDR rules, a DNS name against the DNS
/// rules — and only then (for a name) resolves once to connect.
fn run_l7(
    args: &Args,
    gate: Authorization,
    kill: KillSwitch,
    rate_cap: RateCap,
    duration: Duration,
    mut audit: Option<&mut AuditLog>,
) -> Result<(), String> {
    let url = match args.url.clone() {
        Some(u) => u,
        None => {
            return Err(audit_refusal(&mut audit, "arguments", "--layer l7 requires --url <URL>")?)
        }
    };

    // Phase-6 profile validation, fail-closed before any traffic: knee discovery
    // is meaningless without a rate SLO to detect the breaking point against.
    if args.discover_knee && !args.slo.has_rate_thresholds() {
        return Err(audit_refusal(
            &mut audit,
            "arguments",
            "--discover-knee needs a rate SLO to detect the knee \
             (add e.g. --slo-max-5xx-rate or --slo-max-error-rate)",
        )?);
    }

    // Build the selected engine and authorize its datum up front. Both engines
    // authorize identically (datum + resolve-once); we box to a trait object so
    // the audit/plan/execute flow below is shared. Fail-closed with a clear
    // message and non-zero exit BEFORE any traffic is generated.
    let built: Result<(Box<dyn StressModule>, Vec<AuthorizedTarget>), _> = match args.l7_kind {
        L7Kind::Fast(method) => {
            let spec = RequestSpec {
                url: url.clone(),
                method,
                headers: args.headers.clone(),
                body: args.body.clone().map(String::into_bytes),
                cache_bust: args.cache_bust,
                http_version: args.http_version,
            };
            let mut engine = L7Engine::new(gate, spec)
                .with_slo(args.slo)
                .with_max_connections(args.max_connections)
                .with_request_timeout(Duration::from_millis(args.request_timeout_ms))
                .with_drain_grace(Duration::from_millis(args.drain_timeout_ms));
            if let Some(p) = l7_profile(args, rate_cap, duration) {
                engine = engine.with_profile(p);
            }
            if args.discover_knee {
                engine = engine.discover_knee(true);
            }
            if args.watchdog {
                engine = engine.with_watchdog(WatchdogConfig {
                    window: Duration::from_secs(args.watchdog_window_secs.max(1)),
                    max_breaches: args.watchdog_breaches.max(1),
                });
            }
            engine.authorize_target().map(|t| (Box::new(engine) as Box<dyn StressModule>, t))
        }
        L7Kind::Slow(mode) => {
            let cfg = SlowConfig {
                mode,
                max_conns: args.slow_connections,
                drip: Duration::from_millis(args.drip_ms),
            };
            let engine = L7SlowEngine::new(gate, url.clone(), cfg);
            engine.authorize_target().map(|t| (Box::new(engine) as Box<dyn StressModule>, t))
        }
        L7Kind::RapidReset => {
            let engine = H2RapidResetEngine::new(gate, url.clone());
            engine.authorize_target().map(|t| (Box::new(engine) as Box<dyn StressModule>, t))
        }
        L7Kind::Continuation => {
            let engine = H2ContinuationEngine::new(gate, url.clone());
            engine.authorize_target().map(|t| (Box::new(engine) as Box<dyn StressModule>, t))
        }
        L7Kind::TlsHandshake => {
            let engine = TlsHandshakeEngine::new(gate, url.clone())
                .with_max_connections(args.max_connections);
            engine.authorize_target().map(|t| (Box::new(engine) as Box<dyn StressModule>, t))
        }
        L7Kind::H2Frame(kind) => {
            let engine = H2FrameFloodEngine::new(gate, url.clone(), kind);
            engine.authorize_target().map(|t| (Box::new(engine) as Box<dyn StressModule>, t))
        }
        L7Kind::H2Stream(kind) => {
            let engine = H2StreamFloodEngine::new(gate, url.clone(), kind);
            engine.authorize_target().map(|t| (Box::new(engine) as Box<dyn StressModule>, t))
        }
        L7Kind::LongLived(kind) => {
            // Shares the slow modes' two knobs: both primitives open connections
            // up to a ceiling and then hold them, so a second pair of flags for
            // the same two numbers would only be a way to get them wrong.
            let cfg = LongLivedConfig {
                kind,
                max_conns: args.slow_connections,
                tick: Duration::from_millis(args.drip_ms),
            };
            let engine = LongLivedEngine::new(gate, url.clone(), cfg);
            engine.authorize_target().map(|t| (Box::new(engine) as Box<dyn StressModule>, t))
        }
        L7Kind::TlsHello(kind) => {
            // Same footprint knob as the handshake flood: one connection per
            // hello, and a target that accepts then says nothing holds its slot
            // for the read timeout.
            let engine = TlsHelloEngine::new(gate, url.clone(), kind)
                .with_max_connections(args.max_connections);
            engine.authorize_target().map(|t| (Box::new(engine) as Box<dyn StressModule>, t))
        }
    };
    let (mut engine, targets) = match built {
        Ok(pair) => pair,
        Err(e) => {
            audit_record(
                &mut audit,
                AuditEvent::RunRefused {
                    stage: "authorization".into(),
                    reason: format!("l7 {url}: {e}"),
                },
            )?;
            return Err(format!("refusing L7 run: {e}"));
        }
    };

    let kind = match targets.first() {
        Some(t) if t.is_ip() => "IP",
        Some(_) => "host name",
        None => "target",
    };
    println!(
        "authorized {kind} datum for {url} against {} allowlist rule(s)",
        args.allow.len()
    );

    audit_record(
        &mut audit,
        AuditEvent::RunAuthorized {
            layer: format!("{:?}", engine.layer()),
            mode: engine.name().to_string(),
            rate_per_sec: args.rate,
            duration_secs: args.duration_secs,
            targets: targets.iter().map(target_label).collect(),
            allow_rules: args.allow.clone(),
        },
    )?;

    // SLO/watchdog apply to the fast request-flood methods only: the slow modes
    // and rapid-reset never receive a response to classify. Warn, don't ignore.
    let is_fast = matches!(args.l7_kind, L7Kind::Fast(_));
    // The methods that open connections up to a ceiling and then hold them:
    // `--rate` paces the opening, `--slow-connections` is the real bound.
    let is_connection_holding =
        matches!(args.l7_kind, L7Kind::Slow(_) | L7Kind::LongLived(_));
    if !is_fast && !args.slo.is_empty() {
        eprintln!("warning: --slo-* / --watchdog are ignored for the slow-connection / h2 / tls-* / websocket / sse methods (no per-request response to classify)");
    } else if args.watchdog && !args.slo.has_rate_thresholds() {
        eprintln!("warning: --watchdog is inert without a --slo-max-*-rate to watch");
    }
    // Load profiles / knee discovery only shape the fast request-flood dispatch.
    if !is_fast && (args.discover_knee || args.profile != ProfileKind::Constant) {
        eprintln!("warning: load profiles / --discover-knee apply to fast l7 methods only; ignored here");
    }
    // The protocol version is a property of the fast client; the other primitives
    // are fixed by construction (slow modes speak HTTP/1.1, h2-* speak HTTP/2).
    if !is_fast && args.http_version != HttpVersion::Auto {
        eprintln!(
            "warning: --http-version applies to the fast get/post/head methods only; \
             ignored here (slow / websocket / sse are HTTP/1.1, h2-* are HTTP/2 by construction)"
        );
    }

    let plan = RunPlan { targets, rate_cap, duration, kill };
    if args.dry_run {
        return dry_run_summary(&mut audit, engine.as_ref(), &plan, args, None);
    }
    println!("running module '{}' ({:?})...", engine.name(), engine.layer());
    let started = std::time::Instant::now();
    let started_unix = now_unix();
    // A module that could not run says so, and that is audited as a refusal —
    // not as a run that happened to send nothing.
    let report = match engine.execute(&plan) {
        Ok(r) => r,
        Err(e) => return Err(audit_module_failure(&mut audit, "l7", e)?),
    };
    let elapsed = started.elapsed();

    // Evaluate the SLO verdict (only when the operator declared one, and only for
    // fast methods that produced a classification). A knee-discovery run reports
    // the breaking point instead: reaching a breach is the goal there, so its SLO
    // is the probe, not a target to pass.
    let verdict = if !args.discover_knee && !args.slo.is_empty() && is_fast {
        Some(args.slo.evaluate(&report))
    } else {
        None
    };

    let mut notes = Vec::new();
    if is_fast {
        if let Some(v) = args.http_version.forced_label() {
            notes.push(v.to_string());
        }
        if args.max_connections > 0 {
            notes.push(format!("max {} concurrent connections", args.max_connections));
        }
    }
    // The connection-holding methods open --slow-connections connections and then
    // stop opening. Naming that ceiling is what keeps `25 attempts, 10% of the
    // 50/s cap` from reading as a target that absorbed the other 90%: nothing was
    // withheld, the run simply reached the ceiling the operator set.
    if is_connection_holding {
        notes.push(format!("{} connection ceiling", args.slow_connections));
    }
    report_run(
        args,
        &report,
        verdict.as_ref(),
        RunContext {
            layer: format!("{:?}", engine.layer()),
            mode: engine.name().to_string(),
            target: url.clone(),
            rate_per_sec: args.rate,
            planned: duration,
            elapsed,
            started_unix,
            notes,
            // The in-flight ceiling that actually applied, so the shortfall note
            // can attribute a run that fell short of its cap. For the fast flood
            // that is --max-connections (0 means unbounded, which cannot be the
            // binding constraint); for the connection-holding methods it is
            // --slow-connections, and naming it suppresses the "the generator,
            // not the target" inference — which was false here: the run stopped
            // opening because it hit the ceiling, not because this host could
            // not go faster. The h2-* methods use a single connection and are
            // genuinely paced by --rate alone.
            concurrency: match () {
                _ if is_fast => (args.max_connections > 0).then_some(args.max_connections),
                _ if is_connection_holding => Some(args.slow_connections),
                _ => None,
            },
        },
    );

    if args.discover_knee {
        audit_record(&mut audit, AuditEvent::completed(&report, None))?;
        // Discovery succeeds whether or not a knee was found (an operator Ctrl-C
        // still aborts); it is not a pass/fail run. But "not pass/fail" is not
        // "always green": a run that completed nothing discovered nothing either,
        // and "the target held the full ramp" is then a claim about a target we
        // never reached — the most confidently-wrong line this tool can print. So
        // the hollow-run check applies here too, and it runs BEFORE the conclusion
        // is printed rather than after it.
        check_l7_reached_something(&report)?;
        match report.knee {
            Some(k) => println!(
                "breaking point: sustained {} req/s within SLO, breached at {} req/s",
                k.sustained_per_sec, k.breached_at_per_sec
            ),
            None => println!(
                "no breaking point found: target held the full ramp up to {} req/s within SLO",
                args.rate
            ),
        }
        return Ok(());
    }

    audit_record(&mut audit, AuditEvent::completed(&report, verdict.as_ref()))?;
    check_l7_outcome(&report, verdict.as_ref())
}

/// Wall-clock seconds since the Unix epoch, for stamping the run's start. A
/// clock set before the epoch is not a reason to fail a run, so it yields
/// `None` and the summary simply omits the timestamps rather than claiming 1970.
fn now_unix() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Print the end-of-run report in the operator's chosen form.
///
/// `human` is the default because the compact line — two counters and a boolean —
/// reads the same whether the target absorbed the load or never received a byte,
/// which is precisely the distinction the run exists to establish.
fn report_run(
    args: &Args,
    report: &RunReport,
    verdict: Option<&SloVerdict>,
    ctx: RunContext,
) {
    match args.output {
        OutputForm::Human => {
            println!("{}", jinrai_metrics::render_summary(report, &ctx, verdict))
        }
        OutputForm::Line => {
            println!("{}", jinrai_metrics::render(report));
            if let Some(v) = verdict {
                println!("{}", jinrai_metrics::render_verdict(v));
            }
        }
    }
}

/// Post-run gate for L7: a watchdog abort or an unmet SLO exits non-zero so
/// automation can tell "the target held" from "the target buckled". An operator
/// Ctrl-C (aborted_early without the watchdog) is not itself a failure.
fn check_l7_outcome(report: &RunReport, verdict: Option<&SloVerdict>) -> Result<(), String> {
    if report.aborted_by_watchdog {
        return Err(format!(
            "SLO watchdog aborted the run (sustained breach): {}",
            report.layer_label
        ));
    }
    if let Some(v) = verdict {
        if !v.passed() {
            return Err(format!("target did not meet SLO — {v}"));
        }
    }
    check_l7_reached_something(report)
}

/// A run where every single attempt failed exercised nothing, and must not report
/// success — the same policy L3/L4 already applies (`check_l4_outcome`). Every L7
/// primitive counts a unit once it got somewhere (a response, an established slow
/// connection, a sent frame), so 0 units with only failures means the target was
/// never reached. Without this, `--http-version 2` against an HTTP/1.1-only target
/// exits 0 having sent no valid request at all.
///
/// Split out from [`check_l7_outcome`] because knee discovery has no SLO verdict
/// to check but still must not report a conclusion about a target it never
/// reached.
fn check_l7_reached_something(report: &RunReport) -> Result<(), String> {
    if report.units_sent == 0 && report.errors > 0 {
        return Err(format!(
            "L7 run completed 0 of {} attempts: target unreachable, refusing, or \
             not speaking the requested protocol (nothing was stress-tested)",
            report.attempts()
        ));
    }
    Ok(())
}

/// L3/L4: the operator supplies raw target IPs, authorized directly through the
/// gate, and an explicit lab acknowledgement. Sends real packets.
fn run_l4(
    args: &Args,
    gate: Authorization,
    kill: KillSwitch,
    rate_cap: RateCap,
    duration: Duration,
    mut audit: Option<&mut AuditLog>,
) -> Result<(), String> {
    // The lab acknowledgement is enforced for every layer in `run`, before this
    // point. These pre-gate refusals are audited like every other refusal.
    if args.targets.is_empty() {
        return Err(audit_refusal(
            &mut audit,
            "arguments",
            "--layer l3/l4 requires at least one --target <IP>",
        )?);
    }
    // ICMP is portless; every other mode targets a port (or a set of them).
    let ports = match args.port.as_deref() {
        Some(spec) => match PortSet::parse(spec, args.port_order) {
            Ok(set) => set,
            // Unreachable in practice — the spec was validated when it was
            // parsed off the command line — but a refusal here is still audited
            // rather than unwrapped, because this is the last point before the
            // set decides where packets go.
            Err(e) => return Err(audit_refusal(&mut audit, "arguments", &e)?),
        },
        None if args.l4_mode.is_icmp() => PortSet::single(0),
        None => {
            return Err(audit_refusal(
                &mut audit,
                "arguments",
                "--layer l3/l4 requires --port <SPEC> (except the icmp* modes)",
            )?)
        }
    };
    // Taken before the set moves into the engine config, for the audit record,
    // the summary note, and the dry-run print.
    let port_label = ports.label();
    let dry_run_ports = if args.l4_mode.is_icmp() { None } else { Some(port_label.as_str()) };

    let authorized = match gate.authorize_all(args.targets.iter().copied()) {
        Ok(t) => t,
        Err(e) => {
            audit_record(
                &mut audit,
                AuditEvent::RunRefused {
                    stage: "authorization".into(),
                    reason: e.to_string(),
                },
            )?;
            return Err(e.to_string());
        }
    };

    println!(
        "authorized {} target(s) against {} allowlist rule(s)",
        authorized.len(),
        args.allow.len()
    );

    let plan = RunPlan { targets: authorized, rate_cap, duration, kill };
    let mut module = L34Engine::new(L34Config {
        mode: args.l4_mode,
        ports,
        payload_size: args.payload_size,
        concurrency: args.concurrency,
        connect_timeout: Duration::from_millis(args.connect_timeout_ms),
    });

    // Record the authorized run (targets + rules + params) before any traffic.
    // The port set goes in the mode string rather than a field of its own: a run
    // may now span a whole range, so "which primitive ran" is not fully answered
    // without it, and the pre-traffic record is the only one a refused or aborted
    // run leaves behind. (The completion record carries it inside `layer_label`.)
    let audited_mode = if args.l4_mode.is_icmp() {
        module.name().to_string()
    } else {
        format!("{} on {}", module.name(), port_label)
    };
    audit_record(
        &mut audit,
        AuditEvent::RunAuthorized {
            layer: format!("{:?}", module.layer()),
            mode: audited_mode,
            rate_per_sec: args.rate,
            duration_secs: args.duration_secs,
            targets: plan.targets.iter().map(target_label).collect(),
            allow_rules: args.allow.clone(),
        },
    )?;

    // Fail fast (non-zero exit) before emitting anything: missing raw-socket
    // capability, an IPv6 target a mode can't reach, or no usable IP target.
    if let Err(e) = module.preflight(&plan) {
        audit_record(
            &mut audit,
            AuditEvent::RunRefused {
                stage: "preflight".into(),
                reason: e.to_string(),
            },
        )?;
        return Err(format!("refusing L3/L4 run: {e}"));
    }
    if args.dry_run {
        return dry_run_summary(&mut audit, &module, &plan, args, dry_run_ports);
    }
    println!("running module '{}' ({:?})...", module.name(), module.layer());
    let started = std::time::Instant::now();
    let started_unix = now_unix();
    // Preflight catches most of these earlier, but a setup failure can still
    // surface here (a route that disappears, a bind that fails). It is recorded
    // as a refusal with its cause, not as a completed run with zero units.
    let report = match module.execute(&plan) {
        Ok(r) => r,
        Err(e) => return Err(audit_module_failure(&mut audit, "l3/l4", e)?),
    };
    let elapsed = started.elapsed();

    let mut notes = if args.l4_mode.is_icmp() {
        Vec::new() // ICMP is portless
    } else {
        vec![port_label.clone()]
    };
    // Only the connection-holding modes are bounded by --concurrency; restating it
    // for a stateless flood would suggest a limit that does not exist.
    if matches!(args.l4_mode, L4Mode::TcpConnect | L4Mode::Data) {
        notes.push(format!("max {} sockets open at once", args.concurrency));
    }
    report_run(
        args,
        &report,
        None,
        RunContext {
            layer: format!("{:?}", module.layer()),
            mode: module.name().to_string(),
            target: plan.targets.iter().map(target_label).collect::<Vec<_>>().join(", "),
            rate_per_sec: args.rate,
            planned: duration,
            elapsed,
            started_unix,
            notes,
            // Only the connect flood paces against an in-flight ceiling; the
            // stateless floods measure no latency for the bound to apply to.
            // Report the ceiling that actually applied: the pool clamps
            // simultaneous handshakes, so a larger --concurrency than that buys
            // sockets, not offered load, and the note must not imply otherwise.
            concurrency: match args.l4_mode {
                L4Mode::TcpConnect => Some(jinrai_l34::effective_parallelism(args.concurrency)),
                _ => None,
            },
        },
    );
    audit_record(&mut audit, AuditEvent::completed(&report, None))?;

    // A run that could not complete, or that emitted nothing while every attempt
    // failed, must NOT report success: exit non-zero so automation and operators
    // can tell a real test from a hollow no-op. (A deliberate --rate 0 sends 0
    // with 0 errors and is a legitimate success.)
    check_l4_outcome(&report)
}

/// Post-run gate: a hollow run (aborted, or 0 units with only errors) exits
/// non-zero. Kept separate so the outcome policy is testable in isolation.
fn check_l4_outcome(report: &RunReport) -> Result<(), String> {
    if report.aborted_early {
        return Err(format!("L3/L4 run did not complete: {}", report.layer_label));
    }
    if report.units_sent == 0 && report.errors > 0 {
        return Err(format!(
            "L3/L4 run emitted 0 units with {} error(s): target unreachable or \
             misconfigured (nothing was stress-tested)",
            report.errors
        ));
    }
    Ok(())
}

/// Parse the process's own command line.
fn parse_args() -> Result<Option<Args>, String> {
    parse_args_from(std::env::args().skip(1))
}

/// Parse an arbitrary argument list.
///
/// Split from [`parse_args`] so the operator-facing surface — which flags are
/// accepted, which values are refused, and what the defaults are — can be tested
/// without a process boundary. This is the gate's front door: `--allow`,
/// `--ack-lab` and the SLO thresholds all arrive through here, and a parser
/// that quietly accepts a malformed one of those is a safety problem, not a
/// usability one.
///
/// `Ok(None)` means help was requested and already printed; the caller should
/// exit successfully without running anything. Returning it rather than calling
/// `process::exit` from inside the parse loop keeps this function callable from a
/// test.
fn parse_args_from(args: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut allow = Vec::new();
    let mut targets = Vec::new();
    let mut url = None;
    let mut headers = Vec::new();
    let mut l7_kind = L7Kind::Fast(L7Method::Get);
    let mut http_version = HttpVersion::Auto;
    let mut output = OutputForm::Human;
    let mut body = None;
    let mut cache_bust = false;
    let mut slow_connections = 100usize;
    let mut drip_ms = 10_000u64;
    let mut max_connections = jinrai_l7::DEFAULT_MAX_CONNS;
    let mut request_timeout_ms = jinrai_l7::DEFAULT_REQUEST_TIMEOUT.as_millis() as u64;
    let mut drain_timeout_ms = jinrai_l7::DEFAULT_DRAIN_GRACE.as_millis() as u64;
    let mut layer = Layer::L7;
    let mut l4_mode = L4Mode::Udp;
    let mut port: Option<String> = None;
    let mut port_order = PortOrder::default();
    let mut payload_size = 64usize;
    let mut concurrency = jinrai_l34::DEFAULT_CONCURRENCY;
    let mut connect_timeout_ms = jinrai_l34::DEFAULT_CONNECT_TIMEOUT.as_millis() as u64;
    let mut ack_lab = false;
    let mut dry_run = false;
    let mut no_audit = false;
    let mut rate = 100u64;
    let mut duration_secs = 10u64;
    let mut profile = ProfileKind::Constant;
    let mut ramp_start = 0u64;
    let mut ramp_steps = 10u32;
    let mut spike_base = None;
    let mut spike_secs = 10u64;
    let mut discover_knee = false;
    let mut slo = SloSpec::default();
    let mut watchdog = false;
    let mut watchdog_window_secs = 5u64;
    let mut watchdog_breaches = 3u32;
    let mut audit_log = None;
    let mut verify_audit = None;

    let mut it = args;
    let mut seen: Vec<String> = Vec::new();
    while let Some(arg) = it.next() {
        // A flag given twice used to let the last one win, silently. For `--rate`
        // that means an operator who edited a command line and left the old value
        // behind gets a ceiling they can see in their own shell history and did
        // not get — the wrong direction for a safety control to be quiet about.
        // The repeatable flags are exempt because repetition is their interface.
        if arg.starts_with('-') && !REPEATABLE_FLAGS.contains(&arg.as_str()) {
            if seen.iter().any(|s| s == &arg) {
                return Err(format!(
                    "{arg} given more than once — jinrai will not guess which value \
                     you meant (only {} may repeat)",
                    REPEATABLE_FLAGS.join(", ")
                ));
            }
            seen.push(arg.clone());
        }
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--allow" => allow.push(next_val(&mut it, "--allow")?),
            "--target" => {
                let raw = next_val(&mut it, "--target")?;
                let ip = raw
                    .parse::<IpAddr>()
                    .map_err(|_| format!("invalid --target IP: {raw}"))?;
                targets.push(ip);
            }
            "--url" => url = Some(next_val(&mut it, "--url")?),
            "--l7-method" => {
                l7_kind = match next_val(&mut it, "--l7-method")?.as_str() {
                    "get" => L7Kind::Fast(L7Method::Get),
                    "post" => L7Kind::Fast(L7Method::Post),
                    "head" => L7Kind::Fast(L7Method::Head),
                    "slowloris" => L7Kind::Slow(SlowMode::Headers),
                    "slowbody" => L7Kind::Slow(SlowMode::Body),
                    "slow-read" => L7Kind::Slow(SlowMode::Read),
                    "h2-rapid-reset" => L7Kind::RapidReset,
                    "h2-continuation" => L7Kind::Continuation,
                    "tls-handshake" => L7Kind::TlsHandshake,
                    "h2-settings" => L7Kind::H2Frame(H2FrameKind::Settings),
                    "h2-ping" => L7Kind::H2Frame(H2FrameKind::Ping),
                    "h2-window-update" => L7Kind::H2Frame(H2FrameKind::WindowUpdate),
                    "h2-priority" => L7Kind::H2Frame(H2FrameKind::Priority),
                    "h2-made-you-reset" => L7Kind::H2Stream(H2StreamKind::MadeYouReset),
                    "h2-empty-data" => L7Kind::H2Stream(H2StreamKind::EmptyData),
                    "h2-bomb" => L7Kind::H2Stream(H2StreamKind::Bomb),
                    "websocket" => L7Kind::LongLived(LongLivedKind::WebSocket),
                    "sse" => L7Kind::LongLived(LongLivedKind::Sse),
                    "tls-big-hello" => L7Kind::TlsHello(TlsHelloKind::BigHello),
                    "tls-sni-bomb" => L7Kind::TlsHello(TlsHelloKind::SniBomb),
                    other => {
                        return Err(format!(
                            "unknown --l7-method: {other} (want get|post|head|slowloris|slowbody|\
                             slow-read|h2-rapid-reset|h2-continuation|tls-handshake|h2-settings|\
                             h2-ping|h2-window-update|h2-priority|h2-made-you-reset|h2-empty-data|\
                             h2-bomb|websocket|sse|tls-big-hello|tls-sni-bomb)"
                        ))
                    }
                }
            }
            "--http-version" => {
                let raw = next_val(&mut it, "--http-version")?;
                http_version = match raw.as_str() {
                    "auto" => HttpVersion::Auto,
                    // Accept the spellings an operator actually types.
                    "1.1" | "1" | "http1.1" | "http/1.1" => HttpVersion::Http11,
                    "2" | "2.0" | "h2" | "http2" | "http/2" => HttpVersion::Http2,
                    other => {
                        return Err(format!(
                            "unknown --http-version: {other} (want auto|1.1|2)"
                        ))
                    }
                };
            }
            "--output" => {
                output = match next_val(&mut it, "--output")?.as_str() {
                    "human" => OutputForm::Human,
                    "line" => OutputForm::Line,
                    other => {
                        return Err(format!("unknown --output: {other} (want human|line)"))
                    }
                }
            }
            "--body" => body = Some(next_val(&mut it, "--body")?),
            "--cache-bust" => cache_bust = true,
            "--slow-connections" => {
                slow_connections =
                    parse_capped(&mut it, "--slow-connections", MAX_CONNECTIONS as u64)? as usize;
                // 0 would open nothing and report a clean run that tested
                // nothing — and it means the opposite ("no limit") on
                // --max-connections, so it must not quietly mean "none" here.
                if slow_connections == 0 {
                    return Err("--slow-connections must be at least 1 \
                                (0 would hold no connections and test nothing)"
                        .to_string());
                }
            }
            "--drip-ms" => {
                drip_ms = parse_capped(&mut it, "--drip-ms", MAX_DURATION_SECS * 1000)?;
                // The drip interval is what makes a slow attack slow. At 0 the
                // per-connection write loop is unpaced — a byte-at-a-time write
                // flood on every held connection, which is not the primitive the
                // operator selected and is not bounded by --rate.
                if drip_ms == 0 {
                    return Err("--drip-ms must be at least 1 \
                                (0 turns the drip into an unpaced write flood)"
                        .to_string());
                }
            }
            "--max-connections" => {
                max_connections =
                    parse_capped(&mut it, "--max-connections", MAX_CONNECTIONS as u64)? as usize;
            }
            "--request-timeout-ms" => {
                request_timeout_ms = parse_capped(&mut it, "--request-timeout-ms", MAX_TIMEOUT_MS)?;
            }
            "--drain-timeout-ms" => {
                drain_timeout_ms = parse_capped(&mut it, "--drain-timeout-ms", MAX_TIMEOUT_MS)?;
            }
            "--l4-mode" => {
                l4_mode = match next_val(&mut it, "--l4-mode")?.as_str() {
                    "udp" => L4Mode::Udp,
                    "tcp" => L4Mode::TcpConnect,
                    "syn" => L4Mode::Syn,
                    "ack" => L4Mode::Ack,
                    "fin" => L4Mode::Fin,
                    "rst" => L4Mode::Rst,
                    "urg" => L4Mode::Urg,
                    "cwr" => L4Mode::Cwr,
                    "ece" => L4Mode::Ece,
                    "syn-ack" => L4Mode::SynAck,
                    "syn-fin" => L4Mode::SynFin,
                    "syn-rst" => L4Mode::SynRst,
                    "xmas" => L4Mode::Xmas,
                    "null" => L4Mode::Null,
                    "data" => L4Mode::Data,
                    "tcp-options" => L4Mode::TcpOptions,
                    "icmp" => L4Mode::Icmp,
                    "icmp-timestamp" => L4Mode::IcmpTimestamp,
                    "icmp-address-mask" => L4Mode::IcmpAddressMask,
                    other => {
                        return Err(format!(
                            "unknown --l4-mode: {other} \
                             (want udp|tcp|syn|ack|fin|rst|urg|cwr|ece|syn-ack|syn-fin|\
                              syn-rst|xmas|null|data|tcp-options|icmp|icmp-timestamp|\
                              icmp-address-mask)"
                        ))
                    }
                }
            }
            "--port" => {
                // Parsed here only to reject a malformed spec at argument time;
                // the set is rebuilt once `--port-order` is known, since the
                // flags may arrive in either order.
                let raw = next_val(&mut it, "--port")?;
                PortSet::parse(&raw, PortOrder::Sequential)?;
                port = Some(raw);
            }
            "--port-order" => {
                let raw = next_val(&mut it, "--port-order")?;
                port_order = PortOrder::parse(&raw)?;
            }
            "--payload-size" => {
                payload_size =
                    parse_capped(&mut it, "--payload-size", MAX_PAYLOAD_SIZE as u64)? as usize;
            }
            "--concurrency" => {
                let v = parse_capped(&mut it, "--concurrency", MAX_CONNECTIONS as u64)?;
                // Clamped to 1 downstream, which makes `--concurrency 0` read as
                // "no concurrency" and behave as "one". An operator who typed a
                // zero meant something; we cannot tell what, so we say so.
                if v == 0 {
                    return Err(
                        "--concurrency 0 would send nothing; it is clamped to 1 downstream, \
                         so say 1 if that is what you mean"
                            .to_string(),
                    );
                }
                concurrency = v as usize;
            }
            "--connect-timeout-ms" => {
                connect_timeout_ms = parse_capped(&mut it, "--connect-timeout-ms", MAX_TIMEOUT_MS)?;
            }
            // `--ack-l34-lab` was the L3/L4-only spelling. The acknowledgement now
            // covers every layer that emits traffic, so the flag lost the layer
            // from its name; the old spelling keeps working so existing runbooks
            // and scripts do not break on upgrade.
            "--ack-lab" | "--ack-l34-lab" => ack_lab = true,
            "--dry-run" => dry_run = true,
            "--no-audit" => no_audit = true,
            "--header" => {
                let raw = next_val(&mut it, "--header")?;
                let (k, v) = raw
                    .split_once(':')
                    .ok_or_else(|| format!("invalid --header (want 'Name: value'): {raw}"))?;
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            "--layer" => {
                layer = match next_val(&mut it, "--layer")?.as_str() {
                    "l7" => Layer::L7,
                    "l4" => Layer::L4,
                    "l3" => Layer::L3,
                    other => return Err(format!("unknown --layer: {other}")),
                }
            }
            "--rate" => rate = parse_capped(&mut it, "--rate", MAX_RATE)?,
            "--duration" => {
                duration_secs = parse_capped(&mut it, "--duration", MAX_DURATION_SECS)?
            }
            "--profile" => {
                profile = match next_val(&mut it, "--profile")?.as_str() {
                    "constant" => ProfileKind::Constant,
                    "soak" => ProfileKind::Soak,
                    "ramp" => ProfileKind::Ramp,
                    "spike" => ProfileKind::Spike,
                    other => {
                        return Err(format!(
                            "unknown --profile: {other} (want constant|soak|ramp|spike)"
                        ))
                    }
                }
            }
            "--ramp-start" => ramp_start = parse_capped(&mut it, "--ramp-start", MAX_RATE)?,
            "--ramp-steps" => {
                ramp_steps =
                    parse_capped(&mut it, "--ramp-steps", MAX_RAMP_STEPS as u64)? as u32
            }
            "--spike-base" => {
                spike_base = Some(parse_capped(&mut it, "--spike-base", MAX_RATE)?)
            }
            "--spike-secs" => {
                spike_secs = parse_capped(&mut it, "--spike-secs", MAX_DURATION_SECS)?
            }
            "--discover-knee" => discover_knee = true,
            "--slo-max-error-rate" => slo.max_error_rate = Some(parse_rate(&mut it, "--slo-max-error-rate")?),
            "--slo-max-5xx-rate" => slo.max_5xx_rate = Some(parse_rate(&mut it, "--slo-max-5xx-rate")?),
            "--slo-max-4xx-rate" => slo.max_4xx_rate = Some(parse_rate(&mut it, "--slo-max-4xx-rate")?),
            "--slo-max-p99-ms" => {
                let ms: u64 = next_val(&mut it, "--slo-max-p99-ms")?
                    .parse()
                    .map_err(|_| "invalid --slo-max-p99-ms".to_string())?;
                slo.max_p99_micros = Some(ms.saturating_mul(1000));
            }
            "--watchdog" => watchdog = true,
            // Capped like every other numeric flag: the window becomes a
            // `Duration` added to an `Instant`, and the breach count bounds a
            // loop. Both were the last two flags parsing straight into their
            // types with no ceiling.
            "--watchdog-window" => {
                watchdog_window_secs =
                    parse_capped(&mut it, "--watchdog-window", MAX_DURATION_SECS)?;
            }
            "--watchdog-breaches" => {
                watchdog_breaches =
                    parse_capped(&mut it, "--watchdog-breaches", MAX_WATCHDOG_BREACHES as u64)?
                        as u32;
            }
            "--audit-log" => audit_log = Some(next_val(&mut it, "--audit-log")?),
            "--verify-audit" => verify_audit = Some(next_val(&mut it, "--verify-audit")?),
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }

    // `--rate` is documented as a hard ceiling that every profile shapes traffic
    // only *up to*. Today that holds because the engine clamps each stage — one
    // call site, one `clamped_to`, and the promise rests on it. A profile floor
    // above the ceiling is a contradiction the operator can see and we cannot
    // resolve for them (is the ceiling wrong, or the floor?), so refuse it here
    // rather than silently flattening the shape they asked for.
    // Opposite instructions about the one file that makes a run accountable.
    // `--audit-log` won and the opt-out was silently ignored — a harmless
    // outcome here, but the wrong precedent on this flag: an operator who passed
    // both cannot be assumed to have meant the recorded one, and guessing is not
    // ours to do when the answer is "was this run on the record".
    if no_audit && audit_log.is_some() {
        return Err(
            "--no-audit and --audit-log contradict each other: pass one or the other".to_string(),
        );
    }
    if ramp_start > rate {
        return Err(format!(
            "--ramp-start {ramp_start} exceeds the --rate ceiling {rate}: a ramp cannot \
             start above the cap it ramps toward (raise --rate or lower --ramp-start)"
        ));
    }
    if let Some(base) = spike_base {
        if base > rate {
            return Err(format!(
                "--spike-base {base} exceeds the --rate ceiling {rate}: the baseline \
                 cannot be above the spike peak (raise --rate or lower --spike-base)"
            ));
        }
    }

    // Flags belonging to the other layer were accepted and then quietly dropped.
    // Warn rather than refuse: the run is still well-defined, and an operator
    // adapting an l4 command line into an l7 one should be told which parts did
    // not come across — not have the whole thing rejected.
    let (targeting, wrong_layer) = match layer {
        // Slices, not fixed arrays: the two lists no longer happen to be the
        // same length, and padding one to match the other is not a reason to
        // warn about a flag.
        Layer::L7 => (
            "--url",
            &["--target", "--port", "--port-order", "--concurrency", "--connect-timeout-ms"][..],
        ),
        Layer::L3 | Layer::L4 => {
            ("--target", &["--url", "--header", "--l7-method", "--max-connections"][..])
        }
    };
    let ignored: Vec<&str> =
        wrong_layer.iter().copied().filter(|f| seen.iter().any(|s| s == f)).collect();
    if !ignored.is_empty() {
        eprintln!(
            "warning: {} {} for --layer {}, which targets with {targeting} — ignored",
            ignored.join(", "),
            if ignored.len() == 1 { "is not a flag" } else { "are not flags" },
            match layer {
                Layer::L7 => "l7",
                Layer::L4 => "l4",
                Layer::L3 => "l3",
            },
        );
    }

    Ok(Some(Args {
        allow,
        targets,
        url,
        headers,
        l7_kind,
        http_version,
        output,
        body,
        cache_bust,
        slow_connections,
        drip_ms,
        max_connections,
        request_timeout_ms,
        drain_timeout_ms,
        layer,
        l4_mode,
        port,
        port_order,
        payload_size,
        concurrency,
        connect_timeout_ms,
        ack_lab,
        dry_run,
        no_audit,
        rate,
        duration_secs,
        profile,
        ramp_start,
        ramp_steps,
        spike_base,
        spike_secs,
        discover_knee,
        slo,
        watchdog,
        watchdog_window_secs,
        watchdog_breaches,
        audit_log,
        verify_audit,
    }))
}

/// The flags whose whole point is being given more than once.
const REPEATABLE_FLAGS: &[&str] = &["--allow", "--target", "--header"];

/// Take a flag's value, refusing one that is obviously the next flag.
///
/// `it.next()` alone swallows whatever comes next, so a missing value turns the
/// following flag into data: `--audit-log --ack-lab --allow …` wrote a file
/// literally named `--ack-lab` and left the acknowledgement unset. That run then
/// failed for a reason with no visible connection to the typo. None of jinrai's
/// values legitimately begin with `-` (URLs, hosts, headers, numbers), and a path
/// that does can be written `./-thing`.
fn next_val(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    match it.next() {
        None => Err(format!("{flag} requires a value")),
        Some(v) if v.starts_with('-') && v.len() > 1 => Err(format!(
            "{flag} requires a value but got the flag {v} — if {v} really is the \
             value, write it as ./{v}"
        )),
        Some(v) => Ok(v),
    }
}

/// Upper bound on `--rate`. No single host emits ten million units a second —
/// the syscall path gives out two orders of magnitude below this — so anything
/// above it is a typo, and typos here are expensive: the pacing interval shrinks
/// to a nanosecond and each tick tries to emit a batch nothing can drain.
const MAX_RATE: u64 = 10_000_000;

/// Upper bound on `--duration` (24 hours). Anything longer belongs in a
/// scheduler, and unbounded values overflow `Instant::now() + duration`, which
/// panics rather than refusing.
const MAX_DURATION_SECS: u64 = 86_400;

/// Upper bound on `--concurrency` / `--slow-connections` / `--max-connections`.
/// A million sockets is already far past any reachable descriptor ceiling; the
/// value is also used as an allocation size, so an unbounded one aborts the
/// process on a capacity overflow before a single packet is sent.
const MAX_CONNECTIONS: usize = 1_048_576;

/// Upper bound on `--watchdog-breaches`. The watchdog aborts after this many
/// consecutive breaching windows, so `breaches × window` is how long a target may
/// stay in breach before the run stops. Beyond a thousand the watchdog is not
/// watching anything a run would outlive.
const MAX_WATCHDOG_BREACHES: u32 = 1_000;

/// Upper bound on `--ramp-steps`. Each step is a materialised stage in a `Vec`,
/// so an unbounded count is an allocation request, not a load shape.
const MAX_RAMP_STEPS: u32 = 10_000;

/// Upper bound on every `*-timeout-ms` flag (24 hours, the `--duration` ceiling
/// expressed in milliseconds). These all become `Instant::now() + duration`,
/// which **panics** on overflow — and with `panic = "abort"` that is a process
/// death, potentially with sockets already open. A timeout longer than the
/// longest run jinrai will accept cannot mean anything anyway.
const MAX_TIMEOUT_MS: u64 = MAX_DURATION_SECS * 1_000;

/// Upper bound on `--payload-size` (1 MiB). The value is allocated per unit, so
/// an unbounded one is an out-of-memory abort dressed as a flag. A UDP datagram
/// cannot exceed 65 507 bytes in the first place, and for `--l4-mode data` the
/// write size stops mattering long before a mebibyte — so this ceiling never
/// shapes a real test, it only catches the typo.
const MAX_PAYLOAD_SIZE: usize = 1_048_576;

/// Parse a numeric flag and refuse — loudly — anything above `max`.
///
/// Every one of these values is a size or a rate that something downstream
/// allocates against, divides by, or adds to an `Instant`. Refusing at the front
/// door keeps that arithmetic total: a fat-fingered `--rate 1000000000` is an
/// operator error the parser can name, not a panic three layers down with the
/// raw socket already open. The limits are deliberately far above any real run,
/// so they never shape a legitimate test — they only catch typos.
fn parse_capped(
    it: &mut impl Iterator<Item = String>,
    flag: &str,
    max: u64,
) -> Result<u64, String> {
    let raw = next_val(it, flag)?;
    let v: u64 = raw.parse().map_err(|_| format!("invalid {flag}: {raw}"))?;
    if v > max {
        return Err(format!("{flag} must be at most {max} (got {raw})"));
    }
    Ok(v)
}

/// Parse an SLO rate as a fraction in `[0.0, 1.0]`; anything outside is refused
/// so a fat-fingered `--slo-max-5xx-rate 50` (meaning 50%) can't silently become
/// an unreachable 5000% threshold that never fails.
fn parse_rate(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<f64, String> {
    let raw = next_val(it, flag)?;
    let v: f64 = raw.parse().map_err(|_| format!("invalid {flag}: {raw}"))?;
    if !(0.0..=1.0).contains(&v) {
        return Err(format!("{flag} must be a fraction 0.0–1.0 (got {raw})"));
    }
    Ok(v)
}

/// Tests for the operator-facing surface: argument parsing, the L3/L4 pre-traffic
/// gates, and the exit-code policy.
///
/// Every crate underneath this one is well covered, but the CLI is where an
/// operator's intent is turned into a `RunPlan` — and where the mandatory
/// acknowledgements, the allowlist and the SLO thresholds are read. A parser that
/// silently accepts a malformed threshold, or an outcome check that reports
/// success for a run that tested nothing, is a safety defect that no test below
/// this layer can catch.
#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a command line written the way an operator would type it.
    fn parse(argv: &[&str]) -> Result<Option<Args>, String> {
        parse_args_from(argv.iter().map(|s| s.to_string()))
    }

    /// Parse and unwrap, for the cases that must succeed.
    fn args_of(argv: &[&str]) -> Args {
        parse(argv).expect("should parse").expect("should not be --help")
    }

    fn gate_of(cidrs: &[&str]) -> Authorization {
        Authorization::new(Allowlist::from_cidrs(cidrs).unwrap(), KillSwitch::new())
    }

    // ---- defaults -------------------------------------------------------

    /// The defaults an operator inherits by not passing anything. `--rate 100`
    /// and L7 matter most: the quiet default must be the safe one.
    #[test]
    fn defaults_are_the_conservative_ones() {
        let a = args_of(&["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/"]);
        assert_eq!(a.rate, 100);
        assert_eq!(a.duration_secs, 10);
        assert!(matches!(a.layer, Layer::L7));
        assert!(!a.ack_lab, "the lab acknowledgement must never default to on");
        assert!(!a.no_audit, "opting out of the audit trail must never default to on");
        assert!(!a.dry_run);
        assert!(a.targets.is_empty());
        assert!(matches!(a.output, OutputForm::Human));
        assert_eq!(
            a.max_connections,
            jinrai_l7::DEFAULT_MAX_CONNS,
            "concurrency must default to a finite cap, not unbounded"
        );
    }

    #[test]
    fn the_lab_acknowledgement_accepts_the_old_spelling() {
        // Renaming the flag must not silently turn an acknowledged run in an
        // existing runbook into a refused one.
        for flag in ["--ack-lab", "--ack-l34-lab"] {
            let a = args_of(&["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/", flag]);
            assert!(a.ack_lab, "{flag} should set the acknowledgement");
        }
    }

    // ---- the allowlist, the gate's front door ---------------------------

    /// `--allow` is repeatable, and every rule must survive parsing verbatim —
    /// the allowlist is the whole safety model.
    #[test]
    fn allow_rules_accumulate_in_order() {
        let a = args_of(&[
            "--allow", "10.0.0.0/8",
            "--allow", "*.staging.internal",
            "--allow", "192.0.2.7",
            "--url", "http://10.1.2.3/",
        ]);
        assert_eq!(a.allow, ["10.0.0.0/8", "*.staging.internal", "192.0.2.7"]);
    }

    /// A flag whose value is missing must be an error, never a silent default or
    /// a panic — `--allow` swallowing the next flag would widen the allowlist.
    #[test]
    fn a_flag_without_its_value_is_refused() {
        for flag in ["--allow", "--url", "--rate", "--duration", "--target", "--port"] {
            let err = parse(&[flag]).unwrap_err();
            assert!(err.contains(flag), "{flag}: {err}");
        }
    }

    #[test]
    fn a_malformed_target_ip_is_refused() {
        let err = parse(&["--allow", "10.0.0.0/8", "--target", "10.1.2"]).unwrap_err();
        assert!(err.contains("invalid --target IP"), "{err}");
    }

    // ---- values that must not be silently accepted ----------------------

    /// Every numeric flag that something downstream allocates against, divides
    /// by, or adds to an `Instant` is bounded here. Unbounded, each of these
    /// reached a panic or an allocation the machine cannot serve — after the
    /// gate had passed and, for L3/L4, after the raw socket was open.
    #[test]
    fn absurd_numeric_flags_are_refused_at_the_front_door() {
        let base = ["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/"];
        for (flag, value) in [
            ("--rate", "99999999999"),
            ("--duration", "999999999999"),
            ("--concurrency", "99999999999"),
            ("--ramp-steps", "4000000000"),
            ("--slow-connections", "99999999999"),
            ("--max-connections", "99999999999"),
            ("--spike-secs", "999999999999"),
            ("--ramp-start", "99999999999"),
        ] {
            let mut argv = base.to_vec();
            argv.extend([flag, value]);
            let err = parse(&argv).unwrap_err();
            assert!(
                err.contains(flag) && err.contains("at most"),
                "{flag} {value} should be refused with a limit, got: {err}"
            );
        }
    }

    /// The limits are ceilings on typos, not on real runs: values an operator
    /// might plausibly want must still parse.
    #[test]
    fn realistic_numeric_flags_still_parse() {
        let a = args_of(&[
            "--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/",
            "--rate", "500000", "--duration", "3600", "--concurrency", "65536",
            "--ramp-steps", "500",
        ]);
        assert_eq!(a.rate, 500_000);
        assert_eq!(a.duration_secs, 3600);
        assert_eq!(a.concurrency, 65_536);
        assert_eq!(a.ramp_steps, 500);
    }

    /// Zero means "no pacing" for a drip and "hold nothing" for a slow-mode
    /// connection count — one turns a slow attack into an unpaced write flood,
    /// the other reports a clean run that tested nothing. Neither is what the
    /// operator meant, and 0 already means "unlimited" on `--max-connections`,
    /// so it must not be silently reinterpreted here.
    #[test]
    fn zero_is_refused_where_it_would_change_the_primitive() {
        let base = ["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/"];
        for flag in ["--drip-ms", "--slow-connections"] {
            let mut argv = base.to_vec();
            argv.extend([flag, "0"]);
            let err = parse(&argv).unwrap_err();
            assert!(err.contains(flag) && err.contains("at least 1"), "{flag}: {err}");
        }
    }

    // ---- load profiles fit inside the declared window -------------------

    /// `--duration` is the whole traffic window, including the spike. Adding the
    /// spike on top of it generated 40 seconds of traffic for a 30-second run —
    /// an undeclared window, which is exactly what the drain accounting exists
    /// to rule out.
    #[test]
    fn a_spike_is_carved_out_of_the_duration_not_added_to_it() {
        let a = args_of(&[
            "--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/",
            "--profile", "spike", "--duration", "30", "--spike-secs", "10",
        ]);
        let duration = Duration::from_secs(a.duration_secs);
        let profile = l7_profile(&a, RateCap::new(a.rate), duration).expect("spike profile");
        let total: Duration = profile.stages().iter().map(|s| s.duration).sum();
        assert_eq!(total, duration, "the stages must sum to exactly --duration");
    }

    /// A spike at least as long as the run is the whole run — never longer.
    #[test]
    fn an_oversized_spike_cannot_stretch_the_run() {
        let a = args_of(&[
            "--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/",
            "--profile", "spike", "--duration", "5", "--spike-secs", "600",
        ]);
        let duration = Duration::from_secs(a.duration_secs);
        let profile = l7_profile(&a, RateCap::new(a.rate), duration).expect("spike profile");
        let total: Duration = profile.stages().iter().map(|s| s.duration).sum();
        assert_eq!(total, duration);
    }

    /// The fat-finger guard: `--slo-max-5xx-rate 50` meaning "50%" must not
    /// become an unreachable 5000% threshold that can never fail. A run whose
    /// SLO cannot fail is a test that always passes.
    #[test]
    fn an_out_of_range_slo_threshold_is_refused() {
        for flag in ["--slo-max-error-rate", "--slo-max-5xx-rate", "--slo-max-4xx-rate"] {
            for value in ["50", "-0.1", "1.5"] {
                let err = parse(&["--allow", "10.0.0.0/8", flag, value]).unwrap_err();
                assert!(err.contains(flag), "{flag} {value}: {err}");
            }
            // The boundaries themselves are legitimate.
            for value in ["0", "0.05", "1"] {
                assert!(
                    parse(&["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/", flag, value])
                        .is_ok(),
                    "{flag} {value} should be accepted"
                );
            }
        }
    }

    /// An unrecognised mode name must be refused, not fall back to a default:
    /// silently running `udp` when the operator asked for `syn` would produce a
    /// confidently wrong result.
    #[test]
    fn unknown_enum_values_are_refused_rather_than_defaulted() {
        let cases: [(&str, &str); 4] = [
            ("--l4-mode", "sync"),
            ("--l7-method", "gett"),
            ("--http-version", "3"),
            ("--output", "json"),
        ];
        for (flag, bad) in cases {
            let err = parse(&["--allow", "10.0.0.0/8", flag, bad]).unwrap_err();
            assert!(err.contains(flag), "{flag} {bad}: {err}");
            assert!(err.contains(bad), "the error should quote the bad value: {err}");
        }
    }

    /// Every `--l7-method` the parser accepts must also be documented, and vice
    /// versa. The two lists drift silently: a method in the parser but not the
    /// help is unreachable in practice, one in the help but not the parser is a
    /// documented flag that errors out.
    #[test]
    fn every_l7_method_parses_and_is_documented() {
        for m in [
            "get", "post", "head", "slowloris", "slowbody", "slow-read", "h2-rapid-reset",
            "h2-continuation", "tls-handshake", "h2-settings", "h2-ping", "h2-window-update",
            "h2-priority", "h2-made-you-reset", "h2-empty-data", "h2-bomb", "websocket", "sse",
            "tls-big-hello", "tls-sni-bomb",
        ] {
            let argv =
                ["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/", "--l7-method", m];
            assert!(parse(&argv).is_ok(), "--l7-method {m} should parse");
            assert!(USAGE.contains(m), "help must document --l7-method {m}");
        }
    }

    /// The long-lived transports route to their own engine rather than being
    /// quietly served by the fast request flood.
    #[test]
    fn websocket_and_sse_select_the_long_lived_engine() {
        let base = ["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/", "--l7-method"];
        for (method, want) in
            [("websocket", LongLivedKind::WebSocket), ("sse", LongLivedKind::Sse)]
        {
            let mut argv = base.to_vec();
            argv.push(method);
            match args_of(&argv).l7_kind {
                L7Kind::LongLived(got) => assert_eq!(got, want, "{method}"),
                other => panic!("{method} selected {other:?}"),
            }
        }
    }

    /// `--layer` accepts the spellings the README and the help text use.
    #[test]
    fn layer_and_mode_spellings_operators_actually_type() {
        assert!(matches!(args_of(&["--allow", "1.2.3.4", "--layer", "l4"]).layer, Layer::L4));
        assert!(matches!(args_of(&["--allow", "1.2.3.4", "--layer", "l7"]).layer, Layer::L7));
        // `l3` is accepted too and routes to the same module — the README and the
        // cookbook both say "l3/l4", so the help text has to admit it exists.
        assert!(matches!(args_of(&["--allow", "1.2.3.4", "--layer", "l3"]).layer, Layer::L3));
        assert!(USAGE.contains("--layer <l3|l4|l7>"), "help must document the l3 spelling");
        let a = args_of(&["--allow", "1.2.3.4", "--l4-mode", "icmp-timestamp"]);
        assert!(matches!(a.l4_mode, L4Mode::IcmpTimestamp));
        // Every raw-TCP flag mode the help text lists must actually parse — a mode
        // documented but not wired is indistinguishable, to an operator, from one
        // that "doesn't work".
        for (spelling, expected) in [
            ("syn", L4Mode::Syn),
            ("ack", L4Mode::Ack),
            ("fin", L4Mode::Fin),
            ("rst", L4Mode::Rst),
            ("urg", L4Mode::Urg),
            ("cwr", L4Mode::Cwr),
            ("ece", L4Mode::Ece),
            ("syn-ack", L4Mode::SynAck),
            ("syn-fin", L4Mode::SynFin),
            ("syn-rst", L4Mode::SynRst),
            ("xmas", L4Mode::Xmas),
            ("null", L4Mode::Null),
            ("tcp-options", L4Mode::TcpOptions),
        ] {
            let a = args_of(&["--allow", "1.2.3.4", "--l4-mode", spelling]);
            assert_eq!(a.l4_mode, expected, "--l4-mode {spelling}");
            assert!(USAGE.contains(spelling), "help must document --l4-mode {spelling}");
        }
    }

    /// `--help` must be a successful no-op, not an error and not a run.
    #[test]
    fn help_requests_nothing_to_run() {
        assert!(parse(&["--help"]).unwrap().is_none());
        assert!(parse(&["-h"]).unwrap().is_none());
    }

    /// Zeros that the code silently reinterpreted into something else. Each one
    /// is a value the operator typed and did not get: `--port 0` became port 1 in
    /// the packet builder, `--concurrency 0` was clamped to 1. The rest of the
    /// parser refuses meaningless zeros; these two were the exceptions.
    #[test]
    fn zero_valued_flags_are_refused_rather_than_reinterpreted() {
        let base = ["--allow", "10.0.0.0/8", "--layer", "l4", "--target", "10.1.2.3"];
        for (flag, value) in [("--port", "0"), ("--concurrency", "0")] {
            let mut argv: Vec<&str> = base.to_vec();
            argv.extend([flag, value]);
            let err = parse(&argv).expect_err(&format!("{flag} 0 must be refused"));
            assert!(err.contains(flag), "the refusal must name the flag: {err}");
        }
        // The same flags with a meaningful value still parse.
        let mut argv: Vec<&str> = base.to_vec();
        argv.extend(["--port", "80", "--concurrency", "8"]);
        let a = args_of(&argv);
        assert_eq!(a.port.as_deref(), Some("80"));
        assert_eq!(a.concurrency, 8);
    }

    /// A malformed `--port` spec must be refused while parsing arguments, not
    /// discovered later. The spec decides where every packet of the run goes,
    /// so "it turned out to be nonsense" is not something to learn after the
    /// lab acknowledgement and the audit record are already behind us.
    #[test]
    fn port_specs_are_validated_at_parse_time() {
        let base = ["--allow", "10.0.0.0/8", "--layer", "l4", "--target", "10.1.2.3"];
        for spec in ["0", "80,0", "100-80", "80,,443", "http", "70000"] {
            let mut argv: Vec<&str> = base.to_vec();
            argv.extend(["--port", spec]);
            assert!(parse(&argv).is_err(), "--port {spec:?} must be refused");
        }
        for spec in ["443", "80,443,8080", "1000-2000", "80,8000-8100"] {
            let mut argv: Vec<&str> = base.to_vec();
            argv.extend(["--port", spec]);
            assert_eq!(args_of(&argv).port.as_deref(), Some(spec));
        }
    }

    /// `--port-order` defaults to the deterministic walk, so a command line that
    /// worked before port sets existed still produces the same traffic.
    #[test]
    fn port_order_defaults_to_sequential_and_rejects_unknown_values() {
        let base = ["--allow", "10.0.0.0/8", "--layer", "l4", "--target", "10.1.2.3"];
        let mut argv: Vec<&str> = base.to_vec();
        argv.extend(["--port", "1000-2000"]);
        assert_eq!(args_of(&argv).port_order, PortOrder::Sequential);

        let mut argv: Vec<&str> = base.to_vec();
        argv.extend(["--port", "1000-2000", "--port-order", "random"]);
        assert_eq!(args_of(&argv).port_order, PortOrder::Random);

        let mut argv: Vec<&str> = base.to_vec();
        argv.extend(["--port", "1000-2000", "--port-order", "shuffle"]);
        let err = parse(&argv).expect_err("an unknown order must be refused");
        assert!(err.contains("--port-order"), "the refusal must name the flag: {err}");
    }

    /// Two flags giving opposite instructions about whether the run is on the
    /// record. `--audit-log` used to win and the opt-out was dropped in silence.
    #[test]
    fn no_audit_and_audit_log_together_are_refused() {
        let err = parse(&[
            "--allow",
            "10.0.0.0/8",
            "--url",
            "http://10.1.2.3/",
            "--no-audit",
            "--audit-log",
            "/tmp/jinrai-test.log",
        ])
        .expect_err("contradictory audit flags must be refused");
        assert!(err.contains("--no-audit"), "{err}");
        assert!(err.contains("--audit-log"), "{err}");
    }

    /// The last two numeric flags that parsed straight into their types with no
    /// ceiling. The window becomes a `Duration` added to an `Instant`.
    #[test]
    fn watchdog_flags_are_capped_like_every_other_numeric() {
        let base = ["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/"];
        for (flag, value) in
            [("--watchdog-window", "999999999"), ("--watchdog-breaches", "999999999")]
        {
            let mut argv: Vec<&str> = base.to_vec();
            argv.extend([flag, value]);
            let err = parse(&argv).expect_err(&format!("{flag} must be capped"));
            assert!(err.contains("at most"), "the refusal must name the ceiling: {err}");
        }
    }

    // ---- the pre-traffic gates, every layer -----------------------------

    /// The mandatory lab acknowledgement, asserted against fully-formed,
    /// otherwise-valid invocations of BOTH layers. l7 is the one that regressed
    /// into firing unconfirmed, so it is the one that matters most here.
    #[test]
    fn no_layer_emits_traffic_without_the_lab_acknowledgement() {
        let l7 = args_of(&["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/"]);
        let l4 = args_of(&[
            "--allow", "127.0.0.0/8", "--layer", "l4",
            "--target", "127.0.0.1", "--port", "9",
        ]);
        for a in [&l7, &l4] {
            let err = lab_ack_required(a).unwrap_err();
            assert!(err.contains("--ack-lab"), "{err}");
        }

        let acked = args_of(&[
            "--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/", "--ack-lab",
        ]);
        assert!(lab_ack_required(&acked).is_ok());
    }

    /// A dry run sends nothing, so neither gate applies to it — that is what
    /// makes it the way to check a command line you are not yet sure of.
    #[test]
    fn a_dry_run_is_exempt_from_both_pre_traffic_gates() {
        let a = args_of(&["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/", "--dry-run"]);
        assert!(lab_ack_required(&a).is_ok());
        assert!(audit_trail_required(&a).is_ok());
    }

    /// Omitting `--audit-log` used to mean "this run leaves no trace", silently.
    /// Now it has to be said.
    #[test]
    fn a_live_run_needs_a_trail_or_an_explicit_opt_out() {
        let base = ["--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/", "--ack-lab"];
        let err = audit_trail_required(&args_of(&base)).unwrap_err();
        assert!(err.contains("--audit-log"), "{err}");
        assert!(err.contains("--no-audit"), "{err}");

        let logged =
            args_of(&[&base[..], &["--audit-log", "/tmp/jinrai-test.jsonl"]].concat());
        assert!(audit_trail_required(&logged).is_ok());

        let opted_out = args_of(&[&base[..], &["--no-audit"]].concat());
        assert!(audit_trail_required(&opted_out).is_ok());
    }

    /// A flag given twice used to let the last value win in silence. For a
    /// safety ceiling that is the wrong way to be quiet: the operator's shell
    /// history shows a value they did not get.
    #[test]
    fn a_scalar_flag_given_twice_is_refused_rather_than_last_wins() {
        let err = parse(&[
            "--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/",
            "--rate", "100", "--rate", "5000",
        ])
        .unwrap_err();
        assert!(err.contains("--rate"), "{err}");
        assert!(err.contains("more than once"), "{err}");

        // The repeatable flags are the interface, not a mistake.
        let a = args_of(&[
            "--allow", "10.0.0.0/8", "--allow", "192.168.0.0/16",
            "--url", "http://10.1.2.3/",
            "--header", "A: 1", "--header", "B: 2",
        ]);
        assert_eq!(a.allow.len(), 2);
        assert_eq!(a.headers.len(), 2);
    }

    /// A missing value used to swallow the following flag, so the typo surfaced
    /// later as an unrelated failure.
    #[test]
    fn a_flag_is_never_silently_consumed_as_another_flags_value() {
        let err = parse(&[
            "--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/",
            "--audit-log", "--ack-lab",
        ])
        .unwrap_err();
        assert!(err.contains("--audit-log"), "{err}");
        assert!(err.contains("--ack-lab"), "{err}");

        // A value that genuinely starts with `-` is still reachable.
        let a = args_of(&[
            "--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/",
            "--audit-log", "./-weird.jsonl",
        ]);
        assert_eq!(a.audit_log.as_deref(), Some("./-weird.jsonl"));
    }

    /// `--rate` is documented as a ceiling every profile stays under. A profile
    /// floor above it is a contradiction, refused at the front door rather than
    /// left to one `clamped_to` deep in the engine.
    #[test]
    fn a_profile_floor_above_the_rate_ceiling_is_refused() {
        let err = parse(&[
            "--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/",
            "--rate", "100", "--ramp-start", "500",
        ])
        .unwrap_err();
        assert!(err.contains("--ramp-start"), "{err}");

        let err = parse(&[
            "--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/",
            "--rate", "100", "--spike-base", "500",
        ])
        .unwrap_err();
        assert!(err.contains("--spike-base"), "{err}");

        // At or below the ceiling is a legitimate shape and must still parse.
        assert!(parse(&[
            "--allow", "10.0.0.0/8", "--url", "http://10.1.2.3/",
            "--rate", "100", "--ramp-start", "100",
        ])
        .is_ok());
    }

    /// An L4 run needs a target and (outside ICMP) a port. Both refusals must
    /// also land before any traffic.
    #[test]
    fn l4_refuses_a_run_it_cannot_aim() {
        let no_target = args_of(&[
            "--allow", "127.0.0.0/8", "--layer", "l4", "--ack-l34-lab", "--port", "9",
        ]);
        let err = run_l4(
            &no_target,
            gate_of(&["127.0.0.0/8"]),
            KillSwitch::new(),
            RateCap::new(1),
            Duration::from_secs(1),
            None,
        )
        .unwrap_err();
        assert!(err.contains("--target"), "{err}");

        let no_port = args_of(&[
            "--allow", "127.0.0.0/8", "--layer", "l4", "--ack-l34-lab",
            "--target", "127.0.0.1",
        ]);
        let err = run_l4(
            &no_port,
            gate_of(&["127.0.0.0/8"]),
            KillSwitch::new(),
            RateCap::new(1),
            Duration::from_secs(1),
            None,
        )
        .unwrap_err();
        assert!(err.contains("--port"), "{err}");
    }

    // ---- exit-code policy ------------------------------------------------

    /// A run that completed nothing must not exit 0: "6000 attempts, 0
    /// responses" reported as success is a green pipeline for a test that never
    /// happened.
    #[test]
    fn a_run_that_tested_nothing_is_a_failure() {
        let dead = RunReport { units_sent: 0, errors: 40, ..Default::default() };
        assert!(check_l7_outcome(&dead, None).is_err());
        assert!(check_l4_outcome(&dead).is_err());
    }

    /// `--rate 0` is a deliberate no-op, not a failure: nothing was attempted, so
    /// there is nothing to report as broken.
    #[test]
    fn a_zero_rate_run_is_not_a_failure() {
        let nothing = RunReport { units_sent: 0, errors: 0, ..Default::default() };
        assert!(check_l4_outcome(&nothing).is_ok());
        assert!(check_l7_outcome(&nothing, None).is_ok());
    }

    /// A watchdog abort means the target buckled under load — the run did its
    /// job, and the exit code has to say the target failed.
    #[test]
    fn a_watchdog_abort_exits_non_zero() {
        let tripped = RunReport {
            units_sent: 100,
            aborted_by_watchdog: true,
            ..Default::default()
        };
        assert!(check_l7_outcome(&tripped, None).is_err());
    }

    /// An operator Ctrl-C is not a test failure: they stopped it on purpose.
    #[test]
    fn an_operator_abort_is_not_a_failure() {
        let stopped = RunReport {
            units_sent: 100,
            aborted_early: true,
            ..Default::default()
        };
        assert!(check_l7_outcome(&stopped, None).is_ok());
    }
}

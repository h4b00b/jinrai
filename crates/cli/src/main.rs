//! jinrai CLI — Phase 1 operator entry point.
//!
//! Wires the safety gate to the (stub) traffic modules end-to-end:
//!   1. Parse the operator-supplied allowlist (`--allow <CIDR>`, repeatable).
//!   2. Parse targets (`--target <IP>`, repeatable).
//!   3. Authorize every target through the gate — refuse the whole run if any
//!      target is not allowlisted (fail-closed).
//!   4. Build a `RunPlan` and hand it to the selected module.
//!
//! Because the modules are still stubs, no traffic is emitted yet; this proves
//! the safety wiring works before real generation lands.

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

use jinrai_core::{
    Layer, LoadProfile, RateCap, RunPlan, RunReport, SloSpec, SloVerdict, StressModule,
};
use jinrai_l34::{L34Config, L34Engine, L4Mode};
use jinrai_l7::{L7Engine, L7Method, L7SlowEngine, RequestSpec, SlowConfig, SlowMode, WatchdogConfig};
use jinrai_metrics::{AuditEvent, AuditLog};
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
    --port <N>         Target port (required for l3/l4).
    --ack-l34-lab      REQUIRED acknowledgement that this L3/L4 run targets an
                       authorized, isolated-lab network. No traffic without it.

OPTIONS:
    --layer <l4|l7>       Module to run (default: l7)
    --l4-mode <MODE>      L3/L4 primitive (default: udp). One of:
                            udp | tcp            no privilege needed
                            syn | ack | fin | rst  raw TCP flag floods; each sets
                                                 one flag, needs CAP_NET_RAW/root,
                                                 IPv4-only, real source IP (never
                                                 spoofed)
    --l7-method <METHOD>  L7 primitive (default: get). One of:
                            get | post | head   fast request flood
                            slowloris            slow partial headers (Slowloris)
                            slowbody             slow trickled POST body (RUDY)
                          For slow modes the rate cap is connections-opened/sec,
                          and https targets are supported (slow-TLS; the handshake
                          accepts any server certificate — see README).
    --body <STRING>       Request body sent with each POST (l7-method post)
    --cache-bust          Append a unique _cb=<n> query to every l7 request so
                          caches/CDNs cannot serve a stored response (query only;
                          the host is never altered)
    --slow-connections <N>  Concurrent connection ceiling for slow modes (default: 100)
    --drip-ms <MS>        Keep-alive write interval for slow modes (default: 10000)
    --payload-size <N>    UDP payload bytes (default: 64, l4-mode udp)
    --rate <N>            Rate cap, units/sec (default: 100). This is a hard
                          SAFETY CEILING: every load profile shapes traffic only
                          UP TO this rate, never above it.
    --duration <SECS>     Run duration (default: 10)
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
    --spike-secs <SECS>   Spike peak duration (default: 10)
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
    --audit-log <PATH>    Append a tamper-evident audit record for this run to
                          PATH (authorized/completed/refused). Operator identity
                          comes from $JINRAI_OPERATOR (else the OS user).
    -h, --help            Show this help

AUDIT:
    --verify-audit <PATH> Verify the hash chain of an existing audit log and exit
                          (0 = intact, non-zero = tampered/corrupt). Runs nothing.
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

struct Args {
    allow: Vec<String>,
    targets: Vec<IpAddr>,
    url: Option<String>,
    headers: Vec<(String, String)>,
    l7_kind: L7Kind,
    body: Option<String>,
    cache_bust: bool,
    slow_connections: usize,
    drip_ms: u64,
    layer: Layer,
    l4_mode: L4Mode,
    port: Option<u16>,
    payload_size: usize,
    ack_l34_lab: bool,
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

fn run() -> Result<(), String> {
    let args = parse_args()?;

    // A verify-only invocation checks an existing log's integrity and exits
    // without touching the allowlist, the gate, or any traffic path.
    if let Some(path) = &args.verify_audit {
        let n = jinrai_metrics::verify(path).map_err(|e| e.to_string())?;
        println!("audit log OK: {n} record(s), hash chain intact ({path})");
        return Ok(());
    }

    // Open the audit log (if requested) up front so an unusable log aborts the
    // run BEFORE any authorization or traffic — no untracked runs.
    let operator = operator_identity();
    let mut audit = match &args.audit_log {
        Some(path) => Some(AuditLog::open(path, &operator).map_err(|e| e.to_string())?),
        None => None,
    };

    // 1. Build the allowlist from operator parameters (mixed CIDRs + DNS names).
    let allowlist = Allowlist::from_patterns(&args.allow)
        .map_err(|e| format!("bad --allow value: {e}"))?;
    if allowlist.is_empty() {
        return Err("no --allow rules given; refusing to run (fail-closed)".into());
    }

    // 2. The gate. Kill switch is shared with the run plan.
    let kill = KillSwitch::new();

    // Wire Ctrl-C to the shared kill-switch so an operator can abort a live run
    // gracefully: workers poll it and stop within ~50ms, and the run reports what
    // it managed to send. Without this, the advertised abort control is inert.
    {
        let kill = kill.clone();
        if let Err(e) = ctrlc::set_handler(move || kill.trip()) {
            eprintln!("warning: could not install Ctrl-C abort handler: {e}");
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
            Some(LoadProfile::Spike {
                base: RateCap::new(base),
                peak: rate_cap,
                base_total: duration,
                spike: Duration::from_secs(args.spike_secs),
            })
        }
        // Constant / Soak: flat at the ceiling — use the engine default.
        ProfileKind::Constant | ProfileKind::Soak => None,
        // Ramp handled above.
        ProfileKind::Ramp => unreachable!("ramp handled above"),
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
    let url = args
        .url
        .clone()
        .ok_or("--layer l7 requires --url <URL>")?;

    // Phase-6 profile validation, fail-closed before any traffic: knee discovery
    // is meaningless without a rate SLO to detect the breaking point against.
    if args.discover_knee && !args.slo.has_rate_thresholds() {
        return Err("--discover-knee needs a rate SLO to detect the knee \
                    (add e.g. --slo-max-5xx-rate or --slo-max-error-rate)"
            .into());
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
            };
            let mut engine = L7Engine::new(gate, spec).with_slo(args.slo);
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
    // never receive a response to classify. Warn rather than silently ignore.
    if matches!(args.l7_kind, L7Kind::Slow(_)) && !args.slo.is_empty() {
        eprintln!("warning: --slo-* / --watchdog are ignored for slow-connection methods (no response to classify)");
    } else if args.watchdog && !args.slo.has_rate_thresholds() {
        eprintln!("warning: --watchdog is inert without a --slo-max-*-rate to watch");
    }
    // Load profiles / knee discovery only shape the fast request-flood dispatch.
    if matches!(args.l7_kind, L7Kind::Slow(_))
        && (args.discover_knee || args.profile != ProfileKind::Constant)
    {
        eprintln!("warning: load profiles / --discover-knee apply to fast l7 methods only; ignored for slow-connection modes");
    }

    let plan = RunPlan { targets, rate_cap, duration, kill };
    println!("running module '{}' ({:?})...", engine.name(), engine.layer());
    let report = engine.execute(&plan);
    println!("{}", jinrai_metrics::render(&report));

    // A knee-discovery run reports the breaking point, not a pass/fail verdict:
    // reaching a breach is the goal, so the SLO here is the probe, not a target.
    if args.discover_knee {
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
        audit_record(&mut audit, AuditEvent::completed(&report, None))?;
        // Discovery succeeds whether or not a knee was found (an operator Ctrl-C
        // still aborts); it is not a pass/fail run.
        return Ok(());
    }

    // Evaluate the SLO verdict (only when the operator declared one, and only for
    // fast methods that produced a classification).
    let verdict = if !args.slo.is_empty() && matches!(args.l7_kind, L7Kind::Fast(_)) {
        let v = args.slo.evaluate(&report);
        println!("{}", jinrai_metrics::render_verdict(&v));
        Some(v)
    } else {
        None
    };

    audit_record(&mut audit, AuditEvent::completed(&report, verdict.as_ref()))?;
    check_l7_outcome(&report, verdict.as_ref())
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
    // Explicit, mandatory acknowledgement — in addition to the allowlist.
    if !args.ack_l34_lab {
        return Err(
            "refusing L3/L4 run: pass --ack-l34-lab to confirm this targets an \
             authorized, isolated-lab network"
                .into(),
        );
    }
    if args.targets.is_empty() {
        return Err("--layer l3/l4 requires at least one --target <IP>".into());
    }
    let port = args
        .port
        .ok_or("--layer l3/l4 requires --port <N>")?;

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
        port,
        payload_size: args.payload_size,
    });

    // Record the authorized run (targets + rules + params) before any traffic.
    audit_record(
        &mut audit,
        AuditEvent::RunAuthorized {
            layer: format!("{:?}", module.layer()),
            mode: module.name().to_string(),
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
    println!("running module '{}' ({:?})...", module.name(), module.layer());
    let report = module.execute(&plan);
    println!("{}", jinrai_metrics::render(&report));
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

fn parse_args() -> Result<Args, String> {
    let mut allow = Vec::new();
    let mut targets = Vec::new();
    let mut url = None;
    let mut headers = Vec::new();
    let mut l7_kind = L7Kind::Fast(L7Method::Get);
    let mut body = None;
    let mut cache_bust = false;
    let mut slow_connections = 100usize;
    let mut drip_ms = 10_000u64;
    let mut layer = Layer::L7;
    let mut l4_mode = L4Mode::Udp;
    let mut port = None;
    let mut payload_size = 64usize;
    let mut ack_l34_lab = false;
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

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
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
                    other => {
                        return Err(format!(
                            "unknown --l7-method: {other} (want get|post|head|slowloris|slowbody)"
                        ))
                    }
                }
            }
            "--body" => body = Some(next_val(&mut it, "--body")?),
            "--cache-bust" => cache_bust = true,
            "--slow-connections" => {
                slow_connections = next_val(&mut it, "--slow-connections")?
                    .parse()
                    .map_err(|_| "invalid --slow-connections".to_string())?;
            }
            "--drip-ms" => {
                drip_ms = next_val(&mut it, "--drip-ms")?
                    .parse()
                    .map_err(|_| "invalid --drip-ms".to_string())?;
            }
            "--l4-mode" => {
                l4_mode = match next_val(&mut it, "--l4-mode")?.as_str() {
                    "udp" => L4Mode::Udp,
                    "tcp" => L4Mode::TcpConnect,
                    "syn" => L4Mode::Syn,
                    "ack" => L4Mode::Ack,
                    "fin" => L4Mode::Fin,
                    "rst" => L4Mode::Rst,
                    other => {
                        return Err(format!(
                            "unknown --l4-mode: {other} (want udp|tcp|syn|ack|fin|rst)"
                        ))
                    }
                }
            }
            "--port" => {
                port = Some(
                    next_val(&mut it, "--port")?
                        .parse()
                        .map_err(|_| "invalid --port".to_string())?,
                );
            }
            "--payload-size" => {
                payload_size = next_val(&mut it, "--payload-size")?
                    .parse()
                    .map_err(|_| "invalid --payload-size".to_string())?;
            }
            "--ack-l34-lab" => ack_l34_lab = true,
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
            "--rate" => {
                rate = next_val(&mut it, "--rate")?
                    .parse()
                    .map_err(|_| "invalid --rate".to_string())?;
            }
            "--duration" => {
                duration_secs = next_val(&mut it, "--duration")?
                    .parse()
                    .map_err(|_| "invalid --duration".to_string())?;
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
            "--ramp-start" => {
                ramp_start = next_val(&mut it, "--ramp-start")?
                    .parse()
                    .map_err(|_| "invalid --ramp-start".to_string())?;
            }
            "--ramp-steps" => {
                ramp_steps = next_val(&mut it, "--ramp-steps")?
                    .parse()
                    .map_err(|_| "invalid --ramp-steps".to_string())?;
            }
            "--spike-base" => {
                spike_base = Some(
                    next_val(&mut it, "--spike-base")?
                        .parse()
                        .map_err(|_| "invalid --spike-base".to_string())?,
                );
            }
            "--spike-secs" => {
                spike_secs = next_val(&mut it, "--spike-secs")?
                    .parse()
                    .map_err(|_| "invalid --spike-secs".to_string())?;
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
            "--watchdog-window" => {
                watchdog_window_secs = next_val(&mut it, "--watchdog-window")?
                    .parse()
                    .map_err(|_| "invalid --watchdog-window".to_string())?;
            }
            "--watchdog-breaches" => {
                watchdog_breaches = next_val(&mut it, "--watchdog-breaches")?
                    .parse()
                    .map_err(|_| "invalid --watchdog-breaches".to_string())?;
            }
            "--audit-log" => audit_log = Some(next_val(&mut it, "--audit-log")?),
            "--verify-audit" => verify_audit = Some(next_val(&mut it, "--verify-audit")?),
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }

    Ok(Args {
        allow,
        targets,
        url,
        headers,
        l7_kind,
        body,
        cache_bust,
        slow_connections,
        drip_ms,
        layer,
        l4_mode,
        port,
        payload_size,
        ack_l34_lab,
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
    })
}

fn next_val(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
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

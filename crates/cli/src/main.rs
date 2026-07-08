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

use jinrai_core::{Layer, RateCap, RunPlan, RunReport, StressModule};
use jinrai_l34::{L34Config, L34Engine, L4Mode};
use jinrai_l7::{L7Engine, RequestSpec};
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
    --l4-mode <udp|tcp|syn>  L3/L4 primitive (default: udp). 'syn' needs CAP_NET_RAW/root.
    --payload-size <N>    UDP payload bytes (default: 64, l4-mode udp)
    --rate <N>            Rate cap, units/sec (default: 100)
    --duration <SECS>     Run duration (default: 10)
    --header <K: V>       Extra request header for l7 (repeatable)
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

struct Args {
    allow: Vec<String>,
    targets: Vec<IpAddr>,
    url: Option<String>,
    headers: Vec<(String, String)>,
    layer: Layer,
    l4_mode: L4Mode,
    port: Option<u16>,
    payload_size: usize,
    ack_l34_lab: bool,
    rate: u64,
    duration_secs: u64,
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

    let spec = RequestSpec { url: url.clone(), headers: args.headers.clone() };
    let mut engine = L7Engine::new(gate, spec);

    // Authorize the datum up front so we can fail-closed with a clear message
    // and a non-zero exit BEFORE any traffic is generated.
    let targets = match engine.authorize_target() {
        Ok(t) => t,
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

    let plan = RunPlan { targets, rate_cap, duration, kill };
    println!("running module '{}' ({:?})...", engine.name(), engine.layer());
    let report = engine.execute(&plan);
    println!("{}", jinrai_metrics::render(&report));
    audit_record(&mut audit, AuditEvent::completed(&report))?;
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
    audit_record(&mut audit, AuditEvent::completed(&report))?;

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
    let mut layer = Layer::L7;
    let mut l4_mode = L4Mode::Udp;
    let mut port = None;
    let mut payload_size = 64usize;
    let mut ack_l34_lab = false;
    let mut rate = 100u64;
    let mut duration_secs = 10u64;
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
            "--l4-mode" => {
                l4_mode = match next_val(&mut it, "--l4-mode")?.as_str() {
                    "udp" => L4Mode::Udp,
                    "tcp" => L4Mode::TcpConnect,
                    "syn" => L4Mode::Syn,
                    other => return Err(format!("unknown --l4-mode: {other} (want udp|tcp|syn)")),
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
        layer,
        l4_mode,
        port,
        payload_size,
        ack_l34_lab,
        rate,
        duration_secs,
        audit_log,
        verify_audit,
    })
}

fn next_val(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

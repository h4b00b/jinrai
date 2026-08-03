//! # jinrai-l34 — L3/L4 traffic generation (isolated-lab use only)
//!
//! Direct stress primitives against **allowlisted** targets:
//!   - **UDP flood** — datagrams to `target:port` (no privilege needed);
//!   - **TCP connect flood** — full-handshake connections held open to exercise
//!     the connection table / backlog (no privilege needed);
//!   - **TCP flag floods** — crafted IPv4+TCP packets with a single control flag
//!     set (SYN / ACK / FIN / RST / URG / CWR / ECE), plus the unsolicited
//!     `syn-ack` handshake response, via a raw socket (requires
//!     `CAP_NET_RAW`/root). SYN exercises the accept backlog; ACK/FIN/RST exercise
//!     the target's connection-tracking / stateful-firewall state for packets
//!     outside an established connection; URG/CWR/ECE are otherwise-empty segments
//!     carrying only an urgent or ECN congestion bit, probing how the stack and
//!     any middlebox treat these rarely-standalone flags; `syn-ack` is a legal
//!     handshake response that answers a SYN the target never sent, so every
//!     packet must be matched against connection state (or RST'd).
//!   - **Anomalous flag-combination floods** — segments whose flag field matches
//!     no RFC-legal state: `xmas` (FIN+PSH+URG), `null` (no flags), and the
//!     mutually-contradictory `syn-fin` and `syn-rst` combinations. These probe
//!     stateful-firewall / IDS / TCP-stack handling of illegal control fields.
//!   - **TCP-options bomb** — a SYN flood whose every packet carries the full
//!     40-byte maximum of TCP options (MSS + SACK-permitted + timestamp + window
//!     scale, NOP-padded to the limit), forcing the target's TCP stack to parse a
//!     maximal option block and allocate SACK/timestamp state per SYN. Same raw
//!     socket / real-source / IPv4-only constraints as the flag floods.
//!   - **ICMP echo flood** — L3 ICMPv4 echo-request packets via a raw socket
//!     (requires `CAP_NET_RAW`/root). The kernel writes the IPv4 header, so the
//!     source is the real address — the same no-spoofing property as the rest.
//!   - **Fragmentation floods** — a UDP datagram or a TCP SYN cut into IPv4
//!     fragments, so the target must hold reassembly state per datagram and
//!     cannot read the ports (or, for the SYN, the control flags) until it has
//!     all the pieces. One unit is one datagram, two or three packets.
//!   - **GRE flood** — IP protocol 47 packets wrapping a real IPv4/UDP datagram,
//!     exercising a target's decapsulation path. The encapsulated packet carries
//!     the host's own source address too: the no-spoofing guarantee does not stop
//!     at the tunnel header.
//!
//! ## Non-negotiable guardrail: no source spoofing
//!
//! Every primitive sends from the host's **real** outbound address. The SYN
//! builder obtains the source IP by asking the OS which local address routes to
//! the target (a connected UDP socket's `local_addr()`), never by forging one.
//! There is deliberately **no** API anywhere to set, randomise, or spoof the
//! source address, and no reflection/amplification capability. This keeps the
//! tool a direct self-test, not a DDoS/reflection weapon.
//!
//! That guarantee is a property of one short module — [`packet`] — which is
//! where every byte below the socket API is constructed. It is kept separate
//! precisely so a reviewer can confirm the no-spoofing claim without reading an
//! engine.
//!
//! Targets are always [`AuthorizedTarget`]s that passed the gate as IP data
//! (`as_ip()`); a host-name datum is rejected here (L3/L4 is IP-only).
//!
//! ## Layout
//!
//! | module | holds |
//! |---|---|
//! | [`mode`] | which primitive a run drives, and its configuration — pure data, no sockets |
//! | [`packet`] | packet construction for the raw modes: **the no-spoofing surface** |
//! | [`pace`] | turning `--rate` into a schedule the send loop can keep |
//! | this file | the engine: authorization checks, the send loop, the socket senders, the tally |

#![forbid(unsafe_code)]

mod mode;
mod pace;
mod packet;
mod ports;

pub use mode::{L34Config, L4Mode, DEFAULT_CONCURRENCY, DEFAULT_CONNECT_TIMEOUT};
pub use ports::{PortOrder, PortSet, Rng};

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use jinrai_core::{
    ErrnoBucket, ErrnoTally, Layer, ModuleError, RateCap, RunPlan, RunReport, StressModule,
};

use crate::mode::{IcmpQuery, TcpFlags};
use crate::pace::{batch_for, interruptible_sleep};
use crate::packet::IPPROTO_RAW;
use crate::packet::{
    build_gre_packet, build_icmp_query, build_tcp_fragments, build_tcp_options_syn,
    build_tcp_packet, build_udp_fragments, source_ipv4_for,
};

/// What one emission attempt produced.
enum Emission {
    /// The unit went out. `latency` is `Some` only for attempts with an
    /// observable completion — the TCP handshake, timed from initiation to
    /// resolution. A fire-and-forget packet send (UDP / raw / ICMP) has no
    /// completion to observe, so it reports `None` rather than a meaningless 0.
    Sent { latency: Option<Duration> },
    /// The attempt failed, bucketed by the OS error behind it.
    Failed(ErrnoBucket),
    /// The attempt is in flight on a worker and will be counted when it resolves.
    /// Only the pooled connect flood produces this; every other mode resolves
    /// inline.
    Deferred,
    /// The attempt was never admitted: every in-flight slot was busy and nothing
    /// could be evicted, so this unit was never offered to the target.
    ///
    /// Distinct from [`Emission::Deferred`], which the two shared a variant with
    /// until it became clear they are opposite claims — deferred load lands and is
    /// counted later, dropped load never existed. Merged, a saturated pool
    /// produced a run whose summary was indistinguishable from a target that
    /// absorbed everything.
    Dropped,
}

/// Classify an I/O failure into a reporting bucket. Thin alias for the shared
/// classifier in `core`, which the L7 engine uses too so both layers bucket the
/// same OS failure identically.
fn classify_io(e: &std::io::Error) -> ErrnoBucket {
    ErrnoBucket::from_io_error(e)
}

/// Why an L3/L4 run could not be prepared or fully run. Fail-closed.
#[derive(Debug)]
pub enum L34Error {
    /// The plan contained no IP targets (e.g. only host-name data). L3/L4 is IP-only.
    NoIpTargets,
    /// An IPv6 target was given to a primitive that can only reach IPv4 (UDP flood
    /// binds an IPv4 socket; the SYN builder is IPv4-only). Fail-closed rather than
    /// spin a full run emitting only errors: [`L4Mode::TcpConnect`] handles IPv6.
    Ipv6Unsupported { mode: L4Mode, ip: IpAddr },
    /// A raw-TCP flood mode was asked for an IPv6 target; only IPv4 is implemented.
    Ipv6RawTcpUnsupported(IpAddr),
    /// The raw socket could not be created (usually missing CAP_NET_RAW/root).
    RawSocket(String),
    /// A socket setup step failed.
    Setup(String),
    /// Building the raw TCP packet failed.
    Build(String),
}

impl std::fmt::Display for L34Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L34Error::NoIpTargets => {
                write!(f, "no IP targets in plan (L3/L4 is IP-only; host-name data is not accepted)")
            }
            L34Error::Ipv6Unsupported { mode, ip } => write!(
                f,
                "{} cannot target IPv6 address {ip}: this primitive is IPv4-only \
                 (use --l4-mode tcp for IPv6, or give an IPv4 target)",
                mode.label()
            ),
            L34Error::Ipv6RawTcpUnsupported(ip) => write!(
                f,
                "the raw packet-crafting modes (TCP flag floods, fragmentation, GRE) \
                 are IPv4-only for now; refusing IPv6 target {ip}"
            ),
            L34Error::RawSocket(e) => write!(
                f,
                "cannot open raw socket ({e}); needs CAP_NET_RAW/root \
                 (grant with: sudo setcap cap_net_raw+ep <binary>, or run as root)"
            ),
            L34Error::Setup(e) => write!(f, "socket setup failed: {e}"),
            L34Error::Build(e) => write!(f, "failed to build TCP packet: {e}"),
        }
    }
}

impl std::error::Error for L34Error {}

/// The L3/L4 engine. Holds only its config; the authorized targets arrive via
/// the [`RunPlan`].
#[derive(Debug, Clone)]
pub struct L34Engine {
    config: L34Config,
    /// `StressModule::name` returns `&str`, and a multi-vector run's name is
    /// assembled from its mode list, so it is built once here.
    name: String,
}

impl L34Engine {
    pub fn new(config: L34Config) -> Self {
        let name = config.label();
        Self { config, name }
    }

    /// Pre-flight check so the caller can fail fast (non-zero exit) before
    /// emitting anything: the plan must carry at least one IP target of a family
    /// this mode can actually reach, and (for SYN) the raw-socket privilege must
    /// be present. `Ok(())` means the run can proceed. Fail-closed.
    pub fn preflight(&self, plan: &RunPlan) -> Result<(), L34Error> {
        self.check_targets(plan)?;
        // Every vector, not just the first. A multi-vector run that preflighted
        // only its leading mode would pass, start, and then have its raw vectors
        // fail every packet — a run that reports partial success for a privilege
        // problem the operator could have been told about before any traffic.
        for mode in &self.config.modes {
            if let Some(proto) = mode.raw_socket_protocol() {
                // Opening (and immediately dropping) the raw socket surfaces a
                // missing CAP_NET_RAW now rather than mid-run with a zero-sent
                // report.
                Socket::new(Domain::IPV4, Type::RAW, Some(proto))
                    .map_err(|e| L34Error::RawSocket(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Validate that the plan holds at least one reachable IP target for this
    /// mode. Shared by [`preflight`](Self::preflight) and [`run`](Self::run) so
    /// the engine is fail-closed even if a caller skips preflight and drives
    /// `execute()` directly.
    fn check_targets(&self, plan: &RunPlan) -> Result<(), L34Error> {
        let ips: Vec<IpAddr> = plan.targets.iter().filter_map(|t| t.as_ip()).collect();
        if ips.is_empty() {
            return Err(L34Error::NoIpTargets);
        }
        // UDP binds an IPv4 socket and the raw-TCP builders are IPv4-only, so an
        // IPv6 target would send nothing but errors. Refuse it instead of reporting
        // a hollow "success". TCP connect handles IPv6 natively, so it is exempt.
        //
        // Checked per vector: in a multi-vector run one IPv6-incapable mode is
        // enough to refuse, because a run that quietly drops a vector is not the
        // run the operator described.
        for &mode in &self.config.modes {
            if mode == L4Mode::Udp || mode.needs_raw_socket() {
                if let Some(&ip) = ips.iter().find(|ip| ip.is_ipv6()) {
                    return Err(L34Error::Ipv6Unsupported { mode, ip });
                }
            }
        }
        Ok(())
    }
}

impl StressModule for L34Engine {
    fn layer(&self) -> Layer {
        self.config.layer()
    }

    fn name(&self) -> &str {
        // `&str` by trait contract, so a multi-vector run — whose name is built
        // from its list — caches it on the engine rather than leaking a String.
        &self.name
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        self.run(plan).map_err(|e| {
            let what = format!("{} {}: {e}", layer_tag(self.config.layer()), self.config.label());
            match e {
                // The plan itself is unreachable for this primitive — a gate-level
                // no, decided before any socket exists.
                L34Error::NoIpTargets
                | L34Error::Ipv6Unsupported { .. }
                | L34Error::Ipv6RawTcpUnsupported(_) => ModuleError::Refused(what),
                // The host could not give us what the run needs: privilege, a
                // socket, a route.
                L34Error::RawSocket(_) | L34Error::Setup(_) | L34Error::Build(_) => {
                    ModuleError::Setup(what)
                }
            }
        })
    }
}

/// What one vector of a multi-vector run came back with: which primitive it was,
/// the share of the ceiling it was given, and either its counters or the reason
/// it could not run.
type VectorResult = (L4Mode, u64, Result<(Tally, bool), L34Error>);

/// Short OSI tag for a run's labels: `L3` for an all-ICMP run, else `L4`.
fn layer_tag(layer: Layer) -> &'static str {
    match layer {
        Layer::L3 => "L3",
        _ => "L4",
    }
}

impl L34Engine {
    /// How the whole run labels itself in the summary and the audit log.
    fn run_label(&self, targets: usize) -> String {
        let suffix = format!("({} target{})", targets, if targets == 1 { "" } else { "s" });
        let all_icmp = self.config.modes.iter().all(|m| m.is_icmp());
        // ICMP is portless; naming a port set for an all-ICMP run would describe
        // traffic that carries none. A mixed run does name it, because its
        // non-ICMP vectors used it.
        if all_icmp {
            format!("L3 {} {suffix}", self.config.label())
        } else {
            format!(
                "{} {} -> {} {suffix}",
                layer_tag(self.config.layer()),
                self.config.label(),
                self.config.ports.label()
            )
        }
    }

    fn run(&self, plan: &RunPlan) -> Result<RunReport, L34Error> {
        // L3/L4 only ever acts on IP data, and only on a family these modes can
        // reach. Any host-name target, empty plan, or unreachable IPv6 is refused
        // here too (not just in preflight) so `execute()` is fail-closed on its own.
        self.check_targets(plan)?;
        let ips: Vec<IpAddr> = plan.targets.iter().filter_map(|t| t.as_ip()).collect();
        let label = self.run_label(ips.len());

        // Rate 0 => send nothing (this is a safety control, honoured before we
        // even open a socket, so it is deterministic).
        if plan.rate_cap.min_interval().is_none() {
            return Ok(RunReport { layer_label: label, ..Default::default() });
        }

        let mut report = if self.config.is_multi_vector() {
            self.run_multi_vector(plan, label)?
        } else {
            let (tally, aborted) = self.run_vector(self.config.primary(), plan, plan.rate_cap)?;
            tally.into_report(label, aborted)
        };
        if let Some(note) = self.wire_note() {
            report.detail = Some(match report.detail.take() {
                Some(existing) => format!("{existing}; {note}"),
                None => note,
            });
        }
        Ok(report)
    }

    /// What one *unit* meant on the wire, when it was not one packet.
    ///
    /// The fragmentation floods count the datagram — the thing the target has to
    /// reassemble — as the unit, which is the honest measure of offered load but
    /// two to three times short of the packet count. A summary that reported
    /// `units_sent` with no such note would understate the traffic by that factor,
    /// in the one family of modes where the two numbers differ.
    fn wire_note(&self) -> Option<String> {
        let notes: Vec<String> = self
            .config
            .modes
            .iter()
            .filter(|m| m.packets_per_unit() > 1)
            .map(|m| {
                format!(
                    "{}: 1 unit = 1 datagram, sent as {} IPv4 fragments",
                    m.label(),
                    m.packets_per_unit()
                )
            })
            .collect();
        (!notes.is_empty()).then(|| notes.join("; "))
    }

    /// Drive every vector at once, each on its own thread, each with its own
    /// share of the one `--rate` ceiling.
    ///
    /// A thread per vector rather than one interleaved loop: each primitive
    /// already owns blocking state — a connect pool, a raw socket, a data-flood
    /// connection table — and interleaving them on one thread would let the
    /// slowest (a `data` write blocking on a full buffer) set the pace for the
    /// packet floods, which is the opposite of what running them together is
    /// supposed to show. The shared [`KillSwitch`] and the shared deadline stop
    /// them together.
    fn run_multi_vector(
        &self,
        plan: &RunPlan,
        label: String,
    ) -> Result<RunReport, L34Error> {
        let shares = plan.rate_cap.split_across(self.config.modes.len());
        let mut merged = Tally::new();
        let mut aborted = false;
        let mut per_vector: Vec<String> = Vec::with_capacity(self.config.modes.len());
        // A vector that could not start is the run's failure, not a footnote:
        // reported after every thread is joined, so one dead vector cannot leave
        // the others running unattended.
        let mut first_error: Option<L34Error> = None;

        let results: Vec<VectorResult> = thread::scope(|scope| {
            let handles: Vec<_> = self
                .config
                .modes
                .iter()
                .zip(shares.iter())
                .map(|(&mode, &share)| {
                    let vector_plan = RunPlan {
                        targets: plan.targets.clone(),
                        rate_cap: share,
                        duration: plan.duration,
                        kill: plan.kill.clone(),
                    };
                    let handle = scope.spawn(move || self.run_vector(mode, &vector_plan, share));
                    (mode, share.per_second, handle)
                })
                .collect();
            handles
                .into_iter()
                .map(|(mode, rate, h)| {
                    // A panicked vector is reported as a setup failure of that
                    // vector rather than propagated: the other threads have
                    // already been joined by then, and losing their results to
                    // an unwind would discard traffic that was actually sent.
                    let r = h.join().unwrap_or_else(|_| {
                        Err(L34Error::Setup(format!("vector {} panicked", mode.label())))
                    });
                    (mode, rate, r)
                })
                .collect()
        });

        for (mode, rate, result) in results {
            match result {
                Ok((tally, vector_aborted)) => {
                    aborted |= vector_aborted;
                    per_vector.push(format!(
                        "{} {} sent / {} failed at {}/s",
                        mode.label(),
                        tally.sent,
                        tally.errors,
                        rate
                    ));
                    merged.absorb(tally);
                }
                Err(e) => {
                    per_vector.push(format!("{}: {e}", mode.label()));
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
        if let Some(e) = first_error {
            return Err(e);
        }

        let mut report = merged.into_report(label, aborted);
        // Which vector sent what. Without it the summary is one total, and a
        // multi-vector run whose raw vectors all failed reads the same as one
        // where they all landed.
        report.detail = Some(per_vector.join("; "));
        Ok(report)
    }

    /// One vector's send loop: the whole of what a single-mode run does.
    fn run_vector(
        &self,
        mode: L4Mode,
        plan: &RunPlan,
        rate_cap: RateCap,
    ) -> Result<(Tally, bool), L34Error> {
        let ips: Vec<IpAddr> = plan.targets.iter().filter_map(|t| t.as_ip()).collect();

        // A share of zero means this vector was allocated no traffic. Returning
        // an empty tally rather than opening a socket keeps `--rate 0` (and a
        // split that rounds a vector to nothing) deterministic.
        let interval = match rate_cap.min_interval() {
            Some(i) => i,
            None => return Ok((Tally::new(), false)),
        };

        let mut sender = Sender::setup(&self.config, mode)?;

        let mut tally = Tally::new();
        let mut aborted = false;
        let mut idx = 0usize;
        // Only consulted by `PortOrder::Random`; constructed either way because
        // the alternative is an `Option` unwrapped inside the hot loop.
        let mut rng = Rng::from_clock();

        // How many units share one tick, and how long that tick lasts. Below the
        // resolution a sleep can actually deliver, one-unit-per-sleep makes the
        // *sleep* set the rate instead of `--rate`; see `batch_for`.
        let (batch, tick) = batch_for(interval);

        let start = Instant::now();
        let mut next = start;
        'run: while start.elapsed() < plan.duration {
            if plan.kill.is_tripped() {
                aborted = true;
                break;
            }
            // Collect whatever finished since the last tick. Only the pooled
            // connect flood defers work; every other mode resolves inline and
            // this is a no-op.
            sender.reap(&mut tally);

            // Emit this tick's units back-to-back, then sleep off the remainder
            // of the tick. The ceiling is exact: at most `batch` units leave per
            // `tick`, and `batch / tick == --rate` by construction.
            for _ in 0..batch {
                // A batch is a burst by design, so the deadline and the abort
                // signal are re-checked inside it: a large `--rate` must not buy
                // extra traffic past `--duration`, and Ctrl-C must not wait for
                // the batch to drain.
                //
                // Checked *before* each unit rather than after. `--l4-mode data`
                // opens its connections with a blocking `connect_timeout` on this
                // thread, so a check that comes after the send has already paid
                // for one whole attempt the operator asked us not to make.
                if start.elapsed() >= plan.duration {
                    break 'run;
                }
                if plan.kill.is_tripped() {
                    aborted = true;
                    break 'run;
                }
                let ip = ips[idx % ips.len()];
                // The port advances once per full pass over the targets, not per
                // unit. Advancing per unit would lock each target to its own
                // port whenever the target count and the port count share a
                // factor — with two targets and two ports, target A only ever
                // sees port 1 — which is the opposite of what a carpet-bombing
                // run is asked to produce. Dividing enumerates the whole
                // target x port cross-product instead. (The random order ignores
                // the counter entirely.)
                let port = self.config.ports.pick((idx / ips.len()) as u64, &mut rng);
                idx += 1;
                match sender.send(ip, port, &mut tally, plan) {
                    Ok(e) => tally.record(e),
                    // An `Err` here is never a per-packet failure: the send path
                    // classifies those into `Emission::Failed(bucket)` itself.
                    // Reaching this arm means the run is impossible — no route to
                    // the target, an address family this primitive cannot build
                    // for — and the condition is constant, so it would recur for
                    // every remaining unit. Bucketing it as `Internal` and
                    // carrying on produced the exact shape `check_targets` exists
                    // to prevent: a "completed" run, 100% errors, all of them
                    // blamed on jinrai's internals instead of the dead route.
                    Err(e) => return Err(e),
                }
            }

            next += tick;
            let now = Instant::now();
            if next > now {
                if interruptible_sleep(next - now, plan) {
                    aborted = true;
                    break;
                }
            } else {
                // Behind schedule: reset the clock so we never burst to "catch up".
                next = now;
            }
        }

        // Retire the worker pool and account for every attempt still in flight,
        // so an attempt dispatched just before the deadline is reported rather
        // than silently dropped. The grace differs by *why* we are here: a run
        // that reached its own deadline can afford to wait out the handshakes it
        // dispatched, but an operator who pressed Ctrl-C is owed a prompt exit,
        // not a wait proportional to `--connect-timeout-ms`.
        let grace = if aborted {
            ABORT_DRAIN_GRACE
        } else {
            self.config.connect_timeout + ABORT_DRAIN_GRACE
        };
        sender.finish(&mut tally, grace);

        Ok((tally, aborted))
    }
}

/// Running counters for one run. Exists so the pooled connect flood can fold in
/// results that arrive *after* the tick that dispatched them, without threading
/// four mutable locals through every call site.
struct Tally {
    sent: u64,
    errors: u64,
    errno: ErrnoTally,
    latency: Histogram<u64>,
    /// Total time resolved attempts spent occupying an in-flight slot, and how
    /// many there were. A running sum rather than a second histogram: only the
    /// mean is wanted, and it is the one statistic a histogram of the survivors
    /// cannot supply.
    residency_micros: u128,
    residency_n: u64,
    /// Units the pool refused to admit — see [`RunReport::not_offered`].
    not_offered: u64,
}

impl Tally {
    fn new() -> Self {
        Self {
            sent: 0,
            errors: 0,
            errno: ErrnoTally::default(),
            residency_micros: 0,
            residency_n: 0,
            not_offered: 0,
            // 1us .. 60s at 3 significant figures — bounded memory regardless of
            // how long the run holds, unlike retaining every sample.
            latency: Histogram::new_with_bounds(1, 60_000_000, 3)
                .expect("valid histogram bounds"),
        }
    }

    /// Note how long one resolved attempt held its in-flight slot, whether it
    /// succeeded or failed.
    ///
    /// Kept separate from the latency histogram on purpose. "Latency" in the
    /// summary means *the time a completed handshake took*, and folding failures
    /// into it would redefine a number operators already read. Residency answers
    /// a different question — what the concurrency budget was actually spent on —
    /// and a timeout is the most expensive answer there is: it buys no completion
    /// and holds the slot longer than any success.
    fn record_residency(&mut self, held: Duration) {
        // Floor at one microsecond: an attempt that resolved occupied a slot, and
        // rounding a sub-microsecond loopback refusal down to "free" would let
        // the mean report an infinite ceiling.
        self.residency_micros = self.residency_micros.saturating_add(held.as_micros().max(1));
        self.residency_n += 1;
    }

    fn record(&mut self, emission: Emission) {
        match emission {
            Emission::Sent { latency: observed } => {
                self.sent += 1;
                if let Some(d) = observed {
                    // Saturate at the histogram ceiling rather than drop the
                    // sample: a 60s+ handshake still belongs in `max`.
                    let us = (d.as_micros() as u64).clamp(1, 60_000_000);
                    let _ = self.latency.record(us);
                }
            }
            Emission::Failed(bucket) => {
                self.errors += 1;
                self.errno.record(bucket);
            }
            // Nothing resolved at this tick; the counters move when the worker
            // that owns the attempt reports back.
            Emission::Deferred => {}
            // Never offered. Not an attempt (the target never saw it) and not an
            // error (nothing failed), so it is counted on its own and disclosed
            // separately — see `RunReport::not_offered`.
            Emission::Dropped => self.not_offered += 1,
        }
    }

    /// Fold another vector's counters into this one, for a multi-vector run's
    /// combined total.
    ///
    /// The latency histograms are merged rather than one being picked: HdrHistogram
    /// addition is exact for a combined distribution, and in practice at most one
    /// vector of a run records latency at all (only the connection-oriented modes
    /// do). Residency is summed as a numerator/denominator pair, which is why it
    /// is stored that way — averaging two means would weight a vector that
    /// resolved ten attempts the same as one that resolved a million.
    fn absorb(&mut self, other: Tally) {
        self.sent += other.sent;
        self.errors += other.errors;
        self.not_offered += other.not_offered;
        self.residency_micros = self.residency_micros.saturating_add(other.residency_micros);
        self.residency_n += other.residency_n;
        self.errno.absorb(&other.errno);
        // Only fails on a bounds mismatch, and every tally uses the same bounds.
        let _ = self.latency.add(other.latency);
    }

    fn into_report(self, label: String, aborted: bool) -> RunReport {
        // Only the connection-oriented modes feed the histogram; a packet flood
        // leaves it empty and reports zeros rather than inventing percentiles.
        let measured = !self.latency.is_empty();
        RunReport {
            layer_label: label,
            units_sent: self.sent,
            errors: self.errors,
            errno: self.errno,
            aborted_early: aborted,
            p50_micros: if measured { self.latency.value_at_quantile(0.5) } else { 0 },
            p90_micros: if measured { self.latency.value_at_quantile(0.9) } else { 0 },
            p99_micros: if measured { self.latency.value_at_quantile(0.99) } else { 0 },
            max_micros: if measured { self.latency.max() } else { 0 },
            mean_micros: if self.residency_n > 0 {
                u64::try_from(self.residency_micros / u128::from(self.residency_n))
                    .unwrap_or(u64::MAX)
            } else {
                0
            },
            not_offered: self.not_offered,
            ..Default::default()
        }
    }
}

/// Per-mode socket state, created once before the send loop.
enum Sender {
    Udp { sock: UdpSocket, payload: Vec<u8> },
    /// TCP full-handshake connect flood, driven by a [`ConnectPool`] of blocking
    /// worker threads so the offered rate is not pinned to one handshake per RTT.
    Tcp(ConnectPool),
    /// TCP data (PSH-ACK) flood: a bounded pool of established connections that we
    /// write application data into. `idx` round-robins writes across the pool;
    /// dead connections are dropped and replaced. `timeout` bounds both connect
    /// and each write (a write that blocks on a full buffer is *pressure applied*,
    /// not a failure). `cap` is the pool ceiling, taken from the same
    /// `concurrency` knob the connect flood uses.
    TcpData { conns: Vec<TcpStream>, payload: Vec<u8>, cap: usize, timeout: Duration, idx: usize },
    /// Raw IPv4+TCP flag flood (SYN/ACK/FIN/RST/Xmas/NULL) or TCP-options bomb.
    /// `flags` selects which control flags are set; `with_options` attaches the
    /// maximal 40-byte option block (the options-bomb mode); everything else is
    /// shared.
    RawTcp {
        flags: TcpFlags,
        with_options: bool,
        raw: Socket,
        srcs: HashMap<IpAddr, Ipv4Addr>,
        counter: u32,
    },
    /// Raw ICMPv4 query flood (echo / timestamp / address-mask). The kernel
    /// supplies the IP header (real source address); we craft the ICMP message +
    /// checksum. `query` selects the message type; `id` tags this run; `counter`
    /// is the per-packet sequence number; `payload` is the echo body (ignored by
    /// the fixed-format timestamp and address-mask messages).
    Icmp { raw: Socket, query: IcmpQuery, id: u16, counter: u16, payload: Vec<u8> },
    /// Fragmented UDP or TCP flood. One unit is one **datagram**, emitted as the
    /// several IPv4 fragments the target has to hold and reassemble; `mode`
    /// selects which. `counter` supplies both the per-datagram IP identification
    /// (so fragments of different units do not collide in the reassembly table)
    /// and the varying source port / sequence number.
    Frag {
        mode: L4Mode,
        raw: Socket,
        srcs: HashMap<IpAddr, Ipv4Addr>,
        counter: u32,
        payload: Vec<u8>,
    },
    /// GRE flood (IP protocol 47): one packet per unit, encapsulating a real
    /// IPv4/UDP datagram addressed from the same real source to the same target.
    Gre { raw: Socket, srcs: HashMap<IpAddr, Ipv4Addr>, counter: u32, payload: Vec<u8> },
}

/// UDP payloads above this are rejected to avoid accidental fragmentation.
const MAX_UDP_PAYLOAD: usize = 1472;

/// Smallest payload a fragmented UDP datagram will carry. Below one byte there is
/// nothing past the 8-byte UDP header to cut off, so the "fragmented" flood would
/// quietly emit one ordinary unfragmented datagram — a run that reports a
/// primitive it did not actually exercise. Eight bytes is one fragment block.
const MIN_FRAG_PAYLOAD: usize = 8;

/// Largest payload the GRE flood will encapsulate, so the whole packet — outer
/// IPv4 header, GRE header, inner IPv4+UDP headers, payload — still fits the
/// [`MAX_UDP_PAYLOAD`] budget the other modes keep to. A GRE packet that the
/// local kernel had to fragment on its way out would be testing our MTU, not the
/// target's decapsulation path.
const MAX_GRE_PAYLOAD: usize = MAX_UDP_PAYLOAD - 4 - 28;

/// The per-write payload for the data flood is capped well above a single
/// segment — TCP handles segmentation — to push more bytes per write.
const MAX_DATA_PAYLOAD: usize = 65_536;

/// Upper bound on connect-flood worker threads. `--concurrency` sets the real
/// ceiling; this only stops a very large `--concurrency` from spawning one OS
/// thread per socket.
///
/// ## Why it is not 512
///
/// It was, on the reasoning that "512 handshakes in flight is ~170k attempts/s
/// against a 3 ms target, far above any rate this tool is meant to offer". That
/// arithmetic silently assumes every handshake *completes* — and it is exactly
/// wrong in the case the flood exists to produce. Against a target whose accept
/// path is saturating, a large share of attempts do not complete at all; they
/// occupy a worker for the full `--connect-timeout-ms`. At a 500 ms timeout and
/// a 28% timeout rate the mean slot residency is ~130 ms, not 3 ms, so 512
/// workers top out near 3.9k/s — and in the worst case (nothing completes) at
/// 1024/s. `--concurrency 4096` would not move either number, because the clamp
/// held in-flight handshakes at 512 no matter what the operator asked for.
///
/// The bound now sits high enough that `--concurrency` is the binding constraint
/// across the range of timeouts an operator will actually choose. The cost is
/// bounded and cheap: these threads only block in `connect_timeout`, and at
/// [`CONNECT_WORKER_STACK`] the full ceiling reserves 256 MiB of *address space*
/// with a resident cost of a few MiB. Beyond this, more threads is the wrong
/// instrument — lower `--connect-timeout-ms` (which cuts residency directly) or
/// move the pool to non-blocking connects.
const MAX_CONNECT_WORKERS: usize = 4096;

/// The most simultaneous handshakes a connect flood can have in flight, given a
/// `--concurrency` budget.
///
/// Public because the summary's Little's-law note divides by this to say what
/// the run could have offered, and it must divide by the ceiling that actually
/// applied — quoting a `--concurrency` the pool then clamped away would make the
/// note advise raising a knob that does nothing.
pub fn effective_parallelism(concurrency: usize) -> usize {
    concurrency.clamp(1, MAX_CONNECT_WORKERS)
}

/// The most connections `--l4-mode data` will hold open at once.
///
/// The connect flood has had a hard ceiling ([`MAX_CONNECT_WORKERS`]) since it
/// grew worker threads, but the data flood's pool was bounded only by
/// `--concurrency` and, past that, by the process descriptor limit. "The OS will
/// stop us" is not a limit this crate gets to rely on: the baseline requires hard
/// concurrency ceilings, and the failure it prevents (EMFILE part-way through a
/// run) is a measurement of our own box rather than of the target.
///
/// Every slot here is one descriptor held for the whole run, and 64 Ki of them is
/// already far past any lab this tool is pointed at — so like the other ceilings,
/// it never shapes a real test, it only catches the typo.
const MAX_DATA_CONNECTIONS: usize = 65_536;

/// The pool ceiling a data flood will actually hold, given a `--concurrency`
/// budget. Public for the same reason as [`effective_parallelism`]: the summary
/// must attribute a shortfall to the ceiling that applied, not to one we clamped
/// away.
pub fn effective_data_connections(concurrency: usize) -> usize {
    concurrency.clamp(1, MAX_DATA_CONNECTIONS)
}

/// Stack size for a connect worker. The thread does nothing but block in
/// `connect_timeout` and hand the result back, so the default 8 MiB reservation
/// is pure waste at 512 threads.
///
/// 256 KiB rather than the 64 KiB this started at. The work really does fit in
/// 64 KiB, but the margin does not: a stack overflow is not an error this code
/// can return, it is a `SIGSEGV` that takes the whole run with it, and the
/// budget is address space rather than resident memory — 4096 workers reserve
/// 1 GiB of *virtual* mapping and touch a few pages each. Paying nothing real
/// for a 4x margin against a future refactor (a buffer on the stack, a deeper
/// call into `std::net`) is the right side to be wrong on.
const CONNECT_WORKER_STACK: usize = 256 * 1024;

/// How long the connect pool keeps draining results after an **aborted** run.
///
/// This is the abort latency the tool promises. It is deliberately of the same
/// order as the kill-switch polling granularity (~50ms): an operator who pressed
/// Ctrl-C should get the process back in well under a second, whatever
/// `--connect-timeout-ms` says. Attempts that miss it are reported as
/// [`ErrnoBucket::Abandoned`] rather than waited out.
const ABORT_DRAIN_GRACE: Duration = Duration::from_millis(250);

/// How long [`ConnectPool::send`] will wait for an in-flight slot to free up
/// before giving the run loop control back. Bounded so the kill switch is still
/// polled promptly when the pool is saturated; under load a result almost always
/// lands within microseconds and the wait returns early.
const BACKPRESSURE_WAIT: Duration = Duration::from_millis(25);

/// How often a blocking call on the run thread comes up for air to check the kill
/// switch. Matches the pacing loop's own granularity (`interruptible_sleep`), so
/// no single step of a run delays an abort by more than one of these.
const KILL_POLL: Duration = Duration::from_millis(50);

/// What one worker's connect attempt produced.
enum ConnectOutcome {
    /// Handshake completed. The stream is handed to the run thread, which owns
    /// the FIFO of held connections — keeping a single owner for the descriptor
    /// budget means no lock on the hot path.
    Established { stream: TcpStream, latency: Duration },
    /// The attempt failed after occupying its slot for `held` — which is the
    /// timeout in full whenever the target simply never answered. Carried
    /// because a failure's residency is what actually bounds offered load; see
    /// [`Tally::record_residency`].
    Failed { bucket: ErrnoBucket, held: Duration },
}

/// TCP full-handshake connect flood, backed by a small pool of blocking workers.
///
/// ## Why a pool
///
/// A single-threaded blocking `connect()` loop cannot exceed **one handshake per
/// RTT** — about 330 attempts/s against a 3 ms target — regardless of `--rate`,
/// because the next attempt cannot start until the previous one resolves. That
/// made the rate cap unreachable by construction and the achieved figure a
/// measure of network latency rather than of anything about the target. With
/// `parallelism` handshakes in flight the ceiling becomes `parallelism / RTT`
/// and `--rate` is the binding constraint again.
///
/// ## The descriptor bound is unchanged
///
/// `cap` still means exactly what `--concurrency` always claimed: the number of
/// **simultaneously open sockets**. Admission requires
/// `held.len() + in_flight < cap`, so a socket mid-handshake now counts against
/// the same ceiling established ones always did. The footprint therefore remains
/// a function of `cap` alone, never of `--duration` or `--rate`.
///
/// ## Abortive close on eviction
///
/// Evicted connections are closed with `SO_LINGER 0`, i.e. RST rather than FIN,
/// so the local socket skips `TIME_WAIT`. This is not cosmetic: a graceful close
/// parks each ephemeral port for 60 s, and at any rate above roughly 450/s a
/// single source address exhausts the default ~28k-port range within the run and
/// the flood starts failing on `EADDRNOTAVAIL` instead of testing the target.
/// Steady-state pressure is unaffected — it comes from the `cap` connections
/// held established, not from the ones already closed.
struct ConnectPool {
    /// Dispatch queue. Dropping it is the shutdown signal for every worker.
    work: Option<mpsc::SyncSender<SocketAddr>>,
    /// Unbounded so a worker can never block reporting a result — which would
    /// deadlock against the run thread waiting on that same worker to free a slot.
    results: mpsc::Receiver<ConnectOutcome>,
    workers: Vec<thread::JoinHandle<()>>,
    /// Established connections held open to keep pressure on the target's
    /// connection table. FIFO: the oldest is evicted to make room.
    held: VecDeque<TcpStream>,
    /// Ceiling on open descriptors, covering `held` *and* in-flight handshakes.
    cap: usize,
    /// Attempts dispatched but not yet reaped.
    in_flight: usize,
    /// Maximum concurrent handshakes (the worker count).
    parallelism: usize,
}

impl ConnectPool {
    fn new(cap: usize, timeout: Duration) -> Result<Self, L34Error> {
        // Never more workers than the descriptor budget: a worker that can never
        // be admitted is a thread that only ever sleeps.
        let parallelism = effective_parallelism(cap);
        let (work_tx, work_rx) = mpsc::sync_channel::<SocketAddr>(parallelism);
        let (res_tx, res_rx) = mpsc::channel::<ConnectOutcome>();
        // `mpsc::Receiver` is Send but not Sync, so the workers share one behind a
        // mutex. The lock is held only across `recv`, which is orders of magnitude
        // cheaper than the handshake it hands out.
        let work_rx = Arc::new(Mutex::new(work_rx));

        let mut workers = Vec::with_capacity(parallelism);
        for _ in 0..parallelism {
            let work_rx = Arc::clone(&work_rx);
            let res_tx = res_tx.clone();
            let handle = thread::Builder::new()
                .name("jinrai-connect".into())
                .stack_size(CONNECT_WORKER_STACK)
                .spawn(move || loop {
                    // Take one address, then release the lock before the blocking
                    // connect so the other workers are not serialised behind it.
                    let addr = match work_rx.lock() {
                        Ok(rx) => match rx.recv() {
                            Ok(a) => a,
                            // The run thread dropped the dispatch queue: shut down.
                            Err(_) => break,
                        },
                        // A poisoned lock means another worker panicked mid-run;
                        // stop rather than fabricate attempts.
                        Err(_) => break,
                    };
                    let began = Instant::now();
                    let outcome = match TcpStream::connect_timeout(&addr, timeout) {
                        Ok(stream) => {
                            let latency = began.elapsed();
                            set_abortive_close(&stream);
                            ConnectOutcome::Established { stream, latency }
                        }
                        Err(e) => ConnectOutcome::Failed {
                            bucket: classify_io(&e),
                            held: began.elapsed(),
                        },
                    };
                    if res_tx.send(outcome).is_err() {
                        break;
                    }
                })
                .map_err(|e| L34Error::Setup(format!("cannot spawn connect worker: {e}")))?;
            workers.push(handle);
        }

        Ok(Self {
            work: Some(work_tx),
            results: res_rx,
            workers,
            held: VecDeque::with_capacity(cap),
            cap,
            in_flight: 0,
            parallelism,
        })
    }

    /// Fold every result that has already arrived into `tally`. Non-blocking.
    fn reap(&mut self, tally: &mut Tally) {
        while let Ok(outcome) = self.results.try_recv() {
            self.absorb(outcome, tally);
        }
    }

    fn absorb(&mut self, outcome: ConnectOutcome, tally: &mut Tally) {
        self.in_flight = self.in_flight.saturating_sub(1);
        match outcome {
            ConnectOutcome::Established { stream, latency } => {
                self.held.push_back(stream);
                tally.record_residency(latency);
                tally.record(Emission::Sent { latency: Some(latency) });
            }
            ConnectOutcome::Failed { bucket, held } => {
                tally.record_residency(held);
                tally.record(Emission::Failed(bucket));
            }
        }
    }

    /// True once there is room for one more open socket *and* a free worker.
    fn has_slot(&self) -> bool {
        self.in_flight < self.parallelism && self.held.len() + self.in_flight < self.cap
    }

    /// Dispatch one attempt, evicting held connections as needed to stay inside
    /// `cap`. Returns [`Emission::Deferred`]: the outcome is counted when the
    /// worker reports back, or — if the pool was saturated and nothing could be
    /// admitted — not at all, which is the honest record of load we could not offer.
    fn send(&mut self, addr: SocketAddr, tally: &mut Tally) -> Emission {
        // Close established connections to make room *before* dispatching, so the
        // descriptor count never exceeds `cap` even momentarily. Dropping the
        // stream closes it (RST, per `set_abortive_close`).
        while !self.has_slot() && !self.held.is_empty() {
            self.held.pop_front();
        }
        if !self.has_slot() {
            // Every slot is a handshake in flight and there is nothing left to
            // evict: wait (briefly) for one to resolve rather than spin.
            if let Ok(outcome) = self.results.recv_timeout(BACKPRESSURE_WAIT) {
                self.absorb(outcome, tally);
            }
            while !self.has_slot() && !self.held.is_empty() {
                self.held.pop_front();
            }
            if !self.has_slot() {
                return Emission::Dropped;
            }
        }
        match self.work.as_ref() {
            Some(work) => match work.try_send(addr) {
                Ok(()) => {
                    self.in_flight += 1;
                    Emission::Deferred
                }
                // The queue is momentarily full (a worker has not yet returned to
                // `recv`); skip this tick rather than block the pacer. Skipped is
                // not offered, so it is disclosed as such.
                Err(mpsc::TrySendError::Full(_)) => Emission::Dropped,
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    Emission::Failed(ErrnoBucket::Internal)
                }
            },
            None => Emission::Failed(ErrnoBucket::Internal),
        }
    }

    /// Stop dispatching, fold in whatever lands within `grace`, and account for
    /// anything still outstanding.
    ///
    /// ## Why this is time-bounded
    ///
    /// It used to `join()` every worker. A worker blocked in `connect_timeout`
    /// cannot be interrupted, so the join lasted until the slowest in-flight
    /// handshake resolved — i.e. up to `--connect-timeout-ms`, *after* the
    /// operator pressed Ctrl-C. The run loop polls the kill switch every ~50ms
    /// and then the shutdown ignored it, which made the advertised abort latency
    /// a property of a timeout flag rather than of the abort.
    ///
    /// So the drain is bounded instead. Attempts that have not reported by then
    /// are counted as [`ErrnoBucket::Abandoned`] — the bucket that exists for
    /// exactly this ("offered load that never got an answer, disclosed rather
    /// than dropped") — and their worker threads are detached rather than
    /// waited on. A detached worker exits on its own within one connect timeout
    /// of here, holding nothing but its own socket, so the process is free to
    /// exit immediately without leaving the accounting dishonest.
    fn finish(&mut self, tally: &mut Tally, grace: Duration) {
        // Dropping the dispatch queue is what tells the workers to exit; they can
        // still report the attempt in hand because `results` is unbounded.
        self.work = None;

        let deadline = Instant::now() + grace;
        while self.in_flight > 0 {
            let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
            else {
                break;
            };
            match self.results.recv_timeout(left) {
                Ok(outcome) => self.absorb(outcome, tally),
                // Timed out, or every sender is gone and nothing more is coming.
                Err(_) => break,
            }
        }

        // Whatever never reported is disclosed, not silently dropped.
        for _ in 0..self.in_flight {
            tally.record(Emission::Failed(ErrnoBucket::Abandoned));
        }
        self.in_flight = 0;

        // Detach: see the doc comment. `drain` drops the handles without joining.
        self.workers.drain(..);
    }
}

/// Close this socket abortively (RST, no `TIME_WAIT`) when it is dropped.
///
/// Best-effort: a stack that refuses the option simply gets the default graceful
/// close, which is slower to recycle ports but not incorrect.
fn set_abortive_close(stream: &TcpStream) {
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

impl Sender {
    fn setup(config: &L34Config, mode: L4Mode) -> Result<Self, L34Error> {
        let L34Config { payload_size, connect_timeout, .. } = *config;
        let cap = config.effective_concurrency();
        match mode {
            L4Mode::Udp => {
                let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                    .map_err(|e| L34Error::Setup(e.to_string()))?;
                let payload = vec![0u8; payload_size.min(MAX_UDP_PAYLOAD)];
                Ok(Sender::Udp { sock, payload })
            }
            L4Mode::TcpConnect => Ok(Sender::Tcp(ConnectPool::new(cap, connect_timeout)?)),
            L4Mode::Data => {
                // Hard ceiling, like the connect flood's. `cap` also sizes the
                // allocation below, so an unclamped `--concurrency` was a
                // multi-megabyte reservation before the first handshake.
                let cap = effective_data_connections(cap);
                Ok(Sender::TcpData {
                    conns: Vec::with_capacity(cap),
                    // Non-zero, bounded payload for each PSH-ACK write.
                    payload: vec![0u8; payload_size.clamp(1, MAX_DATA_PAYLOAD)],
                    cap,
                    timeout: connect_timeout,
                    idx: 0,
                })
            }
            L4Mode::UdpFrag | L4Mode::TcpFrag => {
                let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
                    .map_err(|e| L34Error::RawSocket(e.to_string()))?;
                Ok(Sender::Frag {
                    mode,
                    raw,
                    srcs: HashMap::new(),
                    counter: 0,
                    // Only the UDP variant carries one; the TCP variant fragments
                    // a bare SYN, whose 20-byte header is the whole datagram.
                    payload: vec![0u8; payload_size.clamp(MIN_FRAG_PAYLOAD, MAX_UDP_PAYLOAD)],
                })
            }
            L4Mode::Gre => {
                let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
                    .map_err(|e| L34Error::RawSocket(e.to_string()))?;
                Ok(Sender::Gre {
                    raw,
                    srcs: HashMap::new(),
                    counter: 0,
                    payload: vec![0u8; payload_size.min(MAX_GRE_PAYLOAD)],
                })
            }
            L4Mode::Icmp | L4Mode::IcmpTimestamp | L4Mode::IcmpAddressMask => {
                // Refusal, not `expect`. Today the outer arm guarantees this is
                // `Some`, but that guarantee lives in a match arm somebody will
                // eventually edit — and with `panic = "abort"` an `expect` here is
                // a process death, at setup, in a tool whose whole design says a
                // primitive that cannot start says so and returns.
                let query = mode.icmp_query().ok_or_else(|| {
                    L34Error::Setup(format!("{mode:?} has no ICMP query kind"))
                })?;
                let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                    .map_err(|e| L34Error::RawSocket(e.to_string()))?;
                // Payload capped like UDP to avoid accidental fragmentation (echo
                // only; the timestamp/address-mask messages are fixed-length).
                let payload = vec![0u8; payload_size.min(MAX_UDP_PAYLOAD)];
                // Identifier from the PID, so replies (if any) are attributable.
                let id = std::process::id() as u16;
                Ok(Sender::Icmp { raw, query, id, counter: 0, payload })
            }
            other => {
                // SYN/ACK/FIN/RST/Xmas/NULL: all raw-TCP flag floods share one setup.
                //
                // This is the catch-all arm, so a mode added to `L4Mode` and not
                // wired above lands here. Refusing names the gap; the `expect`
                // that used to be here would have aborted the process instead.
                let flags = other.raw_tcp_flags().ok_or_else(|| {
                    L34Error::Setup(format!(
                        "{other:?} has no send path: it is neither a raw-TCP flag \
                         flood nor handled by an earlier arm (this is a jinrai bug)"
                    ))
                })?;
                let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
                    .map_err(|e| L34Error::RawSocket(e.to_string()))?;
                let with_options = other == L4Mode::TcpOptions;
                Ok(Sender::RawTcp { flags, with_options, raw, srcs: HashMap::new(), counter: 0 })
            }
        }
    }

    /// Fold any deferred results into `tally`. A no-op for every mode that
    /// resolves its attempts inline.
    fn reap(&mut self, tally: &mut Tally) {
        if let Sender::Tcp(pool) = self {
            pool.reap(tally);
        }
    }

    /// Retire any background workers and account for attempts still outstanding.
    fn finish(&mut self, tally: &mut Tally, grace: Duration) {
        if let Sender::Tcp(pool) = self {
            pool.finish(tally, grace);
        }
    }

    /// `plan` is threaded in for the kill switch: `--l4-mode data` opens its
    /// connections with a blocking connect on this thread, and that call has to be
    /// abortable or the run's abort bound becomes `--connect-timeout-ms`.
    fn send(
        &mut self,
        ip: IpAddr,
        port: u16,
        tally: &mut Tally,
        plan: &RunPlan,
    ) -> Result<Emission, L34Error> {
        match self {
            Sender::Udp { sock, payload } => Ok(
                match sock.send_to(payload, SocketAddr::new(ip, port)) {
                    // A datagram send has no completion to observe.
                    Ok(_) => Emission::Sent { latency: None },
                    Err(e) => Emission::Failed(classify_io(&e)),
                },
            ),

            // The handshake runs on a worker, which times it from initiation to
            // resolution — a blocking `connect_timeout` has no EINPROGRESS to
            // mis-measure, so the semantics are unchanged from the serial path.
            Sender::Tcp(pool) => Ok(pool.send(SocketAddr::new(ip, port), tally)),

            Sender::TcpData { conns, payload, cap, timeout, idx } => {
                // Below the pool cap, each send opens a new connection and primes
                // it with a write — this ramps the pool up. Once full, we sustain
                // data by round-robining a write onto an existing connection.
                if conns.len() < *cap {
                    return Ok(open_and_prime(
                        SocketAddr::new(ip, port),
                        *timeout,
                        payload,
                        conns,
                        plan,
                    ));
                }
                // Round-robin one connection; a full send buffer is pressure
                // applied (counts as sent), a real error retires the connection
                // and we open a fresh one to replace it.
                let n = conns.len();
                *idx = (*idx + 1) % n;
                let i = *idx;
                match write_pshack(&mut conns[i], payload) {
                    // A write onto an established connection has no handshake to time.
                    WriteOutcome::Sent => Ok(Emission::Sent { latency: None }),
                    WriteOutcome::Dead(_) => {
                        // Retire the dead connection *first* so replacing it cannot
                        // transiently exceed the cap.
                        conns.swap_remove(i);
                        Ok(open_and_prime(
                            SocketAddr::new(ip, port),
                            *timeout,
                            payload,
                            conns,
                            plan,
                        ))
                    }
                }
            }

            Sender::RawTcp { flags, with_options, raw, srcs, counter } => {
                let dst = require_ipv4(ip)?;
                // Real source address for the route to this target — never spoofed.
                let src = route_source(srcs, ip, dst, port)?;
                *counter = counter.wrapping_add(1);
                let src_port = varying_source_port(*counter);
                let packet = if *with_options {
                    build_tcp_options_syn(src, dst, src_port, port, *counter)?
                } else {
                    build_tcp_packet(src, dst, src_port, port, *counter, *flags)?
                };
                let dest = SockAddr::from(SocketAddr::new(IpAddr::V4(dst), 0));
                Ok(match raw.send_to(&packet, &dest) {
                    Ok(_) => Emission::Sent { latency: None },
                    Err(e) => Emission::Failed(classify_io(&e)),
                })
            }

            Sender::Frag { mode, raw, srcs, counter, payload } => {
                let dst = require_ipv4(ip)?;
                let src = route_source(srcs, ip, dst, port)?;
                *counter = counter.wrapping_add(1);
                let src_port = varying_source_port(*counter);
                // The IP identification is what separates one unit's fragments
                // from the next one's in the target's reassembly table, so it
                // moves with the counter rather than being fixed for the run.
                let id = *counter as u16;
                let fragments = match mode.raw_tcp_flags() {
                    Some(flags) => {
                        build_tcp_fragments(src, dst, src_port, port, *counter, flags, id)?
                    }
                    None => build_udp_fragments(src, dst, src_port, port, payload, id)?,
                };
                let dest = SockAddr::from(SocketAddr::new(IpAddr::V4(dst), 0));
                // A datagram the target cannot reassemble is not the unit we
                // claimed to offer, so the first fragment that fails to leave
                // fails the whole unit rather than being averaged away — even
                // though the pieces already on the wire still cost the target a
                // reassembly entry.
                for fragment in &fragments {
                    if let Err(e) = raw.send_to(fragment, &dest) {
                        return Ok(Emission::Failed(classify_io(&e)));
                    }
                }
                Ok(Emission::Sent { latency: None })
            }

            Sender::Gre { raw, srcs, counter, payload } => {
                let dst = require_ipv4(ip)?;
                let src = route_source(srcs, ip, dst, port)?;
                *counter = counter.wrapping_add(1);
                let packet = build_gre_packet(
                    src,
                    dst,
                    varying_source_port(*counter),
                    port,
                    payload,
                    *counter as u16,
                )?;
                let dest = SockAddr::from(SocketAddr::new(IpAddr::V4(dst), 0));
                Ok(match raw.send_to(&packet, &dest) {
                    Ok(_) => Emission::Sent { latency: None },
                    Err(e) => Emission::Failed(classify_io(&e)),
                })
            }

            Sender::Icmp { raw, query, id, counter, payload } => {
                // check_targets refuses IPv6 for ICMP up front; this is defensive.
                let dst = require_ipv4(ip)?;
                *counter = counter.wrapping_add(1);
                let packet = build_icmp_query(*query, *id, *counter, payload);
                // Port is irrelevant for ICMP; the kernel builds the IP header from
                // the real source address (IPPROTO_ICMP), so there is no spoof path.
                let dest = SockAddr::from(SocketAddr::new(IpAddr::V4(dst), 0));
                Ok(match raw.send_to(&packet, &dest) {
                    Ok(_) => Emission::Sent { latency: None },
                    Err(e) => Emission::Failed(classify_io(&e)),
                })
            }
        }
    }
}

/// Narrow an authorized target to IPv4, which every packet-crafting mode is
/// limited to. `check_targets` refuses an IPv6 target before a socket exists, so
/// reaching this is defensive — but it stays a refusal rather than an `expect`,
/// because the alternative to returning here is aborting the process mid-run.
fn require_ipv4(ip: IpAddr) -> Result<Ipv4Addr, L34Error> {
    match ip {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(L34Error::Ipv6RawTcpUnsupported(ip)),
    }
}

/// The host's **real** outbound address for the route to this target, memoised
/// per target so the lookup happens once rather than per packet.
///
/// Every packet-crafting mode goes through here, and [`source_ipv4_for`] is the
/// only thing it calls: that is what makes "no spoofing path" a property of two
/// short functions instead of a claim about an engine.
fn route_source(
    srcs: &mut HashMap<IpAddr, Ipv4Addr>,
    ip: IpAddr,
    dst: Ipv4Addr,
    port: u16,
) -> Result<Ipv4Addr, L34Error> {
    match srcs.get(&ip) {
        Some(s) => Ok(*s),
        None => {
            let s = source_ipv4_for(dst, port)?;
            srcs.insert(ip, s);
            Ok(s)
        }
    }
}

/// The source *port* a crafted packet leaves from: a deterministic walk of the
/// ephemeral range, driven by the run's packet counter.
///
/// Deliberately not random. Source-*address* spoofing is the guardrail this crate
/// is built around, and randomising the source port is the neighbouring move that
/// makes a run's flows unattributable to the host that produced them — see the
/// same note in [`ports`], which only ever decides where a unit is *sent*.
fn varying_source_port(counter: u32) -> u16 {
    20_000u16.wrapping_add((counter % 40_000) as u16)
}

/// The result of a single PSH-ACK write in the data flood.
enum WriteOutcome {
    /// Data was written, OR the send buffer was full (a blocked/timed-out write) —
    /// both mean pressure was applied to the target, so both count as a unit sent.
    Sent,
    /// The connection failed (reset / broken pipe): retire and replace it. Carries
    /// the classified failure so a priming write that dies is reported as what it
    /// was, rather than as a connection successfully added to the pool.
    Dead(ErrnoBucket),
}

/// Write `payload` to an established connection, flushing so the OS emits a
/// PSH-ACK segment. A full send buffer (`WouldBlock`/`TimedOut`) is *pressure
/// applied*, not a failure — the target simply is not draining fast enough, which
/// is the point — so it counts as sent. Any other error retires the connection.
fn write_pshack(stream: &mut TcpStream, payload: &[u8]) -> WriteOutcome {
    use std::io::{ErrorKind, Write};
    match stream.write(payload) {
        Ok(_) => WriteOutcome::Sent,
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
            WriteOutcome::Sent
        }
        Err(e) => WriteOutcome::Dead(classify_io(&e)),
    }
}

/// Open one data-flood connection, prime it with a PSH-ACK write, and add it to
/// the pool.
///
/// The priming write's outcome used to be discarded, so a connection the target
/// reset the instant it was established still went into the pool and still
/// counted as a unit sent — a dead descriptor occupying a slot that the pool
/// would then never refill, because `conns.len()` said it was full. Only a
/// connection that actually took data is kept.
fn open_and_prime(
    addr: SocketAddr,
    timeout: Duration,
    payload: &[u8],
    conns: &mut Vec<TcpStream>,
    plan: &RunPlan,
) -> Emission {
    let began = Instant::now();
    let mut stream = match connect_abortable(addr, timeout, plan) {
        Some(Ok(s)) => s,
        Some(Err(e)) => return Emission::Failed(classify_io(&e)),
        // Aborted mid-handshake. The SYN went out, so this is offered load that
        // never got an answer — the bucket that exists for exactly that — not a
        // unit we declined to send.
        None => return Emission::Failed(ErrnoBucket::Abandoned),
    };
    let elapsed = began.elapsed();
    let _ = stream.set_write_timeout(Some(timeout));
    match write_pshack(&mut stream, payload) {
        WriteOutcome::Sent => {
            conns.push(stream);
            Emission::Sent { latency: Some(elapsed) }
        }
        WriteOutcome::Dead(bucket) => Emission::Failed(bucket),
    }
}

/// `TcpStream::connect_timeout`, made abortable.
///
/// The data flood opens its connections on the run thread, and a blocking
/// `connect_timeout` cannot be interrupted — so with `--connect-timeout-ms 60000`
/// an operator's Ctrl-C was ignored for up to a minute, in a tool that promises a
/// ~250ms abort. The pacing loop's kill-switch checks are only as good as the
/// longest thing that happens between two of them.
///
/// So the connect runs on its own thread and this waits on it in kill-poll
/// slices. On abort the thread is **detached rather than joined**: it is blocked
/// in the same uninterruptible call, so joining it would reintroduce exactly the
/// wait we are removing. It exits on its own within one connect timeout and drops
/// whatever socket it produced. This is the same trade the connect pool already
/// makes at shutdown.
///
/// Returns `None` if the kill switch tripped before the handshake resolved.
fn connect_abortable(
    addr: SocketAddr,
    timeout: Duration,
    plan: &RunPlan,
) -> Option<Result<TcpStream, std::io::Error>> {
    // A timeout we can afford to sit through in full costs no thread: the abort
    // is already within the promised bound.
    if timeout <= ABORT_DRAIN_GRACE {
        return Some(TcpStream::connect_timeout(&addr, timeout));
    }
    let (tx, rx) = mpsc::sync_channel(1);
    let spawned = thread::Builder::new()
        .name("jinrai-data-connect".into())
        .stack_size(CONNECT_WORKER_STACK)
        .spawn(move || {
            // The receiver is gone on abort; the send simply fails and the
            // stream is dropped (closed) as this thread unwinds.
            let _ = tx.send(TcpStream::connect_timeout(&addr, timeout));
        });
    if spawned.is_err() {
        // Out of threads: fall back to the blocking call. A slow abort beats
        // failing a run the operator asked for.
        return Some(TcpStream::connect_timeout(&addr, timeout));
    }
    loop {
        match rx.recv_timeout(KILL_POLL) {
            Ok(res) => return Some(res),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if plan.kill.is_tripped() {
                    return None;
                }
            }
            // The worker vanished without reporting: nothing more to wait for.
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use jinrai_core::RateCap;
    use jinrai_safety::{Allowlist, Authorization, AuthorizedTarget, KillSwitch};

    fn authorized_ip(cidr: &str, ip: &str) -> AuthorizedTarget {
        let gate = Authorization::new(
            Allowlist::from_cidrs([cidr]).unwrap(),
            KillSwitch::new(),
        );
        gate.authorize(ip.parse().unwrap()).unwrap()
    }

    /// A config at the shipped defaults; tests that care about the in-flight cap
    /// or the attempt timeout override the field they are testing.
    fn config(mode: L4Mode, port: u16, payload_size: usize) -> L34Config {
        L34Config {
            modes: vec![mode],
            ports: PortSet::single(port),
            payload_size,
            concurrency: DEFAULT_CONCURRENCY,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// A config for a given vector list, at the shipped defaults — for the tests
    /// that care about which primitives run rather than where they aim.
    fn config_modes(modes: Vec<L4Mode>) -> L34Config {
        let payload_size = 16;
        L34Config {
            modes,
            ports: PortSet::single(9),
            payload_size,
            concurrency: DEFAULT_CONCURRENCY,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    fn plan(targets: Vec<AuthorizedTarget>, rate: u64, secs: u64) -> RunPlan {
        RunPlan {
            targets,
            rate_cap: RateCap::new(rate),
            duration: Duration::from_secs(secs),
            kill: KillSwitch::new(),
        }
    }


    #[test]
    fn all_icmp_query_modes_are_l3_raw_and_carry_no_tcp_flags() {
        for (mode, name, ty) in [
            (L4Mode::Icmp, "icmp-echo-flood", 8u8),
            (L4Mode::IcmpTimestamp, "icmp-timestamp-flood", 13),
            (L4Mode::IcmpAddressMask, "icmp-address-mask-flood", 17),
        ] {
            let engine = L34Engine::new(config(mode, 0, 32));
            assert_eq!(engine.layer(), Layer::L3, "{mode:?} is L3");
            assert_eq!(engine.name(), name);
            assert!(mode.is_icmp(), "{mode:?} is an ICMP mode");
            assert!(mode.needs_raw_socket(), "{mode:?} needs a raw socket");
            assert_eq!(mode.raw_tcp_flags(), None, "{mode:?} carries no TCP flags");
            assert_eq!(mode.icmp_query().map(|q| q.type_byte()), Some(ty));
        }
    }

    #[test]
    fn icmp_is_layer_l3_and_needs_a_raw_socket() {
        let engine = L34Engine::new(config(L4Mode::Icmp, 0, 32));
        assert_eq!(engine.layer(), Layer::L3);
        assert_eq!(engine.name(), "icmp-echo-flood");
        assert!(L4Mode::Icmp.needs_raw_socket());
        assert_eq!(L4Mode::Icmp.raw_tcp_flags(), None);
        assert_eq!(L4Mode::Udp.layer(), Layer::L4);
    }


    #[test]
    fn rate_zero_sends_nothing() {
        // Rate 0 must be honoured deterministically, without opening a socket.
        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(config(L4Mode::Udp, 9, 64));
        let report = engine.execute(&plan(vec![t], 0, 1)).expect("the run should execute");
        assert_eq!(report.units_sent, 0);
        assert_eq!(report.errors, 0);
        assert!(!report.aborted_early);
    }

    #[test]
    fn host_only_target_is_refused_ip_only() {
        // A host-name datum must not be actionable by L3/L4 (IP-only).
        let gate = Authorization::new(
            Allowlist::from_patterns(["*.staging.internal"]).unwrap(),
            KillSwitch::new(),
        );
        let host_target = gate.authorize_host("api.staging.internal").unwrap();
        let mut engine = L34Engine::new(config(L4Mode::Udp, 9, 64));
        // A refusal is an error, not a run that happened to send nothing: the
        // caller (and the audit log) must be able to tell the two apart.
        match engine.execute(&plan(vec![host_target], 100, 1)) {
            Err(ModuleError::Refused(msg)) => assert!(msg.contains("no IP targets"), "got: {msg}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn ipv6_target_refused_fail_closed_for_udp_and_syn() {
        // An allowlisted IPv6 target must NOT produce a hollow all-errors run that
        // still reports success: UDP/SYN are IPv4-only, so refuse up front.
        for mode in [
            L4Mode::Udp,
            L4Mode::Syn,
            L4Mode::Ack,
            L4Mode::Fin,
            L4Mode::Rst,
            L4Mode::Urg,
            L4Mode::Cwr,
            L4Mode::Ece,
            L4Mode::SynAck,
            L4Mode::SynFin,
            L4Mode::SynRst,
            L4Mode::Xmas,
            L4Mode::Null,
            L4Mode::Icmp,
            L4Mode::IcmpTimestamp,
            L4Mode::IcmpAddressMask,
        ] {
            let t = authorized_ip("::1/128", "::1");
            let engine = L34Engine::new(config(mode, 9, 16));
            let p = plan(vec![t], 50, 1);
            // preflight refuses before any socket work (no raw socket / no root needed).
            match engine.preflight(&p) {
                Err(L34Error::Ipv6Unsupported { mode: m, ip }) => {
                    assert_eq!(m, mode);
                    assert!(ip.is_ipv6());
                }
                other => panic!("{mode:?}: expected Ipv6Unsupported, got {other:?}"),
            }
            // And execute() is fail-closed on its own: a refusal, not a report.
            let mut engine = engine;
            match engine.execute(&p) {
                Err(ModuleError::Refused(msg)) => {
                    assert!(msg.contains("IPv6"), "{mode:?}: got {msg}")
                }
                other => panic!("{mode:?}: expected a refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn ipv6_target_allowed_for_tcp_connect() {
        // TCP connect handles IPv6 natively, so it must NOT be refused by the
        // family guard (it will simply attempt the connection).
        let t = authorized_ip("::1/128", "::1");
        let engine = L34Engine::new(config(L4Mode::TcpConnect, 9, 16));
        assert!(engine.preflight(&plan(vec![t], 50, 1)).is_ok());
    }

    /// Serialises every test that either *measures* or *perturbs* this process's
    /// descriptor table. `/proc/self/fd` is process-wide and cargo runs tests as
    /// parallel threads of one process, so an unguarded fd measurement silently
    /// counts the sockets of whatever else is running — which reads exactly like
    /// the leak it is supposed to detect.
    static FD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the descriptor-table lock. A panicking test poisons the mutex; recover
    /// the guard rather than cascading unrelated failures.
    fn fd_guard() -> std::sync::MutexGuard<'static, ()> {
        FD_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How many descriptors this process currently holds open. Linux-only (it
    /// reads `/proc/self/fd`), which is where the leak was measured and where the
    /// fd-plateau criteria are meaningful.
    #[cfg(target_os = "linux")]
    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd").expect("read /proc/self/fd").count()
    }

    /// A loopback TCP listener that accepts each connection and immediately closes
    /// its own end.
    ///
    /// The server end is deliberately *not* retained: listener and flood share this
    /// process, so `/proc/self/fd` counts both ends and holding the accepted
    /// sockets would make the harness itself ramp, masking what the flood does.
    /// Closing the far end does not affect the measurement — a descriptor on our
    /// side stays allocated until the `TcpStream` is dropped no matter what the
    /// peer does, which is exactly the property under test.
    #[cfg(target_os = "linux")]
    fn accept_and_close_listener(hold: Duration) -> (u16, std::thread::JoinHandle<()>) {
        use std::net::TcpListener;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + hold;
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((s, _)) => drop(s),
                    Err(_) => std::thread::sleep(Duration::from_millis(1)),
                }
            }
        });
        (port, handle)
    }

    /// Run the connect flood while sampling this process's fd count, and return
    /// (report, samples). Mirrors the `fd count sampled every 0.5s` measurement
    /// that exposed the leak, just at a finer interval for a short test.
    #[cfg(target_os = "linux")]
    fn connect_flood_fd_samples(
        concurrency: usize,
        rate: u64,
        secs: u64,
    ) -> (RunReport, Vec<usize>) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        let (port, acceptor) = accept_and_close_listener(Duration::from_secs(secs + 2));
        let stop = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let sampler = {
            let stop = stop.clone();
            let samples = samples.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    samples.lock().unwrap().push(open_fds());
                    std::thread::sleep(Duration::from_millis(25));
                }
            })
        };

        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(L34Config {
            concurrency,
            ..config(L4Mode::TcpConnect, port, 16)
        });
        let report = engine.execute(&plan(vec![t], rate, secs)).expect("the run should execute");

        stop.store(true, Ordering::Relaxed);
        sampler.join().unwrap();
        acceptor.join().unwrap();
        let samples = samples.lock().unwrap().clone();
        (report, samples)
    }

    /// ACCEPTANCE: fd count must rise to the cap and then *plateau*. A ramp
    /// (strictly monotonic growth, deltas tracking the rate) is the bug.
    #[test]
    #[cfg(target_os = "linux")]
    fn connect_flood_fd_count_plateaus_at_concurrency() {
        let _fd = fd_guard();
        const CAP: usize = 32;
        let (report, samples) = connect_flood_fd_samples(CAP, 400, 2);
        assert!(report.units_sent > 0, "flood should have connected: {report:?}");
        assert!(samples.len() > 8, "sampler should have collected a series");

        // Descriptors the flood itself holds, over the harness baseline. Slack
        // covers the listener, the sampler, and a socket mid-accept.
        let baseline = samples[0];
        let peak = *samples.iter().max().unwrap();
        let peak_delta = peak.saturating_sub(baseline);
        assert!(
            peak_delta <= CAP + 16,
            "fd peak delta {peak_delta} (peak {peak}, baseline {baseline}) must stay \
             bounded by the cap {CAP}, not grow with the {} attempts made; samples: {samples:?}",
            report.units_sent
        );
        // A plateau, not a ramp. Under the leak this series was strictly
        // monotonic for the whole run; a plateau's second half cannot be
        // meaningfully higher than its first.
        let split = samples.len() / 2;
        let first_half_peak = *samples[..split].iter().max().unwrap();
        let tail_peak = *samples[split..].iter().max().unwrap();
        assert!(
            tail_peak <= first_half_peak + 8,
            "fd count is still ramping rather than plateauing: first-half peak \
             {first_half_peak}, tail peak {tail_peak}; samples: {samples:?}"
        );
    }

    /// ACCEPTANCE: doubling `--duration` must not change the peak fd count. This
    /// is the property the old `Vec<TcpStream>` violated by construction.
    #[test]
    #[cfg(target_os = "linux")]
    fn connect_flood_footprint_is_independent_of_duration() {
        let _fd = fd_guard();
        const CAP: usize = 24;
        let (short_report, short_samples) = connect_flood_fd_samples(CAP, 300, 1);
        let (long_report, long_samples) = connect_flood_fd_samples(CAP, 300, 2);

        let peak_delta = |s: &[usize]| s.iter().max().unwrap().saturating_sub(s[0]);
        let short_peak = peak_delta(&short_samples);
        let long_peak = peak_delta(&long_samples);
        assert!(
            long_report.units_sent > short_report.units_sent,
            "the longer run should have attempted more connections \
             (short={}, long={})",
            short_report.units_sent,
            long_report.units_sent
        );
        // Roughly twice the attempts, same footprint. Under the leak the peak grew
        // as rate*duration, so this margin could not be met.
        assert!(
            long_peak <= short_peak + 8,
            "doubling duration changed the peak fd delta: {short_peak} -> {long_peak} \
             (attempts {} -> {})",
            short_report.units_sent,
            long_report.units_sent
        );
    }

    /// ACCEPTANCE: latency must be measured and ordered. The old code fed nothing
    /// into a histogram and reported p50=p90=p99=max=0 even after ~2000 connects.
    #[test]
    fn connect_flood_reports_ordered_nonzero_latency() {
        let _fd = fd_guard();
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine =
            L34Engine::new(L34Config { concurrency: 16, ..config(L4Mode::TcpConnect, port, 16) });
        let report = engine.execute(&plan(vec![t], 300, 1)).expect("the run should execute");

        assert!(report.units_sent > 0, "should have completed handshakes: {report:?}");
        assert!(report.max_micros > 0, "handshake latency must be measured, not left at 0");
        assert!(
            report.p50_micros <= report.p90_micros
                && report.p90_micros <= report.p99_micros
                && report.p99_micros <= report.max_micros,
            "percentiles must be monotonically ordered, got p50={} p90={} p99={} max={}",
            report.p50_micros,
            report.p90_micros,
            report.p99_micros,
            report.max_micros
        );
        drop(listener);
    }

    /// REGRESSION: `--concurrency` above 512 used to buy nothing.
    ///
    /// The pool clamped simultaneous handshakes at 512 regardless of the
    /// operator's budget, so a run that was told to raise `--concurrency` to
    /// reach its cap could raise it to 4096 and see the achieved rate not move.
    #[test]
    fn concurrency_above_the_old_clamp_still_buys_parallelism() {
        assert_eq!(effective_parallelism(0), 1, "never zero workers");
        assert_eq!(effective_parallelism(512), 512);
        assert!(
            effective_parallelism(2048) > 512,
            "a 2048-socket budget must run more than 512 handshakes in flight"
        );
        assert_eq!(
            effective_parallelism(usize::MAX),
            MAX_CONNECT_WORKERS,
            "but an absurd budget still stops at the thread ceiling"
        );
    }

    /// The data flood's pool had no ceiling of its own — `--concurrency` went
    /// straight through to a `Vec::with_capacity` and a descriptor per slot, so
    /// the only thing stopping it was EMFILE part-way through the run. Baseline
    /// item 2 asks for a hard concurrency limit, not for the OS to intervene.
    #[test]
    fn the_data_pool_has_a_ceiling_of_its_own() {
        assert_eq!(effective_data_connections(0), 1, "never a zero-connection pool");
        assert_eq!(effective_data_connections(1024), 1024, "ordinary budgets pass through");
        assert_eq!(
            effective_data_connections(usize::MAX),
            MAX_DATA_CONNECTIONS,
            "an absurd budget stops at the descriptor ceiling, not at EMFILE"
        );
    }

    /// ACCEPTANCE: a run where nothing completes must still report what an
    /// in-flight slot cost.
    ///
    /// The latency histogram is fed only by successful handshakes, so a flood
    /// against a refusing port leaves every percentile at 0. That is correct for
    /// "latency" and useless for "what could this run have offered?" — the
    /// failures held the slots. `mean_micros` is the field that has to survive
    /// this case, because the summary divides the concurrency budget by it.
    #[test]
    fn connect_flood_measures_slot_residency_even_when_nothing_completes() {
        let _fd = fd_guard();
        let closed_port = {
            let l = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            l.local_addr().unwrap().port()
        };
        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(config(L4Mode::TcpConnect, closed_port, 16));
        let report = engine.execute(&plan(vec![t], 100, 1)).expect("the run should execute");

        assert_eq!(report.units_sent, 0, "a refusing port completes nothing: {report:?}");
        assert!(report.errors > 0, "and must record the refusals: {report:?}");
        assert_eq!(report.p50_micros, 0, "no completion means no latency percentile");
        assert!(
            report.mean_micros > 0,
            "the failures held slots, so residency must be measured: {report:?}"
        );
    }

    /// ACCEPTANCE: shutting the pool down is bounded by its grace, not by
    /// `--connect-timeout-ms`.
    ///
    /// `finish` used to `join()` every worker, and a worker blocked in
    /// `connect_timeout` cannot be interrupted — so Ctrl-C against a target that
    /// never answers waited out the full connect timeout before the process
    /// exited. The run loop polled the kill switch every ~50ms and then the
    /// shutdown ignored it.
    ///
    /// Driven at the pool directly with a deliberately huge timeout and attempts
    /// marked in flight that no worker will ever report: the network-level
    /// version of this ("find a target whose connects hang") is not deterministic
    /// across environments, and the property under test is the shutdown, not the
    /// connect.
    #[test]
    fn retiring_the_connect_pool_is_bounded_by_its_grace_not_the_connect_timeout() {
        let _fd = fd_guard();
        let mut pool = ConnectPool::new(4, Duration::from_secs(3600))
            .expect("the pool should start");
        let mut tally = Tally::new();

        // Three attempts that will never report back.
        pool.in_flight = 3;

        let grace = Duration::from_millis(50);
        let began = Instant::now();
        pool.finish(&mut tally, grace);
        let took = began.elapsed();

        assert!(
            took < Duration::from_secs(1),
            "shutdown must not wait out the connect timeout, took {took:?}"
        );
        let report = tally.into_report("test".into(), true);
        assert_eq!(
            report.errno.iter().find(|(b, _)| *b == ErrnoBucket::Abandoned).map(|(_, n)| n),
            Some(3),
            "in-flight attempts must be disclosed, not dropped: {report:?}"
        );
        assert_eq!(report.errors, 3, "and counted as errors: {report:?}");
    }

    /// ACCEPTANCE: failures are bucketed by errno, and the tally reconciles with
    /// the flat `errors` count. Connecting to a closed port yields ECONNREFUSED on
    /// loopback — crucially *not* the same bucket a local fd ceiling would land in.
    #[test]
    fn connect_flood_buckets_failures_by_errno() {
        let _fd = fd_guard();
        // Bind then drop, so the port is almost certainly unbound and refusing.
        let closed_port = {
            let l = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            l.local_addr().unwrap().port()
        };
        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(config(L4Mode::TcpConnect, closed_port, 16));
        let report = engine.execute(&plan(vec![t], 100, 1)).expect("the run should execute");

        assert!(report.errors > 0, "connecting to a closed port must fail: {report:?}");
        assert_eq!(
            report.errno.total(),
            report.errors,
            "the breakdown must account for every error: {:?}",
            report.errno.iter().collect::<Vec<_>>()
        );
        let buckets: Vec<_> = report.errno.iter().map(|(b, _)| b).collect();
        assert!(
            buckets.contains(&ErrnoBucket::Econnrefused),
            "a refused connection must be attributed to ECONNREFUSED, got {buckets:?}"
        );
        assert!(
            !buckets.contains(&ErrnoBucket::Emfile),
            "a refused connection must NOT be confused with a local fd ceiling"
        );
    }

    /// The attempt timeout is configurable, and expiring it lands in the `timeout`
    /// bucket rather than being reported as the kernel's ETIMEDOUT — the two have
    /// different fixes.
    #[test]
    fn our_expired_attempt_timeout_is_its_own_bucket() {
        let _fd = fd_guard();
        // A blackhole: a listener with a full backlog, or an unroutable address.
        // 192.0.2.0/24 (TEST-NET-1) is reserved and never routed, so the handshake
        // simply never resolves.
        let t = authorized_ip("192.0.2.0/24", "192.0.2.1");
        let mut engine = L34Engine::new(L34Config {
            concurrency: 8,
            connect_timeout: Duration::from_millis(50),
            ..config(L4Mode::TcpConnect, 443, 16)
        });
        let report = engine.execute(&plan(vec![t], 20, 1)).expect("the run should execute");

        assert_eq!(report.units_sent, 0, "an unroutable target cannot complete a handshake");
        assert_eq!(report.errno.total(), report.errors);
        let buckets: Vec<_> = report.errno.iter().map(|(b, _)| b).collect();
        // Either our own deadline expired (Timeout) or the host is unreachable —
        // both are legitimate here, but neither may be a bare unclassified count.
        assert!(
            buckets
                .iter()
                .all(|b| !matches!(b, ErrnoBucket::Internal)),
            "every failure must carry an OS attribution, got {buckets:?}"
        );
        assert!(!buckets.is_empty(), "failures must be bucketed: {report:?}");
    }

    /// ACCEPTANCE: handshakes must overlap. A blocking `connect()` loop with no
    /// parallelism cannot start attempt N+1 until attempt N resolves, which
    /// caps it at `duration / attempt-cost` — the bug that made a 10000/s run
    /// against a 3 ms target achieve 320/s and report "3% of the cap".
    ///
    /// The listener here has a backlog of 1 and never accepts, so once the
    /// accept queue overflows Linux silently drops further SYNs and every
    /// subsequent connect hangs until *our* timeout expires. That fixes the
    /// per-attempt cost at a known constant, which makes the serial ceiling
    /// arithmetic rather than a guess about network conditions.
    #[test]
    #[cfg(target_os = "linux")]
    fn connect_flood_overlaps_handshakes_instead_of_one_per_rtt() {
        let _fd = fd_guard();
        const TIMEOUT: Duration = Duration::from_millis(250);
        const SECS: u64 = 2;
        const CONCURRENCY: usize = 32;

        let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        listener
            .bind(&SockAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
            .unwrap();
        listener.listen(1).unwrap();
        let port = listener.local_addr().unwrap().as_socket().unwrap().port();

        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(L34Config {
            concurrency: CONCURRENCY,
            connect_timeout: TIMEOUT,
            ..config(L4Mode::TcpConnect, port, 16)
        });
        // A rate cap far above what either implementation can reach, so the
        // limiter is not what this test measures.
        let report = engine.execute(&plan(vec![t], 10_000, SECS)).expect("the run should execute");

        let attempts = report.units_sent + report.errors;
        let serial_ceiling = (SECS as f64 / TIMEOUT.as_secs_f64()).ceil() as u64;
        assert!(
            attempts > serial_ceiling * 3,
            "connect flood is still serialised: {attempts} attempts in {SECS}s at a \
             {TIMEOUT:?} timeout, against a one-at-a-time ceiling of {serial_ceiling} \
             (report: {report:?})"
        );
        // Every attempt still has to be accounted for, deferred or not.
        assert_eq!(
            report.errno.total(),
            report.errors,
            "deferred results must still be bucketed: {:?}",
            report.errno.iter().collect::<Vec<_>>()
        );
    }

    /// ACCEPTANCE: an evicted connection is closed abortively (RST), not with a
    /// graceful FIN. This is what keeps our own ephemeral ports out of the 60 s
    /// `TIME_WAIT` parking lot — without it a sustained flood exhausts the
    /// default ~28k-port range and starts failing on EADDRNOTAVAIL instead of
    /// testing the target. The peer-observable consequence is ECONNRESET where a
    /// graceful close would have delivered end-of-stream.
    #[test]
    fn connect_flood_evictions_reset_rather_than_parking_ports_in_time_wait() {
        let _fd = fd_guard();
        use std::io::{ErrorKind, Read};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let resets = Arc::new(AtomicUsize::new(0));
        let graceful = Arc::new(AtomicUsize::new(0));

        let acceptor = {
            let (resets, graceful) = (resets.clone(), graceful.clone());
            std::thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut streams: Vec<std::net::TcpStream> = Vec::new();
                while Instant::now() < deadline {
                    while let Ok((s, _)) = listener.accept() {
                        s.set_nonblocking(true).ok();
                        streams.push(s);
                    }
                    let mut buf = [0u8; 64];
                    streams.retain_mut(|s| match s.read(&mut buf) {
                        // Orderly shutdown: the FIN path this test exists to rule out.
                        Ok(0) => {
                            graceful.fetch_add(1, Ordering::Relaxed);
                            false
                        }
                        Ok(_) => true,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => true,
                        Err(e) if e.kind() == ErrorKind::ConnectionReset => {
                            resets.fetch_add(1, Ordering::Relaxed);
                            false
                        }
                        Err(_) => false,
                    });
                    std::thread::sleep(Duration::from_millis(2));
                }
            })
        };

        // A cap of 1 forces an eviction on essentially every attempt, so the
        // close path is what the test exercises.
        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine =
            L34Engine::new(L34Config { concurrency: 1, ..config(L4Mode::TcpConnect, port, 16) });
        let report = engine.execute(&plan(vec![t], 200, 1)).expect("the run should execute");
        assert!(report.units_sent > 1, "flood should have connected repeatedly: {report:?}");

        acceptor.join().unwrap();
        let (resets, graceful) = (resets.load(Ordering::Relaxed), graceful.load(Ordering::Relaxed));
        assert!(
            resets > 0,
            "evicted connections must be reset (SO_LINGER 0), but the peer saw \
             {graceful} graceful close(s) and {resets} reset(s)"
        );
        assert!(
            resets > graceful,
            "resets must be the rule, not the exception: {resets} reset(s) vs \
             {graceful} graceful close(s)"
        );
    }

    #[test]
    fn concurrency_of_zero_is_clamped_up_rather_than_disabling_the_mode() {
        // A cap of 0 would mean "close the socket before using it"; clamp to 1.
        let c = L34Config { concurrency: 0, ..config(L4Mode::TcpConnect, 9, 16) };
        assert_eq!(c.effective_concurrency(), 1);
        assert_eq!(config(L4Mode::TcpConnect, 9, 16).effective_concurrency(), DEFAULT_CONCURRENCY);
    }

    #[test]
    fn data_flood_delivers_bytes_to_a_local_listener() {
        let _fd = fd_guard();
        // A TCP listener that accepts and drains: the data flood must establish a
        // real connection and deliver application bytes (PSH-ACK), i.e. exercise
        // the app buffers, not just the accept backlog.
        use std::io::Read;
        use std::net::TcpListener;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let got = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let got_srv = got.clone();
        let acceptor = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut streams = Vec::new();
            while Instant::now() < deadline {
                if let Ok((s, _)) = listener.accept() {
                    s.set_nonblocking(true).ok();
                    streams.push(s);
                }
                let mut buf = [0u8; 4096];
                for s in &mut streams {
                    if let Ok(n) = s.read(&mut buf) {
                        got_srv.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(config(L4Mode::Data, port, 512));
        let report = engine.execute(&plan(vec![t], 200, 1)).expect("the run should execute");
        acceptor.join().unwrap();

        assert!(report.units_sent > 0, "data flood should have sent writes");
        assert!(got.load(std::sync::atomic::Ordering::Relaxed) > 0, "listener should have received application bytes");
    }

    #[test]
    fn data_flood_is_l4_needs_no_raw_socket_and_allows_ipv6() {
        assert_eq!(L4Mode::Data.layer(), Layer::L4);
        assert_eq!(L4Mode::Data.label(), "tcp-data-flood");
        assert!(!L4Mode::Data.needs_raw_socket(), "data flood uses the OS stack");
        assert_eq!(L4Mode::Data.raw_tcp_flags(), None);
        // Like TcpConnect, the OS stack handles IPv6, so it must not be refused.
        let t = authorized_ip("::1/128", "::1");
        let engine = L34Engine::new(config(L4Mode::Data, 9, 16));
        assert!(engine.preflight(&plan(vec![t], 50, 1)).is_ok());
    }

    #[test]
    fn udp_flood_sends_to_local_listener() {
        let _fd = fd_guard();
        // Bind a UDP listener and confirm the flood actually delivers datagrams.
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(config(L4Mode::Udp, port, 16));
        let report = engine.execute(&plan(vec![t], 200, 1)).expect("the run should execute");
        assert!(report.units_sent > 0, "should have sent datagrams");
        assert_eq!(report.errors, 0);

        let mut buf = [0u8; 64];
        assert!(listener.recv_from(&mut buf).is_ok(), "listener should receive at least one datagram");
    }

    /// The port set has to reach *every* port in it, not just the first one.
    /// A spec that parses correctly but is only ever asked for `nth(0)` would
    /// pass every unit test in `ports` and still send the whole run to one
    /// port — a random-port test that is not one, which is worse than not
    /// having the feature.
    ///
    /// Four listeners on ephemeral ports; the run must deliver to all four.
    #[test]
    fn a_port_set_delivers_to_every_port_in_it() {
        let _fd = fd_guard();
        let listeners: Vec<UdpSocket> = (0..4)
            .map(|_| {
                let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
                s
            })
            .collect();
        let spec = listeners
            .iter()
            .map(|s| s.local_addr().unwrap().port().to_string())
            .collect::<Vec<_>>()
            .join(",");

        let ports = PortSet::parse(&spec, PortOrder::Sequential).expect("spec parses");
        assert_eq!(ports.count(), 4);
        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(L34Config {
            modes: vec![L4Mode::Udp],
            ports,
            payload_size: 16,
            concurrency: DEFAULT_CONCURRENCY,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        });
        let report = engine.execute(&plan(vec![t], 200, 1)).expect("the run should execute");
        assert!(report.units_sent >= 4, "sent {} units, too few to cover the set", report.units_sent);
        assert_eq!(report.errors, 0);
        // The label names the set, not a single port — an operator reading the
        // summary must be able to tell which shape ran.
        assert!(report.layer_label.contains("ports "), "label was {:?}", report.layer_label);

        let mut buf = [0u8; 64];
        for (i, l) in listeners.iter().enumerate() {
            assert!(l.recv_from(&mut buf).is_ok(), "port {i} of the set received nothing");
        }
    }

    /// The safety property of a multi-vector run, measured rather than argued:
    /// two vectors under one `--rate` must together stay under it. Handing each
    /// vector the full cap would double the traffic behind the number the
    /// operator typed, acknowledged, and had written to the audit log.
    #[test]
    fn multi_vector_vectors_share_the_rate_ceiling_they_do_not_multiply_it() {
        let _fd = fd_guard();
        let udp_listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        udp_listener.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let port = udp_listener.local_addr().unwrap().port();

        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let rate = 400u64;
        let mut engine = L34Engine::new(L34Config {
            // Two privilege-free vectors, so this runs anywhere the rest of the
            // suite does.
            modes: vec![L4Mode::Udp, L4Mode::TcpConnect],
            ports: PortSet::single(port),
            payload_size: 16,
            concurrency: DEFAULT_CONCURRENCY,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        });
        let report = engine.execute(&plan(vec![t], rate, 1)).expect("the run should execute");

        // Every attempt of every vector, against the one ceiling. The slack is
        // for the final tick's batch, not for a second vector's worth of load:
        // an unshared cap would land near 800.
        assert!(
            report.attempts() <= rate + rate / 4,
            "{} attempts against a {rate}/s shared ceiling",
            report.attempts()
        );
        assert!(report.attempts() > rate / 2, "only {} attempts — did a vector run at all?", report.attempts());

        // Both vectors are named with their own numbers. A single total cannot
        // distinguish "both landed" from "one did all the work".
        let detail = report.detail.expect("a multi-vector run reports per-vector detail");
        assert!(detail.contains("udp-flood"), "detail was {detail:?}");
        assert!(detail.contains("tcp-connect-flood"), "detail was {detail:?}");
        assert!(report.layer_label.contains("multi-vector"), "label was {:?}", report.layer_label);

        let mut buf = [0u8; 64];
        assert!(udp_listener.recv_from(&mut buf).is_ok(), "the udp vector sent nothing");
    }

    /// A mixed L3+L4 run reports as L4: calling a run that floods a port "L3"
    /// because one of its vectors is ICMP would understate what was sent.
    #[test]
    fn a_mixed_vector_run_reports_the_stronger_layer() {
        let mixed = config_modes(vec![L4Mode::Udp, L4Mode::Icmp]);
        assert_eq!(mixed.layer(), Layer::L4);
        assert!(mixed.label().contains("udp-flood + icmp-echo-flood"));

        let all_icmp = config_modes(vec![L4Mode::Icmp, L4Mode::IcmpTimestamp]);
        assert_eq!(all_icmp.layer(), Layer::L3);

        let single = config_modes(vec![L4Mode::Syn]);
        assert_eq!(single.label(), "tcp-syn-flood", "a one-vector run keeps its plain name");
    }

    /// Preflight must check every vector, not just the leading one. A run that
    /// passed on its UDP vector and then failed every raw packet reports partial
    /// success for a privilege problem the operator could have been told about
    /// before any traffic left.
    #[test]
    fn preflight_refuses_an_ipv6_target_named_by_any_vector() {
        let gate = Authorization::new(Allowlist::from_cidrs(["::/0"]).unwrap(), KillSwitch::new());
        let t = gate.authorize("2001:db8::1".parse().unwrap()).unwrap();
        // `tcp` alone handles IPv6 and would be accepted; the udp vector is what
        // makes the plan unreachable, and it is second in the list.
        let engine = L34Engine::new(config_modes(vec![L4Mode::TcpConnect, L4Mode::Udp]));
        match engine.preflight(&plan(vec![t], 10, 1)) {
            Err(L34Error::Ipv6Unsupported { mode, .. }) => assert_eq!(mode, L4Mode::Udp),
            other => panic!("expected an IPv6 refusal naming the udp vector, got {other:?}"),
        }
    }

    /// The random order must also cover the set. It picks per unit rather than
    /// walking, so "every port got traffic" is the property that separates a
    /// working draw from a generator stuck on one value.
    #[test]
    fn the_random_port_order_covers_its_set_too() {
        let _fd = fd_guard();
        let listeners: Vec<UdpSocket> = (0..4)
            .map(|_| {
                let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
                s
            })
            .collect();
        let spec = listeners
            .iter()
            .map(|s| s.local_addr().unwrap().port().to_string())
            .collect::<Vec<_>>()
            .join(",");

        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(L34Config {
            modes: vec![L4Mode::Udp],
            ports: PortSet::parse(&spec, PortOrder::Random).expect("spec parses"),
            payload_size: 16,
            concurrency: DEFAULT_CONCURRENCY,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        });
        // 400 draws over 4 ports: missing one has probability (3/4)^400, which is
        // not a flake worth designing around.
        let report = engine.execute(&plan(vec![t], 400, 1)).expect("the run should execute");
        assert_eq!(report.errors, 0);
        assert!(report.layer_label.contains("random"), "label was {:?}", report.layer_label);

        let mut buf = [0u8; 64];
        for (i, l) in listeners.iter().enumerate() {
            assert!(l.recv_from(&mut buf).is_ok(), "port {i} of the set received nothing");
        }
    }


    /// The point of the batching: a rate whose per-unit interval is far below
    /// what a sleep can resolve must actually be delivered, not silently capped
    /// at the sleep granularity.
    ///
    /// One unit per `thread::sleep` tops out near 30k/s regardless of `--rate`,
    /// so this asserts a floor an unbatched pacer cannot reach.
    #[test]
    fn high_rate_udp_flood_is_not_capped_by_sleep_granularity() {
        let _fd = fd_guard();
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(config(L4Mode::Udp, port, 16));
        let requested = 200_000u64;
        let secs = 2u64;
        let report = engine.execute(&plan(vec![t], requested, secs)).expect("the run should execute");

        assert_eq!(report.errors, 0, "loopback UDP should not fail: {:?}", report.errno);
        // Deliberately well under the requested rate: this asserts the sleep
        // ceiling is gone, not that any particular host reaches 200k/s.
        let floor = 60_000 * secs;
        assert!(
            report.units_sent > floor,
            "sent {} in {secs}s at a {requested}/s cap — an unbatched pacer tops \
             out near 30k/s, so this should clear {floor}",
            report.units_sent
        );
        // And the ceiling still holds: a batch may burst within its tick, but the
        // run as a whole must never exceed what --rate authorised.
        let ceiling = requested * secs;
        assert!(
            report.units_sent <= ceiling,
            "sent {} which exceeds the {requested}/s cap over {secs}s ({ceiling})",
            report.units_sent
        );
    }

    /// A batch is a burst, so the run must still stop at `--duration` rather than
    /// finishing the batch it happens to be in.
    #[test]
    fn a_high_rate_run_still_ends_on_time() {
        let _fd = fd_guard();
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(config(L4Mode::Udp, port, 16));
        let wall = Instant::now();
        let _ = engine.execute(&plan(vec![t], 500_000, 1)).expect("the run should execute");
        let elapsed = wall.elapsed();
        assert!(
            elapsed < Duration::from_millis(1400),
            "a 1s run at 500000/s took {elapsed:?}"
        );
    }
}

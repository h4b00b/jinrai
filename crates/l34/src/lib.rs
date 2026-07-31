//! # jinrai-l34 — L3/L4 traffic generation (isolated-lab use only)
//!
//! Direct stress primitives against **allowlisted** targets:
//!   - **UDP flood** — datagrams to `target:port` (no privilege needed);
//!   - **TCP connect flood** — full-handshake connections held open to exercise
//!     the connection table / backlog (no privilege needed);
//!   - **TCP flag floods** — crafted IPv4+TCP packets with a single control flag
//!     set (SYN / ACK / FIN / RST / URG / CWR / ECE) via a raw socket (requires
//!     `CAP_NET_RAW`/root). SYN exercises the accept backlog; ACK/FIN/RST exercise
//!     the target's connection-tracking / stateful-firewall state for packets
//!     outside an established connection; URG/CWR/ECE are otherwise-empty segments
//!     carrying only an urgent or ECN congestion bit, probing how the stack and
//!     any middlebox treat these rarely-standalone flags.
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
//! Targets are always [`AuthorizedTarget`]s that passed the gate as IP data
//! (`as_ip()`); a host-name datum is rejected here (L3/L4 is IP-only).

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use jinrai_core::{ErrnoBucket, ErrnoTally, Layer, RunPlan, RunReport, StressModule};

/// Which L4 primitive to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Mode {
    /// UDP datagram flood.
    Udp,
    /// TCP full-handshake connect flood (connections held open).
    TcpConnect,
    /// TCP SYN flood (raw socket, SYN flag).
    Syn,
    /// TCP ACK flood (raw socket, ACK flag) — packets with no matching connection.
    Ack,
    /// TCP FIN flood (raw socket, FIN flag) — connection-teardown packets.
    Fin,
    /// TCP RST flood (raw socket, RST flag) — reset packets.
    Rst,
    /// TCP URG flood (raw socket, URG flag only) — an out-of-state segment whose
    /// only control bit is the (degenerate, zero-pointer) urgent flag.
    Urg,
    /// TCP CWR flood (raw socket, CWR flag only) — a lone ECN Congestion-Window-
    /// Reduced bit with no SYN/ACK, probing ECN handling outside a connection.
    Cwr,
    /// TCP ECE flood (raw socket, ECE flag only) — a lone ECN-Echo bit, likewise
    /// standalone rather than part of an established/negotiating connection.
    Ece,
    /// TCP SYN+FIN flood (raw socket) — a classic illegal combination (open and
    /// close at once) long used to probe firewall/IDS flag handling.
    SynFin,
    /// TCP SYN+RST flood (raw socket) — the mutually-contradictory open+reset
    /// combination; another flag field that matches no legal TCP state.
    SynRst,
    /// TCP Xmas flood (raw socket, FIN+PSH+URG set at once) — an illegal flag
    /// combination that probes stateful-firewall / TCP-stack handling of packets
    /// that match no RFC-legal state ("lit up like a Christmas tree").
    Xmas,
    /// TCP NULL flood (raw socket, no flags set) — the other anomalous extreme:
    /// a segment with an empty control field.
    Null,
    /// TCP data flood (PSH-ACK) — establishes real connections through the OS
    /// stack and writes application data into them, filling the target's receive
    /// / application buffers rather than just its accept backlog or conn-track
    /// state. No raw socket (the OS sets PSH on each flushed write); IPv4 + IPv6.
    Data,
    /// TCP-options bomb — a raw SYN flood whose every packet carries the maximal
    /// 40-byte TCP options block, forcing full option parsing + SACK/timestamp
    /// state allocation per SYN. Same raw-socket / IPv4-only constraints as the
    /// flag floods; it simply crafts a SYN with a full option field instead of a
    /// bare one.
    TcpOptions,
    /// ICMP echo-request flood (raw socket, L3). IPv4-only; source is the
    /// kernel-assigned real address (the kernel builds the IP header).
    Icmp,
    /// ICMP timestamp-request flood (type 13, raw socket, L3). Same machinery as
    /// the echo flood; exercises the target's timestamp handler instead.
    IcmpTimestamp,
    /// ICMP address-mask-request flood (type 17, raw socket, L3). Exercises the
    /// target's address-mask handler.
    IcmpAddressMask,
}

/// Which ICMPv4 *query* message an ICMP flood mode emits. All three are messages
/// the target host answers directly (like a ping) — never forged error, redirect,
/// or router messages, which are only meaningful spoofed as if from a gateway and
/// are out of scope by design. They differ only in the ICMP type byte and the
/// fixed body that follows the identifier/sequence header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IcmpQuery {
    /// Echo request (type 8) — the classic ping flood, carries an arbitrary body.
    Echo,
    /// Timestamp request (type 13) — a 20-byte message with three 32-bit
    /// timestamps; forces the ICMP timestamp handler and can leak clock state.
    Timestamp,
    /// Address-mask request (type 17) — a 12-byte message with a 4-byte mask
    /// field; forces the address-mask handler.
    AddressMask,
}

impl IcmpQuery {
    /// The ICMPv4 type byte; the code byte is 0 for every query request.
    fn type_byte(self) -> u8 {
        match self {
            IcmpQuery::Echo => 8,
            IcmpQuery::Timestamp => 13,
            IcmpQuery::AddressMask => 17,
        }
    }
}

/// The TCP control flags a raw-TCP flood sets on each crafted packet. All raw-TCP
/// modes share the same packet-crafting, socket, and no-spoofing machinery; they
/// differ only in which flags are set. The single-flag floods (SYN/ACK/FIN/RST)
/// light exactly one; the anomalous-combination floods set an illegal mix — Xmas
/// (FIN+PSH+URG) lights several, NULL sets none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpFlags {
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    psh: bool,
    urg: bool,
    /// ECN Congestion-Window-Reduced.
    cwr: bool,
    /// ECN-Echo.
    ece: bool,
}

impl TcpFlags {
    /// No flag set — the NULL segment, and the base for the named constructors.
    const NONE: TcpFlags = TcpFlags {
        syn: false,
        ack: false,
        fin: false,
        rst: false,
        psh: false,
        urg: false,
        cwr: false,
        ece: false,
    };
}

impl L4Mode {
    fn label(self) -> &'static str {
        match self {
            L4Mode::Udp => "udp-flood",
            L4Mode::TcpConnect => "tcp-connect-flood",
            L4Mode::Syn => "tcp-syn-flood",
            L4Mode::Ack => "tcp-ack-flood",
            L4Mode::Fin => "tcp-fin-flood",
            L4Mode::Rst => "tcp-rst-flood",
            L4Mode::Urg => "tcp-urg-flood",
            L4Mode::Cwr => "tcp-cwr-flood",
            L4Mode::Ece => "tcp-ece-flood",
            L4Mode::SynFin => "tcp-syn-fin-flood",
            L4Mode::SynRst => "tcp-syn-rst-flood",
            L4Mode::Xmas => "tcp-xmas-flood",
            L4Mode::Null => "tcp-null-flood",
            L4Mode::Data => "tcp-data-flood",
            L4Mode::TcpOptions => "tcp-options-flood",
            L4Mode::Icmp => "icmp-echo-flood",
            L4Mode::IcmpTimestamp => "icmp-timestamp-flood",
            L4Mode::IcmpAddressMask => "icmp-address-mask-flood",
        }
    }

    /// The ICMP query message this mode emits, or `None` for the non-ICMP modes.
    fn icmp_query(self) -> Option<IcmpQuery> {
        match self {
            L4Mode::Icmp => Some(IcmpQuery::Echo),
            L4Mode::IcmpTimestamp => Some(IcmpQuery::Timestamp),
            L4Mode::IcmpAddressMask => Some(IcmpQuery::AddressMask),
            _ => None,
        }
    }

    /// Whether this mode is one of the L3 ICMP query floods.
    pub fn is_icmp(self) -> bool {
        self.icmp_query().is_some()
    }

    /// The TCP flags for a raw-TCP flood mode, or `None` for every other mode
    /// (UDP / TCP-connect need no raw socket; ICMP is not TCP).
    fn raw_tcp_flags(self) -> Option<TcpFlags> {
        match self {
            // The options bomb is a SYN too — it differs only in carrying a full
            // option block, which the sender attaches based on the mode.
            L4Mode::Syn | L4Mode::TcpOptions => Some(TcpFlags { syn: true, ..TcpFlags::NONE }),
            L4Mode::Ack => Some(TcpFlags { ack: true, ..TcpFlags::NONE }),
            L4Mode::Fin => Some(TcpFlags { fin: true, ..TcpFlags::NONE }),
            L4Mode::Rst => Some(TcpFlags { rst: true, ..TcpFlags::NONE }),
            L4Mode::Urg => Some(TcpFlags { urg: true, ..TcpFlags::NONE }),
            L4Mode::Cwr => Some(TcpFlags { cwr: true, ..TcpFlags::NONE }),
            L4Mode::Ece => Some(TcpFlags { ece: true, ..TcpFlags::NONE }),
            // Illegal open+close / open+reset combinations.
            L4Mode::SynFin => Some(TcpFlags { syn: true, fin: true, ..TcpFlags::NONE }),
            L4Mode::SynRst => Some(TcpFlags { syn: true, rst: true, ..TcpFlags::NONE }),
            // Xmas lights FIN+PSH+URG at once; NULL sets nothing at all.
            L4Mode::Xmas => Some(TcpFlags { fin: true, psh: true, urg: true, ..TcpFlags::NONE }),
            L4Mode::Null => Some(TcpFlags::NONE),
            // Data flood uses the OS TCP stack (no crafted packet), like TcpConnect;
            // the ICMP floods are not TCP at all.
            L4Mode::Udp
            | L4Mode::TcpConnect
            | L4Mode::Data
            | L4Mode::Icmp
            | L4Mode::IcmpTimestamp
            | L4Mode::IcmpAddressMask => None,
        }
    }

    /// Raw-socket modes craft packets on a raw socket (need CAP_NET_RAW) and are
    /// IPv4-only: the six TCP flag floods, the TCP-options bomb, and the ICMP
    /// echo flood.
    fn needs_raw_socket(self) -> bool {
        self.raw_socket_protocol().is_some()
    }

    /// The IP protocol for this mode's raw socket, or `None` for the socket-based
    /// (UDP / TCP-connect) modes. Raw TCP uses `IPPROTO_RAW` (we supply the whole
    /// IPv4 header); ICMP uses `IPPROTO_ICMP` (the kernel supplies the IP header,
    /// so the source address is the real one — no spoofing path).
    fn raw_socket_protocol(self) -> Option<Protocol> {
        if self.raw_tcp_flags().is_some() {
            Some(Protocol::from(IPPROTO_RAW))
        } else if self.is_icmp() {
            Some(Protocol::ICMPV4)
        } else {
            None
        }
    }

    /// Which OSI layer this mode drives: ICMP is L3, everything else L4.
    fn layer(self) -> Layer {
        if self.is_icmp() {
            Layer::L3
        } else {
            Layer::L4
        }
    }
}

/// Runtime configuration for an L3/L4 run.
#[derive(Debug, Clone)]
pub struct L34Config {
    pub mode: L4Mode,
    pub port: u16,
    /// UDP payload size in bytes (ignored by TCP/SYN). Capped to a sane MTU-ish
    /// ceiling to avoid accidental fragmentation surprises.
    pub payload_size: usize,
    /// Ceiling on **simultaneously open sockets** for the connection-holding
    /// modes (`tcp` / `data`). This is what decouples the run's local footprint
    /// from `--duration`: the three knobs are orthogonal —
    ///   * `rate` is the offered load (attempts/sec),
    ///   * `concurrency` is the maximum open sockets at any instant,
    ///   * `duration` is wall-clock run length and *nothing else*.
    ///
    /// For `tcp` this ceiling covers sockets **mid-handshake** as well as
    /// established ones, and so doubles as the connect flood's parallelism (see
    /// [`ConnectPool`]): it is what lets the run reach `rate` instead of being
    /// pinned to one handshake per round-trip. The descriptor bound is the same
    /// number it always was.
    ///
    /// Clamped to at least 1 (see [`L34Config::effective_concurrency`]).
    pub concurrency: usize,
    /// How long a single connection attempt may stay unresolved before it is
    /// abandoned and bucketed as [`ErrnoBucket::Timeout`].
    pub connect_timeout: Duration,
}

/// Default in-flight cap: high enough to apply real connection-table pressure,
/// comfortably below a default 1024-descriptor ceiling so a stock shell cannot
/// turn the run into an EMFILE self-test.
pub const DEFAULT_CONCURRENCY: usize = 256;

/// Default per-attempt connect timeout (the historical hard-coded value).
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

impl L34Config {
    /// The in-flight cap actually enforced: a cap of 0 would mean "close the
    /// socket we just opened before doing anything with it", so 0 is clamped up
    /// to 1 rather than silently disabling the mode.
    pub fn effective_concurrency(&self) -> usize {
        self.concurrency.max(1)
    }
}

/// What one emission attempt produced.
enum Emission {
    /// The unit went out. `latency` is `Some` only for attempts with an
    /// observable completion — the TCP handshake, timed from initiation to
    /// resolution. A fire-and-forget packet send (UDP / raw / ICMP) has no
    /// completion to observe, so it reports `None` rather than a meaningless 0.
    Sent { latency: Option<Duration> },
    /// The attempt failed, bucketed by the OS error behind it.
    Failed(ErrnoBucket),
    /// No outcome to record at this tick. The attempt is either in flight on a
    /// worker (and will be counted when it resolves) or was never admitted
    /// because every in-flight slot was busy. Only the pooled connect flood
    /// produces this; every other mode resolves inline.
    Deferred,
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
            L34Error::Ipv6RawTcpUnsupported(ip) => {
                write!(f, "TCP flag floods are IPv4-only for now; refusing IPv6 target {ip}")
            }
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
}

impl L34Engine {
    pub fn new(config: L34Config) -> Self {
        Self { config }
    }

    /// Pre-flight check so the caller can fail fast (non-zero exit) before
    /// emitting anything: the plan must carry at least one IP target of a family
    /// this mode can actually reach, and (for SYN) the raw-socket privilege must
    /// be present. `Ok(())` means the run can proceed. Fail-closed.
    pub fn preflight(&self, plan: &RunPlan) -> Result<(), L34Error> {
        self.check_targets(plan)?;
        if let Some(proto) = self.config.mode.raw_socket_protocol() {
            // Opening (and immediately dropping) the raw socket surfaces a missing
            // CAP_NET_RAW now rather than mid-run with a zero-sent report.
            Socket::new(Domain::IPV4, Type::RAW, Some(proto))
                .map_err(|e| L34Error::RawSocket(e.to_string()))?;
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
        if self.config.mode == L4Mode::Udp || self.config.mode.needs_raw_socket() {
            if let Some(&ip) = ips.iter().find(|ip| ip.is_ipv6()) {
                return Err(L34Error::Ipv6Unsupported { mode: self.config.mode, ip });
            }
        }
        Ok(())
    }
}

impl StressModule for L34Engine {
    fn layer(&self) -> Layer {
        self.config.mode.layer()
    }

    fn name(&self) -> &str {
        self.config.mode.label()
    }

    fn execute(&mut self, plan: &RunPlan) -> RunReport {
        match self.run(plan) {
            Ok(report) => report,
            Err(e) => RunReport {
                layer_label: format!("{} {} ERROR: {e}", layer_tag(self.config.mode), self.config.mode.label()),
                aborted_early: true,
                ..Default::default()
            },
        }
    }
}

/// Short OSI tag for a mode's run/error labels: `L3` for ICMP, else `L4`.
fn layer_tag(mode: L4Mode) -> &'static str {
    match mode.layer() {
        Layer::L3 => "L3",
        _ => "L4",
    }
}

impl L34Engine {
    fn run(&self, plan: &RunPlan) -> Result<RunReport, L34Error> {
        // L3/L4 only ever acts on IP data, and only on a family this mode can
        // reach. Any host-name target, empty plan, or unreachable IPv6 is refused
        // here too (not just in preflight) so `execute()` is fail-closed on its own.
        self.check_targets(plan)?;
        let ips: Vec<IpAddr> = plan.targets.iter().filter_map(|t| t.as_ip()).collect();

        let targets_suffix = format!("({} target{})", ips.len(), if ips.len() == 1 { "" } else { "s" });
        // ICMP has no port; every other mode targets a port.
        let label = if self.config.mode.is_icmp() {
            format!("L3 {} {targets_suffix}", self.config.mode.label())
        } else {
            format!("L4 {} -> port {} {targets_suffix}", self.config.mode.label(), self.config.port)
        };

        // Rate 0 => send nothing (this is a safety control, honoured before we
        // even open a socket, so it is deterministic).
        let interval = match plan.rate_cap.min_interval() {
            Some(i) => i,
            None => {
                return Ok(RunReport { layer_label: label, ..Default::default() });
            }
        };

        let mut sender = Sender::setup(&self.config)?;

        let mut tally = Tally::new();
        let mut aborted = false;
        let mut idx = 0usize;

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
                let ip = ips[idx % ips.len()];
                idx += 1;
                match sender.send(ip, self.config.port, &mut tally) {
                    Ok(e) => tally.record(e),
                    Err(_) => tally.record(Emission::Failed(ErrnoBucket::Internal)),
                }
                // A batch is a burst by design, so the deadline and the abort
                // signal are re-checked inside it: a large `--rate` must not buy
                // extra traffic past `--duration`, and Ctrl-C must not wait for
                // the batch to drain.
                if start.elapsed() >= plan.duration {
                    break 'run;
                }
                if plan.kill.is_tripped() {
                    aborted = true;
                    break 'run;
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
        // than silently dropped.
        sender.finish(&mut tally);

        Ok(tally.into_report(label, aborted))
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
}

impl Tally {
    fn new() -> Self {
        Self {
            sent: 0,
            errors: 0,
            errno: ErrnoTally::default(),
            // 1us .. 60s at 3 significant figures — bounded memory regardless of
            // how long the run holds, unlike retaining every sample.
            latency: Histogram::new_with_bounds(1, 60_000_000, 3)
                .expect("valid histogram bounds"),
        }
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
        }
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
}

/// UDP payloads above this are rejected to avoid accidental fragmentation.
const MAX_UDP_PAYLOAD: usize = 1472;

/// The per-write payload for the data flood is capped well above a single
/// segment — TCP handles segmentation — to push more bytes per write.
const MAX_DATA_PAYLOAD: usize = 65_536;

/// Upper bound on connect-flood worker threads. `--concurrency` sets the real
/// ceiling; this only stops a very large `--concurrency` from spawning one OS
/// thread per socket. 512 handshakes in flight is ~170k attempts/s against a
/// 3 ms target, far above any rate this tool is meant to offer.
const MAX_CONNECT_WORKERS: usize = 512;

/// Stack size for a connect worker. The thread does nothing but block in
/// `connect_timeout` and hand the result back, so the default 8 MiB reservation
/// is pure waste at 512 threads.
const CONNECT_WORKER_STACK: usize = 64 * 1024;

/// How long [`ConnectPool::send`] will wait for an in-flight slot to free up
/// before giving the run loop control back. Bounded so the kill switch is still
/// polled promptly when the pool is saturated; under load a result almost always
/// lands within microseconds and the wait returns early.
const BACKPRESSURE_WAIT: Duration = Duration::from_millis(25);

/// What one worker's connect attempt produced.
enum ConnectOutcome {
    /// Handshake completed. The stream is handed to the run thread, which owns
    /// the FIFO of held connections — keeping a single owner for the descriptor
    /// budget means no lock on the hot path.
    Established { stream: TcpStream, latency: Duration },
    Failed(ErrnoBucket),
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
        let parallelism = cap.clamp(1, MAX_CONNECT_WORKERS);
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
                        Err(e) => ConnectOutcome::Failed(classify_io(&e)),
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
                tally.record(Emission::Sent { latency: Some(latency) });
            }
            ConnectOutcome::Failed(bucket) => tally.record(Emission::Failed(bucket)),
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
                return Emission::Deferred;
            }
        }
        match self.work.as_ref() {
            Some(work) => match work.try_send(addr) {
                Ok(()) => {
                    self.in_flight += 1;
                    Emission::Deferred
                }
                // The queue is momentarily full (a worker has not yet returned to
                // `recv`); skip this tick rather than block the pacer.
                Err(mpsc::TrySendError::Full(_)) => Emission::Deferred,
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    Emission::Failed(ErrnoBucket::Internal)
                }
            },
            None => Emission::Failed(ErrnoBucket::Internal),
        }
    }

    /// Stop dispatching, wait for the workers to finish what they hold, and fold
    /// every remaining result into `tally`.
    fn finish(&mut self, tally: &mut Tally) {
        // Dropping the dispatch queue is what tells the workers to exit; they can
        // still report the attempt in hand because `results` is unbounded.
        self.work = None;
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
        // Every worker (and so every result sender) is gone: this drains to
        // completion and terminates.
        while let Ok(outcome) = self.results.recv() {
            self.absorb(outcome, tally);
        }
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
    fn setup(config: &L34Config) -> Result<Self, L34Error> {
        let L34Config { mode, payload_size, connect_timeout, .. } = *config;
        let cap = config.effective_concurrency();
        match mode {
            L4Mode::Udp => {
                let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                    .map_err(|e| L34Error::Setup(e.to_string()))?;
                let payload = vec![0u8; payload_size.min(MAX_UDP_PAYLOAD)];
                Ok(Sender::Udp { sock, payload })
            }
            L4Mode::TcpConnect => Ok(Sender::Tcp(ConnectPool::new(cap, connect_timeout)?)),
            L4Mode::Data => Ok(Sender::TcpData {
                conns: Vec::with_capacity(cap),
                // Non-zero, bounded payload for each PSH-ACK write.
                payload: vec![0u8; payload_size.clamp(1, MAX_DATA_PAYLOAD)],
                cap,
                timeout: connect_timeout,
                idx: 0,
            }),
            L4Mode::Icmp | L4Mode::IcmpTimestamp | L4Mode::IcmpAddressMask => {
                let query = mode.icmp_query().expect("ICMP mode without a query kind");
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
                let flags = other
                    .raw_tcp_flags()
                    .expect("setup reached with a non-raw-TCP mode");
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
    fn finish(&mut self, tally: &mut Tally) {
        if let Sender::Tcp(pool) = self {
            pool.finish(tally);
        }
    }

    fn send(&mut self, ip: IpAddr, port: u16, tally: &mut Tally) -> Result<Emission, L34Error> {
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
                    let began = Instant::now();
                    let mut stream =
                        match TcpStream::connect_timeout(&SocketAddr::new(ip, port), *timeout) {
                            Ok(s) => s,
                            Err(e) => return Ok(Emission::Failed(classify_io(&e))),
                        };
                    let elapsed = began.elapsed();
                    let _ = stream.set_write_timeout(Some(*timeout));
                    write_pshack(&mut stream, payload);
                    conns.push(stream);
                    return Ok(Emission::Sent { latency: Some(elapsed) });
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
                    WriteOutcome::Dead => {
                        // Retire the dead connection *first* so replacing it cannot
                        // transiently exceed the cap.
                        conns.swap_remove(i);
                        let began = Instant::now();
                        let mut stream =
                            match TcpStream::connect_timeout(&SocketAddr::new(ip, port), *timeout) {
                                Ok(s) => s,
                                Err(e) => return Ok(Emission::Failed(classify_io(&e))),
                            };
                        let elapsed = began.elapsed();
                        let _ = stream.set_write_timeout(Some(*timeout));
                        write_pshack(&mut stream, payload);
                        conns.push(stream);
                        Ok(Emission::Sent { latency: Some(elapsed) })
                    }
                }
            }

            Sender::RawTcp { flags, with_options, raw, srcs, counter } => {
                let dst = match ip {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => return Err(L34Error::Ipv6RawTcpUnsupported(ip)),
                };
                // Real source address for the route to this target — never spoofed.
                let src = match srcs.get(&ip) {
                    Some(s) => *s,
                    None => {
                        let s = source_ipv4_for(dst, port)?;
                        srcs.insert(ip, s);
                        s
                    }
                };
                *counter = counter.wrapping_add(1);
                let src_port = 20_000u16.wrapping_add((*counter % 40_000) as u16);
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

            Sender::Icmp { raw, query, id, counter, payload } => {
                let dst = match ip {
                    IpAddr::V4(v4) => v4,
                    // check_targets refuses IPv6 for ICMP up front; this is defensive.
                    IpAddr::V6(_) => return Err(L34Error::Ipv6RawTcpUnsupported(ip)),
                };
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

/// The result of a single PSH-ACK write in the data flood.
enum WriteOutcome {
    /// Data was written, OR the send buffer was full (a blocked/timed-out write) —
    /// both mean pressure was applied to the target, so both count as a unit sent.
    Sent,
    /// The connection failed (reset / broken pipe): retire and replace it.
    Dead,
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
        Err(_) => WriteOutcome::Dead,
    }
}

/// `IPPROTO_RAW` — send-only raw IPv4 socket; the kernel takes our IP header
/// verbatim (IP_HDRINCL is implied), so we craft the whole IPv4+TCP packet.
const IPPROTO_RAW: i32 = 255;

/// Ask the OS which local IPv4 address routes to `dst` by connecting a UDP
/// socket (no packets are sent) and reading its local address. This is the real
/// source — there is no spoofing path.
fn source_ipv4_for(dst: Ipv4Addr, port: u16) -> Result<Ipv4Addr, L34Error> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| L34Error::Setup(e.to_string()))?;
    probe
        .connect((dst, port.max(1)))
        .map_err(|e| L34Error::Setup(e.to_string()))?;
    match probe.local_addr().map_err(|e| L34Error::Setup(e.to_string()))?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        // A v4 destination should yield a v4 local address; fall back to loopback.
        IpAddr::V6(_) => Ok(Ipv4Addr::LOCALHOST),
    }
}

/// Build a complete IPv4 + TCP packet (no payload) with correct checksums and the
/// given control flags set. One imperative path serves every raw-TCP mode: a
/// single-flag flood sets one, Xmas sets FIN+PSH+URG, NULL sets none. The source
/// address is the caller-supplied real route-local address — no spoofing path.
fn build_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    flags: TcpFlags,
) -> Result<Vec<u8>, L34Error> {
    use etherparse::PacketBuilder;
    // Apply flags imperatively so any combination is expressible. ACK carries an
    // acknowledgement number and URG an urgent pointer; the rest are bare bits.
    let mut b = PacketBuilder::ipv4(src.octets(), dst.octets(), 64).tcp(src_port, dst_port, seq, 64_240);
    if flags.syn {
        b = b.syn();
    }
    if flags.ack {
        b = b.ack(seq.wrapping_add(1));
    }
    if flags.fin {
        b = b.fin();
    }
    if flags.rst {
        b = b.rst();
    }
    if flags.psh {
        b = b.psh();
    }
    if flags.urg {
        b = b.urg(0);
    }
    if flags.cwr {
        b = b.cwr();
    }
    if flags.ece {
        b = b.ece();
    }
    let mut out = Vec::with_capacity(b.size(0));
    b.write(&mut out, &[])
        .map_err(|e| L34Error::Build(e.to_string()))?;
    Ok(out)
}

/// The maximal TCP option set an IPv4 SYN can carry: the four options a real SYN
/// commonly negotiates (MSS, SACK-permitted, timestamp, window scale) followed by
/// enough NOP padding to fill the entire 40-byte option area. The timestamp folds
/// in `seq` so successive packets are not byte-identical. Total = 40 bytes exactly
/// (a multiple of 4), so it maps to the maximum data offset of 15 with no further
/// padding — every SYN forces the target to walk a full-size option block and set
/// up SACK/timestamp state.
fn options_bomb(seq: u32) -> Vec<etherparse::TcpOptionElement> {
    use etherparse::TcpOptionElement::*;
    // 4 + 2 + 10 + 3 = 19 bytes of real options...
    let mut opts = vec![
        MaximumSegmentSize(1460),
        SelectiveAcknowledgementPermitted,
        Timestamp(seq, 0),
        WindowScale(7),
    ];
    // ...then 21 NOPs (1 byte each) to reach the 40-byte maximum.
    opts.extend(std::iter::repeat_n(Noop, 21));
    opts
}

/// Build a complete IPv4 + SYN packet carrying the maximal option block from
/// [`options_bomb`] — the "TCP-options bomb". Same real-source, no-spoof property
/// as [`build_tcp_packet`]; it differs only in attaching a full 40-byte option
/// field instead of none.
fn build_tcp_options_syn(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Result<Vec<u8>, L34Error> {
    use etherparse::PacketBuilder;
    let opts = options_bomb(seq);
    let b = PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
        .tcp(src_port, dst_port, seq, 64_240)
        .syn()
        .options(&opts)
        .map_err(|e| L34Error::Build(e.to_string()))?;
    let mut out = Vec::with_capacity(b.size(0));
    b.write(&mut out, &[])
        .map_err(|e| L34Error::Build(e.to_string()))?;
    Ok(out)
}

/// Build an ICMPv4 query-request message (echo / timestamp / address-mask) with
/// its checksum. The kernel prepends the IPv4 header (real source address), so we
/// only craft the ICMP message itself: the shared 8-byte header (type, code 0,
/// checksum, identifier, sequence) followed by the per-type body. Echo carries the
/// arbitrary `payload`; timestamp appends three 32-bit timestamps (originate set,
/// receive/transmit zero for a request); address-mask appends a zero 4-byte mask.
fn build_icmp_query(query: IcmpQuery, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(20 + payload.len());
    pkt.push(query.type_byte());
    pkt.push(0); // code is 0 for every query request
    pkt.extend_from_slice(&[0, 0]); // checksum placeholder
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    match query {
        IcmpQuery::Echo => pkt.extend_from_slice(payload),
        IcmpQuery::Timestamp => {
            // Originate carries the per-packet sequence so successive packets are
            // not byte-identical; receive/transmit are zero in a request.
            pkt.extend_from_slice(&(seq as u32).to_be_bytes()); // originate
            pkt.extend_from_slice(&[0, 0, 0, 0]); // receive
            pkt.extend_from_slice(&[0, 0, 0, 0]); // transmit
        }
        IcmpQuery::AddressMask => {
            pkt.extend_from_slice(&[0, 0, 0, 0]); // address mask, zero in a request
        }
    }
    let ck = icmp_checksum(&pkt);
    pkt[2..4].copy_from_slice(&ck.to_be_bytes());
    pkt
}

/// The standard Internet checksum (one's-complement sum of 16-bit words) over an
/// ICMP message whose checksum field is currently zero.
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in chunks.by_ref() {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8; // odd length: pad with a zero low byte
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The shortest tick worth sleeping on.
///
/// `thread::sleep` cannot resolve arbitrarily small durations: the syscall plus
/// the scheduler round-trip costs tens of microseconds, so asking for a 5 µs nap
/// yields something nearer 50 µs. One millisecond is comfortably above that floor
/// on every platform jinrai targets, while still being a fine enough quantum that
/// a batch is a millisecond of traffic rather than a visible slug.
const MIN_TICK: Duration = Duration::from_millis(1);

/// How many units to emit per tick, and how long that tick lasts, for a given
/// per-unit interval.
///
/// One unit per sleep works while the interval is longer than a sleep can
/// resolve. Below that the sleep, not `--rate`, sets the pace: at `--rate 200000`
/// the interval is 5 µs, every nap overshoots by an order of magnitude, and the
/// run tops out near 29 k/s while the summary reports "14% of the 200000/s cap" —
/// a shortfall the operator can easily read as absorbed load.
///
/// So below [`MIN_TICK`] the *tick*, not the unit, becomes the scheduling
/// quantum: emit `batch` units back-to-back, then sleep off the rest of the tick.
/// The ceiling stays exact — `batch / tick` is the requested rate by
/// construction, and no window of one tick or longer ever carries more than the
/// cap allows.
///
/// The trade is deliberate and bounded: within a tick the units leave as fast as
/// the syscalls go. That burst is at most one millisecond of traffic, it is
/// declared rather than accidental, and it is the same shape any rate-limited
/// generator produces once the requested rate exceeds what per-unit pacing can
/// deliver.
fn batch_for(interval: Duration) -> (u64, Duration) {
    if interval >= MIN_TICK {
        return (1, interval);
    }
    // interval > 0 here: a zero rate never reaches this code (`min_interval`
    // returns `None` and the run ends before a socket is opened).
    let batch = MIN_TICK.as_nanos().div_ceil(interval.as_nanos()).max(1);
    let batch = u64::try_from(batch).unwrap_or(u64::MAX);
    // Derive the tick from the batch rather than reusing MIN_TICK, so
    // `batch / tick` is exactly the requested rate even when the division above
    // rounded up.
    (batch, interval * u32::try_from(batch).unwrap_or(u32::MAX))
}

/// Sleep for `dur` but wake early (and return `true`) if the kill switch trips,
/// so a large inter-packet interval never delays an abort by more than ~50ms.
fn interruptible_sleep(dur: Duration, plan: &RunPlan) -> bool {
    let end = Instant::now() + dur;
    let chunk = Duration::from_millis(50);
    loop {
        if plan.kill.is_tripped() {
            return true;
        }
        let now = Instant::now();
        if now >= end {
            return false;
        }
        std::thread::sleep((end - now).min(chunk));
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
            mode,
            port,
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

    /// Parse a raw IPv4+TCP packet back into headers for assertions.
    fn parse_tcp(pkt: &[u8]) -> (etherparse::Ipv4Header, etherparse::TcpHeader) {
        let headers = etherparse::PacketHeaders::from_ip_slice(pkt).expect("parse IP packet");
        let ipv4 = match headers.net.expect("net header") {
            etherparse::NetHeaders::Ipv4(h, _) => h,
            other => panic!("expected IPv4, got {other:?}"),
        };
        let tcp = match headers.transport.expect("transport header") {
            etherparse::TransportHeader::Tcp(t) => t,
            other => panic!("expected TCP, got {other:?}"),
        };
        (ipv4, tcp)
    }

    #[test]
    fn syn_packet_is_well_formed() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let syn = L4Mode::Syn.raw_tcp_flags().unwrap();
        let pkt = build_tcp_packet(src, dst, 40000, 80, 12345, syn).unwrap();

        let (ipv4, tcp) = parse_tcp(&pkt);
        assert_eq!(ipv4.source, src.octets());
        assert_eq!(ipv4.destination, dst.octets());
        assert!(tcp.syn, "SYN flag must be set");
        assert!(!tcp.ack, "ACK must not be set on a SYN");
        assert_eq!(tcp.source_port, 40000);
        assert_eq!(tcp.destination_port, 80);
        assert_eq!(tcp.sequence_number, 12345);
        assert_ne!(tcp.checksum, 0, "checksum must be computed");
    }

    #[test]
    fn each_single_flag_flood_sets_exactly_its_own_flag() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        // (mode, is_syn, is_ack, is_fin, is_rst)
        let cases = [
            (L4Mode::Syn, true, false, false, false),
            (L4Mode::Ack, false, true, false, false),
            (L4Mode::Fin, false, false, true, false),
            (L4Mode::Rst, false, false, false, true),
        ];
        for (mode, syn, ack, fin, rst) in cases {
            let flags = mode.raw_tcp_flags().unwrap();
            let pkt = build_tcp_packet(src, dst, 40000, 80, 999, flags).unwrap();
            let (_, tcp) = parse_tcp(&pkt);
            assert_eq!(tcp.syn, syn, "{mode:?} syn");
            assert_eq!(tcp.ack, ack, "{mode:?} ack");
            assert_eq!(tcp.fin, fin, "{mode:?} fin");
            assert_eq!(tcp.rst, rst, "{mode:?} rst");
            assert!(!tcp.psh && !tcp.urg, "{mode:?} must not set PSH/URG");
            assert_ne!(tcp.checksum, 0, "{mode:?} checksum must be computed");
        }
    }

    #[test]
    fn xmas_flood_lights_fin_psh_urg_and_nothing_else() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let flags = L4Mode::Xmas.raw_tcp_flags().unwrap();
        let pkt = build_tcp_packet(src, dst, 40000, 80, 42, flags).unwrap();
        let (_, tcp) = parse_tcp(&pkt);
        assert!(tcp.fin && tcp.psh && tcp.urg, "Xmas must set FIN+PSH+URG");
        assert!(!tcp.syn && !tcp.ack && !tcp.rst, "Xmas must set no other flag");
        assert_ne!(tcp.checksum, 0, "checksum must be computed");
    }

    #[test]
    fn urg_cwr_ece_floods_each_light_exactly_their_own_bit() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        // (mode, is_urg, is_cwr, is_ece)
        let cases = [
            (L4Mode::Urg, true, false, false),
            (L4Mode::Cwr, false, true, false),
            (L4Mode::Ece, false, false, true),
        ];
        for (mode, urg, cwr, ece) in cases {
            let flags = mode.raw_tcp_flags().unwrap();
            let pkt = build_tcp_packet(src, dst, 40000, 80, 7, flags).unwrap();
            let (_, tcp) = parse_tcp(&pkt);
            assert_eq!(tcp.urg, urg, "{mode:?} urg");
            assert_eq!(tcp.cwr, cwr, "{mode:?} cwr");
            assert_eq!(tcp.ece, ece, "{mode:?} ece");
            assert!(
                !tcp.syn && !tcp.ack && !tcp.fin && !tcp.rst && !tcp.psh,
                "{mode:?} must light no other flag"
            );
            assert_ne!(tcp.checksum, 0, "{mode:?} checksum must be computed");
        }
    }

    #[test]
    fn illegal_syn_combinations_set_both_contradictory_bits() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();

        let synfin = build_tcp_packet(src, dst, 40000, 80, 5, L4Mode::SynFin.raw_tcp_flags().unwrap()).unwrap();
        let (_, tcp) = parse_tcp(&synfin);
        assert!(tcp.syn && tcp.fin, "SYN+FIN must set both");
        assert!(!tcp.ack && !tcp.rst && !tcp.psh && !tcp.urg, "SYN+FIN sets nothing else");
        assert_ne!(tcp.checksum, 0, "checksum must be computed");

        let synrst = build_tcp_packet(src, dst, 40000, 80, 5, L4Mode::SynRst.raw_tcp_flags().unwrap()).unwrap();
        let (_, tcp) = parse_tcp(&synrst);
        assert!(tcp.syn && tcp.rst, "SYN+RST must set both");
        assert!(!tcp.ack && !tcp.fin && !tcp.psh && !tcp.urg, "SYN+RST sets nothing else");
        assert_ne!(tcp.checksum, 0, "checksum must be computed");
    }

    #[test]
    fn null_flood_sets_no_flags_at_all() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let flags = L4Mode::Null.raw_tcp_flags().unwrap();
        let pkt = build_tcp_packet(src, dst, 40000, 80, 42, flags).unwrap();
        let (_, tcp) = parse_tcp(&pkt);
        assert!(
            !tcp.syn && !tcp.ack && !tcp.fin && !tcp.rst && !tcp.psh && !tcp.urg
                && !tcp.cwr && !tcp.ece,
            "NULL must set no control flag"
        );
        assert_ne!(tcp.checksum, 0, "checksum must be computed");
    }

    #[test]
    fn tcp_options_bomb_is_a_syn_with_a_full_40_byte_option_block() {
        use etherparse::TcpOptionElement;
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let pkt = build_tcp_options_syn(src, dst, 40000, 80, 777).unwrap();
        let (_, tcp) = parse_tcp(&pkt);

        assert!(tcp.syn, "the options bomb is a SYN");
        assert!(!tcp.ack && !tcp.rst && !tcp.fin, "no other control flag is set");
        assert_eq!(tcp.options.as_slice().len(), 40, "must fill the 40-byte option maximum");
        assert_eq!(tcp.data_offset(), 15, "max data offset: 5 fixed + 40/4 option words");
        assert_ne!(tcp.checksum, 0, "checksum must be computed");

        // The negotiated options the target is forced to parse are actually there.
        let elems: Vec<_> = tcp.options_iterator().map(|r| r.expect("valid option")).collect();
        assert!(
            elems.iter().any(|e| matches!(e, TcpOptionElement::MaximumSegmentSize(_))),
            "MSS present"
        );
        assert!(
            elems.iter().any(|e| matches!(e, TcpOptionElement::Timestamp(_, _))),
            "timestamp present"
        );
        assert!(
            elems.iter().any(|e| matches!(e, TcpOptionElement::SelectiveAcknowledgementPermitted)),
            "SACK-permitted present"
        );
    }

    #[test]
    fn plain_syn_carries_no_options_unlike_the_bomb() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let plain = build_tcp_packet(src, dst, 40000, 80, 1, L4Mode::Syn.raw_tcp_flags().unwrap()).unwrap();
        let (_, tcp) = parse_tcp(&plain);
        assert_eq!(tcp.options.as_slice().len(), 0, "the flag floods carry no options");
        assert_eq!(tcp.data_offset(), 5, "minimum data offset when there are no options");
    }

    /// One's-complement sum of a whole ICMP message must be 0xFFFF for the
    /// checksum to verify.
    fn icmp_checksum_verifies(pkt: &[u8]) -> bool {
        let mut sum = 0u32;
        for c in pkt.chunks(2) {
            let word = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { (c[0] as u16) << 8 };
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16 == 0xFFFF
    }

    #[test]
    fn icmp_echo_is_well_formed_with_valid_checksum() {
        let pkt = build_icmp_query(IcmpQuery::Echo, 0x1234, 7, b"ping");
        assert_eq!(pkt[0], 8, "type must be echo request");
        assert_eq!(pkt[1], 0, "code must be 0");
        assert_eq!(&pkt[4..6], &0x1234u16.to_be_bytes(), "identifier");
        assert_eq!(&pkt[6..8], &7u16.to_be_bytes(), "sequence");
        assert_eq!(&pkt[8..], b"ping", "payload");
        assert!(icmp_checksum_verifies(&pkt), "checksum must verify");
    }

    #[test]
    fn icmp_timestamp_is_a_20_byte_message_with_valid_checksum() {
        let pkt = build_icmp_query(IcmpQuery::Timestamp, 0xBEEF, 9, b"ignored");
        assert_eq!(pkt.len(), 20, "timestamp message is header + 3x32-bit timestamps");
        assert_eq!(pkt[0], 13, "type must be timestamp request");
        assert_eq!(pkt[1], 0, "code must be 0");
        assert_eq!(&pkt[8..12], &9u32.to_be_bytes(), "originate timestamp = sequence");
        assert_eq!(&pkt[12..20], &[0u8; 8], "receive/transmit zero in a request");
        assert!(icmp_checksum_verifies(&pkt), "checksum must verify");
    }

    #[test]
    fn icmp_address_mask_is_a_12_byte_message_with_valid_checksum() {
        let pkt = build_icmp_query(IcmpQuery::AddressMask, 0x0042, 3, b"ignored");
        assert_eq!(pkt.len(), 12, "address-mask message is header + 4-byte mask");
        assert_eq!(pkt[0], 17, "type must be address-mask request");
        assert_eq!(pkt[1], 0, "code must be 0");
        assert_eq!(&pkt[8..12], &[0u8; 4], "mask is zero in a request");
        assert!(icmp_checksum_verifies(&pkt), "checksum must verify");
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
    fn raw_tcp_modes_map_to_their_flags_and_labels() {
        // Every raw-TCP mode yields flags and needs a raw socket; the socket-based
        // and ICMP modes yield none.
        for mode in [
            L4Mode::Syn,
            L4Mode::Ack,
            L4Mode::Fin,
            L4Mode::Rst,
            L4Mode::Urg,
            L4Mode::Cwr,
            L4Mode::Ece,
            L4Mode::SynFin,
            L4Mode::SynRst,
            L4Mode::Xmas,
            L4Mode::Null,
            L4Mode::TcpOptions,
        ] {
            assert!(mode.raw_tcp_flags().is_some(), "{mode:?} should map to flags");
            assert!(mode.needs_raw_socket(), "{mode:?} needs a raw socket");
        }
        assert_eq!(L4Mode::Udp.raw_tcp_flags(), None);
        assert_eq!(L4Mode::TcpConnect.raw_tcp_flags(), None);
        assert_eq!(L4Mode::Icmp.raw_tcp_flags(), None);
        assert!(!L4Mode::Udp.needs_raw_socket());
        assert_eq!(L4Mode::Rst.label(), "tcp-rst-flood");
        assert_eq!(L4Mode::Urg.label(), "tcp-urg-flood");
        assert_eq!(L4Mode::Cwr.label(), "tcp-cwr-flood");
        assert_eq!(L4Mode::Ece.label(), "tcp-ece-flood");
        assert_eq!(L4Mode::SynFin.label(), "tcp-syn-fin-flood");
        assert_eq!(L4Mode::SynRst.label(), "tcp-syn-rst-flood");
        assert_eq!(L4Mode::Xmas.label(), "tcp-xmas-flood");
        assert_eq!(L4Mode::Null.label(), "tcp-null-flood");
        assert_eq!(L4Mode::TcpOptions.label(), "tcp-options-flood");
    }

    #[test]
    fn rate_zero_sends_nothing() {
        // Rate 0 must be honoured deterministically, without opening a socket.
        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(config(L4Mode::Udp, 9, 64));
        let report = engine.execute(&plan(vec![t], 0, 1));
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
        let report = engine.execute(&plan(vec![host_target], 100, 1));
        assert_eq!(report.units_sent, 0);
        assert!(report.aborted_early);
        assert!(report.layer_label.contains("ERROR"), "got: {}", report.layer_label);
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
            // And execute() is fail-closed on its own (aborted, nothing sent).
            let mut engine = engine;
            let report = engine.execute(&p);
            assert_eq!(report.units_sent, 0);
            assert!(report.aborted_early);
            assert!(report.layer_label.contains("ERROR"), "got: {}", report.layer_label);
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
        let report = engine.execute(&plan(vec![t], rate, secs));

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
        let report = engine.execute(&plan(vec![t], 300, 1));

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
        let report = engine.execute(&plan(vec![t], 100, 1));

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
        let report = engine.execute(&plan(vec![t], 20, 1));

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
        let report = engine.execute(&plan(vec![t], 10_000, SECS));

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
        let report = engine.execute(&plan(vec![t], 200, 1));
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
        let report = engine.execute(&plan(vec![t], 200, 1));
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
        let report = engine.execute(&plan(vec![t], 200, 1));
        assert!(report.units_sent > 0, "should have sent datagrams");
        assert_eq!(report.errors, 0);

        let mut buf = [0u8; 64];
        assert!(listener.recv_from(&mut buf).is_ok(), "listener should receive at least one datagram");
    }

    /// The batching arithmetic, which is what keeps `--rate` a hard ceiling.
    #[test]
    fn batching_holds_the_requested_rate_exactly() {
        // Rates a sleep can pace one unit at a time are left alone.
        for per_sec in [1u64, 10, 100, 1000] {
            let interval = RateCap::new(per_sec).min_interval().unwrap();
            let (batch, tick) = batch_for(interval);
            assert_eq!(batch, 1, "{per_sec}/s should not batch");
            assert_eq!(tick, interval, "{per_sec}/s tick should be the interval");
        }

        // Above that, the tick becomes the quantum — and `batch / tick` must
        // still be the requested rate, or the cap would be a lie in either
        // direction.
        for per_sec in [2_000u64, 20_000, 200_000, 1_000_000] {
            let interval = RateCap::new(per_sec).min_interval().unwrap();
            let (batch, tick) = batch_for(interval);
            assert!(batch > 1, "{per_sec}/s should batch");
            assert!(tick >= MIN_TICK, "{per_sec}/s tick {tick:?} must be sleepable");
            let effective = batch as f64 / tick.as_secs_f64();
            let drift = (effective - per_sec as f64).abs() / per_sec as f64;
            assert!(
                drift < 0.001,
                "{per_sec}/s batches to {batch} per {tick:?} = {effective:.1}/s"
            );
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
        let report = engine.execute(&plan(vec![t], requested, secs));

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
        let _ = engine.execute(&plan(vec![t], 500_000, 1));
        let elapsed = wall.elapsed();
        assert!(
            elapsed < Duration::from_millis(1400),
            "a 1s run at 500000/s took {elapsed:?}"
        );
    }
}

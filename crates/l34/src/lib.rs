//! # jinrai-l34 — L3/L4 traffic generation (isolated-lab use only)
//!
//! Direct stress primitives against **allowlisted** targets:
//!   - **UDP flood** — datagrams to `target:port` (no privilege needed);
//!   - **TCP connect flood** — full-handshake connections held open to exercise
//!     the connection table / backlog (no privilege needed);
//!   - **TCP flag floods** — crafted IPv4+TCP packets with a single control flag
//!     set (SYN / ACK / FIN / RST) via a raw socket (requires `CAP_NET_RAW`/root).
//!     SYN exercises the accept backlog; ACK/FIN/RST exercise the target's
//!     connection-tracking / stateful-firewall state for packets outside an
//!     established connection.
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

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use jinrai_core::{Layer, RunPlan, RunReport, StressModule};

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
    /// ICMP echo-request flood (raw socket, L3). IPv4-only; source is the
    /// kernel-assigned real address (the kernel builds the IP header).
    Icmp,
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
}

impl TcpFlags {
    /// No flag set — the NULL segment, and the base for the named constructors.
    const NONE: TcpFlags =
        TcpFlags { syn: false, ack: false, fin: false, rst: false, psh: false, urg: false };
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
            L4Mode::Xmas => "tcp-xmas-flood",
            L4Mode::Null => "tcp-null-flood",
            L4Mode::Data => "tcp-data-flood",
            L4Mode::Icmp => "icmp-echo-flood",
        }
    }

    /// The TCP flags for a raw-TCP flood mode, or `None` for every other mode
    /// (UDP / TCP-connect need no raw socket; ICMP is not TCP).
    fn raw_tcp_flags(self) -> Option<TcpFlags> {
        match self {
            L4Mode::Syn => Some(TcpFlags { syn: true, ..TcpFlags::NONE }),
            L4Mode::Ack => Some(TcpFlags { ack: true, ..TcpFlags::NONE }),
            L4Mode::Fin => Some(TcpFlags { fin: true, ..TcpFlags::NONE }),
            L4Mode::Rst => Some(TcpFlags { rst: true, ..TcpFlags::NONE }),
            // Xmas lights FIN+PSH+URG at once; NULL sets nothing at all.
            L4Mode::Xmas => Some(TcpFlags { fin: true, psh: true, urg: true, ..TcpFlags::NONE }),
            L4Mode::Null => Some(TcpFlags::NONE),
            // Data flood uses the OS TCP stack (no crafted packet), like TcpConnect.
            L4Mode::Udp | L4Mode::TcpConnect | L4Mode::Data | L4Mode::Icmp => None,
        }
    }

    /// Raw-socket modes craft packets on a raw socket (need CAP_NET_RAW) and are
    /// IPv4-only: the six TCP flag floods plus the ICMP echo flood.
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
        } else if self == L4Mode::Icmp {
            Some(Protocol::ICMPV4)
        } else {
            None
        }
    }

    /// Which OSI layer this mode drives: ICMP is L3, everything else L4.
    fn layer(self) -> Layer {
        if self == L4Mode::Icmp {
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
        let label = if self.config.mode == L4Mode::Icmp {
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

        let mut sender = Sender::setup(self.config.mode, self.config.payload_size, &ips)?;

        let mut sent = 0u64;
        let mut errors = 0u64;
        let mut aborted = false;
        let mut idx = 0usize;

        let start = Instant::now();
        let mut next = start;
        while start.elapsed() < plan.duration {
            if plan.kill.is_tripped() {
                aborted = true;
                break;
            }
            let ip = ips[idx % ips.len()];
            idx += 1;
            match sender.send(ip, self.config.port) {
                Ok(()) => sent += 1,
                Err(_) => errors += 1,
            }

            next += interval;
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

        Ok(RunReport {
            layer_label: label,
            units_sent: sent,
            errors,
            aborted_early: aborted,
            ..Default::default()
        })
    }
}

/// Per-mode socket state, created once before the send loop.
enum Sender {
    Udp { sock: UdpSocket, payload: Vec<u8> },
    Tcp { held: Vec<TcpStream>, timeout: Duration },
    /// TCP data (PSH-ACK) flood: a bounded pool of established connections that we
    /// write application data into. `idx` round-robins writes across the pool;
    /// dead connections are dropped and replaced. `timeout` bounds both connect
    /// and each write (a write that blocks on a full buffer is *pressure applied*,
    /// not a failure).
    TcpData { conns: Vec<TcpStream>, payload: Vec<u8>, timeout: Duration, idx: usize },
    /// Raw IPv4+TCP flag flood (SYN/ACK/FIN/RST/Xmas/NULL). `flags` selects which
    /// control flags are set; everything else is shared.
    RawTcp { flags: TcpFlags, raw: Socket, srcs: HashMap<IpAddr, Ipv4Addr>, counter: u32 },
    /// Raw ICMPv4 echo-request flood. The kernel supplies the IP header (real
    /// source address); we craft the ICMP echo message + checksum. `id` tags this
    /// run; `counter` is the per-packet sequence number. `payload` is a fixed body.
    Icmp { raw: Socket, id: u16, counter: u16, payload: Vec<u8> },
}

/// UDP payloads above this are rejected to avoid accidental fragmentation.
const MAX_UDP_PAYLOAD: usize = 1472;

/// TCP-data-flood tunables. The pool is bounded so the flood establishes a fixed
/// number of connections and then sustains data on them (rather than growing
/// unboundedly like the connect flood). The per-write payload is capped well
/// above a single segment — TCP handles segmentation — to push more per write.
const MAX_DATA_CONNS: usize = 128;
const MAX_DATA_PAYLOAD: usize = 65_536;

impl Sender {
    fn setup(mode: L4Mode, payload_size: usize, _ips: &[IpAddr]) -> Result<Self, L34Error> {
        match mode {
            L4Mode::Udp => {
                let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                    .map_err(|e| L34Error::Setup(e.to_string()))?;
                let payload = vec![0u8; payload_size.min(MAX_UDP_PAYLOAD)];
                Ok(Sender::Udp { sock, payload })
            }
            L4Mode::TcpConnect => Ok(Sender::Tcp {
                held: Vec::new(),
                timeout: Duration::from_millis(500),
            }),
            L4Mode::Data => Ok(Sender::TcpData {
                conns: Vec::new(),
                // Non-zero, bounded payload for each PSH-ACK write.
                payload: vec![0u8; payload_size.clamp(1, MAX_DATA_PAYLOAD)],
                timeout: Duration::from_millis(500),
                idx: 0,
            }),
            L4Mode::Icmp => {
                let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                    .map_err(|e| L34Error::RawSocket(e.to_string()))?;
                // Payload capped like UDP to avoid accidental fragmentation.
                let payload = vec![0u8; payload_size.min(MAX_UDP_PAYLOAD)];
                // Identifier from the PID, so replies (if any) are attributable.
                let id = std::process::id() as u16;
                Ok(Sender::Icmp { raw, id, counter: 0, payload })
            }
            other => {
                // SYN/ACK/FIN/RST/Xmas/NULL: all raw-TCP flag floods share one setup.
                let flags = other
                    .raw_tcp_flags()
                    .expect("setup reached with a non-raw-TCP mode");
                let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
                    .map_err(|e| L34Error::RawSocket(e.to_string()))?;
                Ok(Sender::RawTcp { flags, raw, srcs: HashMap::new(), counter: 0 })
            }
        }
    }

    fn send(&mut self, ip: IpAddr, port: u16) -> Result<(), L34Error> {
        match self {
            Sender::Udp { sock, payload } => sock
                .send_to(payload, SocketAddr::new(ip, port))
                .map(|_| ())
                .map_err(|e| L34Error::Setup(e.to_string())),

            Sender::Tcp { held, timeout } => {
                let stream = TcpStream::connect_timeout(&SocketAddr::new(ip, port), *timeout)
                    .map_err(|e| L34Error::Setup(e.to_string()))?;
                // Hold the connection open to exercise the target's connection
                // table / backlog; dropped when the run ends.
                held.push(stream);
                Ok(())
            }

            Sender::TcpData { conns, payload, timeout, idx } => {
                // Below the pool cap, each send opens a new connection and primes
                // it with a write — this ramps the pool up. Once full, we sustain
                // data by round-robining a write onto an existing connection.
                if conns.len() < MAX_DATA_CONNS {
                    let mut stream =
                        TcpStream::connect_timeout(&SocketAddr::new(ip, port), *timeout)
                            .map_err(|e| L34Error::Setup(e.to_string()))?;
                    let _ = stream.set_write_timeout(Some(*timeout));
                    write_pshack(&mut stream, payload);
                    conns.push(stream);
                    return Ok(());
                }
                // Round-robin one connection; a full send buffer is pressure
                // applied (counts as sent), a real error retires the connection
                // and we open a fresh one to replace it.
                let n = conns.len();
                *idx = (*idx + 1) % n;
                let i = *idx;
                match write_pshack(&mut conns[i], payload) {
                    WriteOutcome::Sent => Ok(()),
                    WriteOutcome::Dead => {
                        conns.swap_remove(i);
                        let mut stream =
                            TcpStream::connect_timeout(&SocketAddr::new(ip, port), *timeout)
                                .map_err(|e| L34Error::Setup(e.to_string()))?;
                        let _ = stream.set_write_timeout(Some(*timeout));
                        write_pshack(&mut stream, payload);
                        conns.push(stream);
                        Ok(())
                    }
                }
            }

            Sender::RawTcp { flags, raw, srcs, counter } => {
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
                let packet = build_tcp_packet(src, dst, src_port, port, *counter, *flags)?;
                let dest = SockAddr::from(SocketAddr::new(IpAddr::V4(dst), 0));
                raw.send_to(&packet, &dest)
                    .map(|_| ())
                    .map_err(|e| L34Error::Setup(e.to_string()))
            }

            Sender::Icmp { raw, id, counter, payload } => {
                let dst = match ip {
                    IpAddr::V4(v4) => v4,
                    // check_targets refuses IPv6 for ICMP up front; this is defensive.
                    IpAddr::V6(_) => return Err(L34Error::Ipv6RawTcpUnsupported(ip)),
                };
                *counter = counter.wrapping_add(1);
                let packet = build_icmp_echo(*id, *counter, payload);
                // Port is irrelevant for ICMP; the kernel builds the IP header from
                // the real source address (IPPROTO_ICMP), so there is no spoof path.
                let dest = SockAddr::from(SocketAddr::new(IpAddr::V4(dst), 0));
                raw.send_to(&packet, &dest)
                    .map(|_| ())
                    .map_err(|e| L34Error::Setup(e.to_string()))
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
    let mut out = Vec::with_capacity(b.size(0));
    b.write(&mut out, &[])
        .map_err(|e| L34Error::Build(e.to_string()))?;
    Ok(out)
}

/// Build an ICMPv4 echo-request message (type 8, code 0) with its checksum. The
/// kernel prepends the IPv4 header (real source address), so we only craft the
/// ICMP message itself: header + `payload`.
fn build_icmp_echo(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(8 + payload.len());
    pkt.push(8); // type: echo request
    pkt.push(0); // code
    pkt.extend_from_slice(&[0, 0]); // checksum placeholder
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(payload);
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
    fn null_flood_sets_no_flags_at_all() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let flags = L4Mode::Null.raw_tcp_flags().unwrap();
        let pkt = build_tcp_packet(src, dst, 40000, 80, 42, flags).unwrap();
        let (_, tcp) = parse_tcp(&pkt);
        assert!(
            !tcp.syn && !tcp.ack && !tcp.fin && !tcp.rst && !tcp.psh && !tcp.urg,
            "NULL must set no control flag"
        );
        assert_ne!(tcp.checksum, 0, "checksum must be computed");
    }

    #[test]
    fn icmp_echo_is_well_formed_with_valid_checksum() {
        let pkt = build_icmp_echo(0x1234, 7, b"ping");
        assert_eq!(pkt[0], 8, "type must be echo request");
        assert_eq!(pkt[1], 0, "code must be 0");
        assert_eq!(&pkt[4..6], &0x1234u16.to_be_bytes(), "identifier");
        assert_eq!(&pkt[6..8], &7u16.to_be_bytes(), "sequence");
        assert_eq!(&pkt[8..], b"ping", "payload");
        // A correct Internet checksum makes the one's-complement sum of the whole
        // message equal 0xFFFF (i.e. the checksum verifies).
        let mut sum = 0u32;
        for c in pkt.chunks(2) {
            let word = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { (c[0] as u16) << 8 };
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF, "checksum must verify");
    }

    #[test]
    fn icmp_is_layer_l3_and_needs_a_raw_socket() {
        let engine = L34Engine::new(L34Config { mode: L4Mode::Icmp, port: 0, payload_size: 32 });
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
        for mode in [L4Mode::Syn, L4Mode::Ack, L4Mode::Fin, L4Mode::Rst, L4Mode::Xmas, L4Mode::Null] {
            assert!(mode.raw_tcp_flags().is_some(), "{mode:?} should map to flags");
            assert!(mode.needs_raw_socket(), "{mode:?} needs a raw socket");
        }
        assert_eq!(L4Mode::Udp.raw_tcp_flags(), None);
        assert_eq!(L4Mode::TcpConnect.raw_tcp_flags(), None);
        assert_eq!(L4Mode::Icmp.raw_tcp_flags(), None);
        assert!(!L4Mode::Udp.needs_raw_socket());
        assert_eq!(L4Mode::Rst.label(), "tcp-rst-flood");
        assert_eq!(L4Mode::Xmas.label(), "tcp-xmas-flood");
        assert_eq!(L4Mode::Null.label(), "tcp-null-flood");
    }

    #[test]
    fn rate_zero_sends_nothing() {
        // Rate 0 must be honoured deterministically, without opening a socket.
        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(L34Config {
            mode: L4Mode::Udp,
            port: 9,
            payload_size: 64,
        });
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
        let mut engine = L34Engine::new(L34Config {
            mode: L4Mode::Udp,
            port: 9,
            payload_size: 64,
        });
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
            L4Mode::Xmas,
            L4Mode::Null,
            L4Mode::Icmp,
        ] {
            let t = authorized_ip("::1/128", "::1");
            let engine = L34Engine::new(L34Config { mode, port: 9, payload_size: 16 });
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
        let engine = L34Engine::new(L34Config {
            mode: L4Mode::TcpConnect,
            port: 9,
            payload_size: 16,
        });
        assert!(engine.preflight(&plan(vec![t], 50, 1)).is_ok());
    }

    #[test]
    fn data_flood_delivers_bytes_to_a_local_listener() {
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
        let mut engine = L34Engine::new(L34Config {
            mode: L4Mode::Data,
            port,
            payload_size: 512,
        });
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
        let engine = L34Engine::new(L34Config { mode: L4Mode::Data, port: 9, payload_size: 16 });
        assert!(engine.preflight(&plan(vec![t], 50, 1)).is_ok());
    }

    #[test]
    fn udp_flood_sends_to_local_listener() {
        // Bind a UDP listener and confirm the flood actually delivers datagrams.
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let t = authorized_ip("127.0.0.0/8", "127.0.0.1");
        let mut engine = L34Engine::new(L34Config {
            mode: L4Mode::Udp,
            port,
            payload_size: 16,
        });
        let report = engine.execute(&plan(vec![t], 200, 1));
        assert!(report.units_sent > 0, "should have sent datagrams");
        assert_eq!(report.errors, 0);

        let mut buf = [0u8; 64];
        assert!(listener.recv_from(&mut buf).is_ok(), "listener should receive at least one datagram");
    }
}

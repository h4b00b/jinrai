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
}

/// The single TCP control flag a raw-TCP flood sets. All raw-TCP modes share the
/// same packet-crafting, socket, and no-spoofing machinery; they differ only in
/// which one flag is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpFlag {
    Syn,
    Ack,
    Fin,
    Rst,
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
        }
    }

    /// The TCP flag for a raw-TCP flood mode, or `None` for the socket-based
    /// (UDP / TCP-connect) modes that need no raw socket.
    fn raw_tcp_flag(self) -> Option<TcpFlag> {
        match self {
            L4Mode::Syn => Some(TcpFlag::Syn),
            L4Mode::Ack => Some(TcpFlag::Ack),
            L4Mode::Fin => Some(TcpFlag::Fin),
            L4Mode::Rst => Some(TcpFlag::Rst),
            L4Mode::Udp | L4Mode::TcpConnect => None,
        }
    }

    /// Raw-TCP flood modes craft IPv4 packets on a raw socket (needs CAP_NET_RAW)
    /// and are IPv4-only.
    fn needs_raw_socket(self) -> bool {
        self.raw_tcp_flag().is_some()
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
                "cannot open raw socket for a TCP flag flood ({e}); needs CAP_NET_RAW/root \
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
        if self.config.mode.needs_raw_socket() {
            // Opening (and immediately dropping) the raw socket surfaces a missing
            // CAP_NET_RAW now rather than mid-run with a zero-sent report.
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
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
        Layer::L4
    }

    fn name(&self) -> &str {
        self.config.mode.label()
    }

    fn execute(&mut self, plan: &RunPlan) -> RunReport {
        match self.run(plan) {
            Ok(report) => report,
            Err(e) => RunReport {
                layer_label: format!("L4 {} ERROR: {e}", self.config.mode.label()),
                aborted_early: true,
                ..Default::default()
            },
        }
    }
}

impl L34Engine {
    fn run(&self, plan: &RunPlan) -> Result<RunReport, L34Error> {
        // L3/L4 only ever acts on IP data, and only on a family this mode can
        // reach. Any host-name target, empty plan, or unreachable IPv6 is refused
        // here too (not just in preflight) so `execute()` is fail-closed on its own.
        self.check_targets(plan)?;
        let ips: Vec<IpAddr> = plan.targets.iter().filter_map(|t| t.as_ip()).collect();

        let label = format!(
            "L4 {} -> port {} ({} target{})",
            self.config.mode.label(),
            self.config.port,
            ips.len(),
            if ips.len() == 1 { "" } else { "s" }
        );

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
    /// Raw IPv4+TCP flag flood (SYN/ACK/FIN/RST). `flag` selects which one control
    /// flag is set; everything else is shared.
    RawTcp { flag: TcpFlag, raw: Socket, srcs: HashMap<IpAddr, Ipv4Addr>, counter: u32 },
}

/// UDP payloads above this are rejected to avoid accidental fragmentation.
const MAX_UDP_PAYLOAD: usize = 1472;

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
            other => {
                // SYN / ACK / FIN / RST: all raw-TCP flag floods share one setup.
                let flag = other
                    .raw_tcp_flag()
                    .expect("setup reached with a non-raw-TCP mode");
                let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
                    .map_err(|e| L34Error::RawSocket(e.to_string()))?;
                Ok(Sender::RawTcp { flag, raw, srcs: HashMap::new(), counter: 0 })
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

            Sender::RawTcp { flag, raw, srcs, counter } => {
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
                let packet = build_tcp_flag(src, dst, src_port, port, *counter, *flag)?;
                let dest = SockAddr::from(SocketAddr::new(IpAddr::V4(dst), 0));
                raw.send_to(&packet, &dest)
                    .map(|_| ())
                    .map_err(|e| L34Error::Setup(e.to_string()))
            }
        }
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

/// Build a complete IPv4 + TCP packet (no payload) with correct checksums and a
/// single control flag set. The source address is the caller-supplied real
/// route-local address — there is no spoofing path.
fn build_tcp_flag(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    flag: TcpFlag,
) -> Result<Vec<u8>, L34Error> {
    use etherparse::PacketBuilder;
    let base = PacketBuilder::ipv4(src.octets(), dst.octets(), 64).tcp(src_port, dst_port, seq, 64_240);
    // Each mode sets exactly one control flag. ACK carries an acknowledgement
    // number (the flag is meaningless without one); the rest are bare flags.
    let builder = match flag {
        TcpFlag::Syn => base.syn(),
        TcpFlag::Ack => base.ack(seq.wrapping_add(1)),
        TcpFlag::Fin => base.fin(),
        TcpFlag::Rst => base.rst(),
    };
    let mut out = Vec::with_capacity(builder.size(0));
    builder
        .write(&mut out, &[])
        .map_err(|e| L34Error::Build(e.to_string()))?;
    Ok(out)
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
        let pkt = build_tcp_flag(src, dst, 40000, 80, 12345, TcpFlag::Syn).unwrap();

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
    fn each_flag_flood_sets_exactly_its_own_flag() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        // (flag, is_syn, is_ack, is_fin, is_rst)
        let cases = [
            (TcpFlag::Syn, true, false, false, false),
            (TcpFlag::Ack, false, true, false, false),
            (TcpFlag::Fin, false, false, true, false),
            (TcpFlag::Rst, false, false, false, true),
        ];
        for (flag, syn, ack, fin, rst) in cases {
            let pkt = build_tcp_flag(src, dst, 40000, 80, 999, flag).unwrap();
            let (_, tcp) = parse_tcp(&pkt);
            assert_eq!(tcp.syn, syn, "{flag:?} syn");
            assert_eq!(tcp.ack, ack, "{flag:?} ack");
            assert_eq!(tcp.fin, fin, "{flag:?} fin");
            assert_eq!(tcp.rst, rst, "{flag:?} rst");
            assert_ne!(tcp.checksum, 0, "{flag:?} checksum must be computed");
        }
    }

    #[test]
    fn raw_tcp_modes_map_to_their_flag_and_labels() {
        assert_eq!(L4Mode::Syn.raw_tcp_flag(), Some(TcpFlag::Syn));
        assert_eq!(L4Mode::Ack.raw_tcp_flag(), Some(TcpFlag::Ack));
        assert_eq!(L4Mode::Fin.raw_tcp_flag(), Some(TcpFlag::Fin));
        assert_eq!(L4Mode::Rst.raw_tcp_flag(), Some(TcpFlag::Rst));
        assert_eq!(L4Mode::Udp.raw_tcp_flag(), None);
        assert_eq!(L4Mode::TcpConnect.raw_tcp_flag(), None);
        assert!(L4Mode::Ack.needs_raw_socket() && !L4Mode::Udp.needs_raw_socket());
        assert_eq!(L4Mode::Rst.label(), "tcp-rst-flood");
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
        for mode in [L4Mode::Udp, L4Mode::Syn, L4Mode::Ack, L4Mode::Fin, L4Mode::Rst] {
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

//! Which primitive a run drives, and the configuration it carries.
//!
//! This module is deliberately inert: it decides *what* a mode is — its label,
//! its OSI layer, which control flags it sets, whether it needs a raw socket —
//! and holds no sockets, no counters and no traffic path. Everything here is a
//! pure function of the mode, which is what makes the table of eighteen
//! primitives readable as a table rather than as an engine.

use std::time::Duration;

use socket2::Protocol;

use jinrai_core::Layer;

use crate::packet::IPPROTO_RAW;
use crate::ports::PortSet;

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
    /// TCP SYN+ACK flood (raw socket) — an *unsolicited* handshake response: the
    /// second segment of a three-way handshake arriving at a host that never sent
    /// the first. Unlike the flag combinations below it this one is perfectly
    /// legal on the wire; what makes it a test is that it matches no connection,
    /// so the target must either allocate/consult connection-tracking state or
    /// answer each packet with an RST — the classic SYN-ACK reflection load a
    /// firewall or load balancer sees during a spoofed flood elsewhere.
    SynAck,
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
pub(crate) enum IcmpQuery {
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
    pub(crate) fn type_byte(self) -> u8 {
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
pub(crate) struct TcpFlags {
    pub(crate) syn: bool,
    pub(crate) ack: bool,
    pub(crate) fin: bool,
    pub(crate) rst: bool,
    pub(crate) psh: bool,
    pub(crate) urg: bool,
    /// ECN Congestion-Window-Reduced.
    pub(crate) cwr: bool,
    /// ECN-Echo.
    pub(crate) ece: bool,
}

impl TcpFlags {
    /// No flag set — the NULL segment, and the base for the named constructors.
    pub(crate) const NONE: TcpFlags = TcpFlags {
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
    pub(crate) fn label(self) -> &'static str {
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
            L4Mode::SynAck => "tcp-syn-ack-flood",
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
    pub(crate) fn icmp_query(self) -> Option<IcmpQuery> {
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
    pub(crate) fn raw_tcp_flags(self) -> Option<TcpFlags> {
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
            // Legal flags, illegal *state*: a handshake response nobody asked for.
            L4Mode::SynAck => Some(TcpFlags { syn: true, ack: true, ..TcpFlags::NONE }),
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
    pub(crate) fn needs_raw_socket(self) -> bool {
        self.raw_socket_protocol().is_some()
    }

    /// The IP protocol for this mode's raw socket, or `None` for the socket-based
    /// (UDP / TCP-connect) modes. Raw TCP uses `IPPROTO_RAW` (we supply the whole
    /// IPv4 header); ICMP uses `IPPROTO_ICMP` (the kernel supplies the IP header,
    /// so the source address is the real one — no spoofing path).
    pub(crate) fn raw_socket_protocol(self) -> Option<Protocol> {
        if self.raw_tcp_flags().is_some() {
            Some(Protocol::from(IPPROTO_RAW))
        } else if self.is_icmp() {
            Some(Protocol::ICMPV4)
        } else {
            None
        }
    }

    /// Which OSI layer this mode drives: ICMP is L3, everything else L4.
    pub(crate) fn layer(self) -> Layer {
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
    /// The primitive(s) this run drives. More than one means a **multi-vector**
    /// run: they are emitted concurrently against the same targets, sharing the
    /// one `--rate` ceiling between them (see [`RateCap::split_across`]).
    ///
    /// A `Vec` rather than a single mode because the multi-vector shapes a test
    /// plan asks for — "UDP MultiVector", "UDP/TCP/ICMP Multivectors" — are not
    /// a new primitive, they are the existing ones running at the same time.
    ///
    /// Never empty; [`L34Config::primary`] is the mode that names the run.
    pub modes: Vec<L4Mode>,
    /// Destination port(s). A one-port set is the ordinary single-service test;
    /// a range or list is what the random-port and carpet-bombing shapes need.
    /// The ICMP modes are portless and carry an unused single set.
    pub ports: PortSet,
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
    /// established ones, and so doubles as the connect flood's parallelism: it is
    /// what lets the run reach `rate` instead of being pinned to one handshake
    /// per round-trip. The descriptor bound is the same number it always was.
    ///
    /// Clamped to at least 1 (see [`L34Config::effective_concurrency`]).
    pub concurrency: usize,
    /// How long a single connection attempt may stay unresolved before it is
    /// abandoned and bucketed as `ErrnoBucket::Timeout`.
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

    /// The mode that names the run: the first, which for a single-vector run is
    /// the only one. Falls back to `Udp` for the empty `modes` a caller should
    /// not be able to build — a default beats a panic in a tool whose contract
    /// is that a primitive which cannot start says so and returns.
    pub fn primary(&self) -> L4Mode {
        self.modes.first().copied().unwrap_or(L4Mode::Udp)
    }

    /// Whether this run drives more than one primitive at once.
    pub fn is_multi_vector(&self) -> bool {
        self.modes.len() > 1
    }

    /// Which OSI layer the run reports as. A run whose vectors are *all* ICMP is
    /// L3; anything else is L4, including a mix — the L4 claim is the stronger
    /// one, and calling a UDP+ICMP run "L3" would understate it.
    pub fn layer(&self) -> Layer {
        if !self.modes.is_empty() && self.modes.iter().all(|m| m.layer() == Layer::L3) {
            Layer::L3
        } else {
            Layer::L4
        }
    }

    /// How the run names itself: the single mode's label, or a joined list for a
    /// multi-vector run. The list is spelled out rather than counted — "3
    /// vectors" in a summary tells a reader nothing about what was sent.
    pub fn label(&self) -> String {
        match self.modes.as_slice() {
            [one] => one.label().to_string(),
            many => {
                format!(
                    "multi-vector [{}]",
                    many.iter().map(|m| m.label()).collect::<Vec<_>>().join(" + ")
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            L4Mode::SynAck,
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
        assert_eq!(L4Mode::SynAck.label(), "tcp-syn-ack-flood");
        assert_eq!(L4Mode::SynFin.label(), "tcp-syn-fin-flood");
        assert_eq!(L4Mode::SynRst.label(), "tcp-syn-rst-flood");
        assert_eq!(L4Mode::Xmas.label(), "tcp-xmas-flood");
        assert_eq!(L4Mode::Null.label(), "tcp-null-flood");
        assert_eq!(L4Mode::TcpOptions.label(), "tcp-options-flood");
    }

    /// The ICMP query modes differ only in their type byte, and none of them is
    /// TCP — a regression here would have an ICMP mode crafting TCP flags.
    #[test]
    fn icmp_query_modes_are_l3_raw_and_carry_no_tcp_flags() {
        for (mode, name, ty) in [
            (L4Mode::Icmp, "icmp-echo-flood", 8u8),
            (L4Mode::IcmpTimestamp, "icmp-timestamp-flood", 13),
            (L4Mode::IcmpAddressMask, "icmp-address-mask-flood", 17),
        ] {
            assert_eq!(mode.layer(), Layer::L3, "{mode:?} is L3");
            assert_eq!(mode.label(), name);
            assert!(mode.is_icmp(), "{mode:?} is an ICMP mode");
            assert!(mode.needs_raw_socket(), "{mode:?} needs a raw socket");
            assert_eq!(mode.raw_tcp_flags(), None, "{mode:?} carries no TCP flags");
            assert_eq!(mode.icmp_query().map(|q| q.type_byte()), Some(ty));
        }
        assert_eq!(L4Mode::Udp.layer(), Layer::L4);
    }
}

//! Packet construction for the raw-socket modes.
//!
//! # This is the no-spoofing surface
//!
//! Everything that decides what goes on the wire below the socket API lives
//! here, and it is a short file on purpose: the crate's central guarantee — that
//! every packet leaves with the host's **real** source address — is a property of
//! these functions, and a reviewer should be able to confirm it without reading
//! an engine.
//!
//! The guarantee holds in two different ways depending on the mode:
//!
//! * **Raw TCP** ([`build_tcp_packet`], [`build_tcp_options_syn`]) crafts the
//!   whole IPv4 header, so the source address is an explicit argument — and the
//!   only value ever passed for it comes from [`source_ipv4_for`], which *asks
//!   the OS* which local address routes to the destination. There is deliberately
//!   no other producer of that argument, no flag that sets it, and no
//!   randomisation path.
//! * **ICMP** ([`build_icmp_query`]) crafts only the ICMP message; the kernel
//!   prepends the IPv4 header, so the source is the real one by construction and
//!   is not expressible here at all.
//!
//! There is no reflection or amplification capability, and the ICMP builder emits
//! only *query* messages the target answers directly — never error, redirect or
//! router-advertisement types, which are meaningful only when spoofed as if from
//! a gateway.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use crate::mode::{IcmpQuery, TcpFlags};
use crate::L34Error;

/// `IPPROTO_RAW` — send-only raw IPv4 socket; the kernel takes our IP header
/// verbatim (IP_HDRINCL is implied), so we craft the whole IPv4+TCP packet.
pub(crate) const IPPROTO_RAW: i32 = 255;

/// Ask the OS which local IPv4 address routes to `dst` by connecting a UDP
/// socket (no packets are sent) and reading its local address. This is the real
/// source — there is no spoofing path.
pub(crate) fn source_ipv4_for(dst: Ipv4Addr, port: u16) -> Result<Ipv4Addr, L34Error> {
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
pub(crate) fn build_tcp_packet(
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
pub(crate) fn build_tcp_options_syn(
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
pub(crate) fn build_icmp_query(query: IcmpQuery, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::L4Mode;

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

    /// The source address that reaches the wire is exactly the one handed in —
    /// the builder never substitutes, randomises or derives a different one.
    #[test]
    fn the_source_address_is_the_one_supplied_and_nothing_else() {
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let syn = L4Mode::Syn.raw_tcp_flags().unwrap();
        for src in ["10.0.0.1", "192.0.2.55", "127.0.0.1"] {
            let src: Ipv4Addr = src.parse().unwrap();
            let (ipv4, _) = parse_tcp(&build_tcp_packet(src, dst, 1, 2, 3, syn).unwrap());
            assert_eq!(ipv4.source, src.octets(), "source must be carried verbatim");
        }
        let bomb = build_tcp_options_syn("192.0.2.55".parse().unwrap(), dst, 1, 2, 3).unwrap();
        let (ipv4, _) = parse_tcp(&bomb);
        assert_eq!(ipv4.source, Ipv4Addr::new(192, 0, 2, 55).octets());
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
}

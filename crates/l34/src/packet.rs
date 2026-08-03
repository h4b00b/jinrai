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
//! * **Fragments and GRE** ([`build_udp_fragments`], [`build_tcp_fragments`],
//!   [`build_gre_packet`]) craft whole IPv4 packets like the raw-TCP path, and
//!   take the same single source argument from the same single producer. The GRE
//!   builder is the one place an address could be written *inside* a payload,
//!   where no kernel would ever check it — so the packet it encapsulates carries
//!   the host's own address too, not a chosen one.
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

/// GRE (RFC 2784) is IP protocol 47.
pub(crate) const IPPROTO_GRE: u8 = 47;

/// IPv4 fragment offsets are counted in 8-byte blocks, so every fragment but the
/// last must carry a length that is a multiple of 8.
const FRAG_BLOCK: usize = 8;

/// The fixed UDP header length — where a fragmented UDP datagram is cut.
const UDP_HEADER_LEN: usize = 8;

/// The 4-byte GRE header of a version-0 packet carrying no optional fields:
/// flags and version all zero (no checksum, no key, no sequence number), then
/// the EtherType of what is encapsulated — `0x0800`, IPv4.
const GRE_HEADER: [u8; 4] = [0x00, 0x00, 0x08, 0x00];

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
        // A v4 destination should always yield a v4 local address, so this arm is
        // unreachable on AF_INET today. It still must not invent an address:
        // substituting a plausible-looking constant here would put a source IP on
        // the wire that the kernel never assigned us, which is the definition of
        // the spoofing path this crate promises not to have. If the OS ever
        // surprises us, refuse the run and say so.
        IpAddr::V6(v6) => Err(L34Error::Setup(format!(
            "a v4 destination resolved to the v6 local address {v6}: refusing to \
             guess a source address (jinrai never puts an address it was not given \
             on the wire)"
        ))),
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

/// Drop the IPv4 header off a packet a builder just produced, leaving the L4
/// bytes. The length comes from the IHL field rather than being assumed to be 20,
/// so a builder that one day emits IP options cannot silently shift the split.
fn ipv4_payload(packet: &[u8]) -> &[u8] {
    match packet.first() {
        Some(first) => {
            let ihl = ((first & 0x0f) as usize) * 4;
            &packet[ihl.min(packet.len())..]
        }
        None => packet,
    }
}

/// Split one datagram's already-checksummed L4 bytes into IPv4 fragments.
///
/// The cut rule is what makes this a *test* rather than an accident of MTU: the
/// datagram is cut at every 8-byte boundary **inside its L4 header**, and
/// whatever is left becomes the final fragment. So the first fragment carries
/// only part of the transport header — a fragmented TCP SYN puts its ports in
/// fragment 0 and its *flags* in fragment 1 — and nothing on the path can read
/// the ports, the flags, or the payload without holding the pieces and
/// reassembling them. That reassembly state, per datagram, for as long as the
/// target's fragment timeout, is the load being offered.
///
/// The source address is the caller's real one, exactly as in
/// [`build_tcp_packet`]; fragmentation changes what a packet is cut into, never
/// who it claims to be from.
fn build_ipv4_fragments(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: etherparse::IpNumber,
    inner: &[u8],
    l4_header_len: usize,
    id: u16,
) -> Result<Vec<Vec<u8>>, L34Error> {
    use etherparse::{IpFragOffset, Ipv4Header};

    let mut cuts = Vec::new();
    let mut at = FRAG_BLOCK;
    while at <= l4_header_len && at < inner.len() {
        cuts.push(at);
        at += FRAG_BLOCK;
    }

    let mut out = Vec::with_capacity(cuts.len() + 1);
    let mut start = 0usize;
    for end in cuts.into_iter().chain(std::iter::once(inner.len())) {
        let chunk = &inner[start..end];
        let len = u16::try_from(chunk.len())
            .map_err(|_| L34Error::Build("fragment longer than an IPv4 payload".into()))?;
        let mut header = Ipv4Header::new(len, 64, protocol, src.octets(), dst.octets())
            .map_err(|e| L34Error::Build(e.to_string()))?;
        // One identification value per datagram. Without it every fragment of
        // every unit would claim to belong to the *same* datagram, and the target
        // would keep overwriting one reassembly entry instead of accumulating the
        // many this is meant to make it hold.
        header.identification = id;
        header.dont_fragment = false;
        header.more_fragments = end < inner.len();
        header.fragment_offset = IpFragOffset::try_new((start / FRAG_BLOCK) as u16)
            .map_err(|e| L34Error::Build(e.to_string()))?;
        let mut pkt = Vec::with_capacity(Ipv4Header::MIN_LEN + chunk.len());
        // `write` recomputes the header checksum, which has to happen *after* the
        // fragment fields are set — they are covered by it.
        header.write(&mut pkt).map_err(|e| L34Error::Build(e.to_string()))?;
        pkt.extend_from_slice(chunk);
        out.push(pkt);
        start = end;
    }
    Ok(out)
}

/// Build the IPv4 fragments of one UDP datagram: the 8-byte UDP header in
/// fragment 0, the payload in fragment 1. The UDP checksum is computed over the
/// whole datagram before it is cut, so the pieces only verify once reassembled.
pub(crate) fn build_udp_fragments(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    id: u16,
) -> Result<Vec<Vec<u8>>, L34Error> {
    use etherparse::{IpNumber, PacketBuilder};
    let b = PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(src_port, dst_port);
    let mut whole = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut whole, payload)
        .map_err(|e| L34Error::Build(e.to_string()))?;
    build_ipv4_fragments(src, dst, IpNumber::UDP, ipv4_payload(&whole), UDP_HEADER_LEN, id)
}

/// Build the IPv4 fragments of one TCP segment — a SYN, so the target must decide
/// whether to open a connection it can only see after reassembly. A 20-byte TCP
/// header cut on 8-byte boundaries gives three fragments (8 + 8 + 4): ports in
/// the first, control flags in the second.
pub(crate) fn build_tcp_fragments(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    flags: TcpFlags,
    id: u16,
) -> Result<Vec<Vec<u8>>, L34Error> {
    use etherparse::IpNumber;
    let whole = build_tcp_packet(src, dst, src_port, dst_port, seq, flags)?;
    let inner = ipv4_payload(&whole);
    // Data offset (high nibble of byte 12) in 4-byte words. The segment built
    // above carries no options, so this is 20 — read rather than assumed so the
    // cut still lands inside the header if that ever changes.
    let header_len = inner.get(12).map_or(20, |b| ((b >> 4) as usize) * 4);
    build_ipv4_fragments(src, dst, IpNumber::TCP, inner, header_len, id)
}

/// Build one GRE (RFC 2784) packet: an IPv4 header with protocol 47, the 4-byte
/// version-0 GRE header, and an encapsulated IPv4/UDP datagram.
///
/// What this tests is the decapsulation path — a router, firewall or tunnel
/// endpoint that accepts protocol 47 has to recognise it, strip the outer header,
/// and hand an inner packet to the IP stack a second time, which is roughly twice
/// the per-packet work of the flood that carries it.
///
/// The encapsulated datagram is addressed from the same real source to the same
/// target. A GRE payload is the one place a source address could be written where
/// no kernel would validate it, and this builder deliberately has no argument
/// with which to write a different one.
pub(crate) fn build_gre_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    id: u16,
) -> Result<Vec<u8>, L34Error> {
    use etherparse::{IpNumber, Ipv4Header, PacketBuilder};
    let b = PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(src_port, dst_port);
    let mut inner = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut inner, payload)
        .map_err(|e| L34Error::Build(e.to_string()))?;

    let body_len = u16::try_from(GRE_HEADER.len() + inner.len())
        .map_err(|_| L34Error::Build("GRE packet longer than an IPv4 payload".into()))?;
    let mut header = Ipv4Header::new(
        body_len,
        64,
        IpNumber(IPPROTO_GRE),
        src.octets(),
        dst.octets(),
    )
    .map_err(|e| L34Error::Build(e.to_string()))?;
    header.identification = id;
    header.dont_fragment = false;

    let mut pkt = Vec::with_capacity(Ipv4Header::MIN_LEN + body_len as usize);
    header.write(&mut pkt).map_err(|e| L34Error::Build(e.to_string()))?;
    pkt.extend_from_slice(&GRE_HEADER);
    pkt.extend_from_slice(&inner);
    Ok(pkt)
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

    /// A SYN-ACK flood is the one combination whose flags are *legal* — it is the
    /// second segment of a handshake, arriving unsolicited. It must therefore
    /// carry a real acknowledgement number, not just the two bits.
    #[test]
    fn syn_ack_flood_sets_both_bits_and_carries_an_ack_number() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let pkt =
            build_tcp_packet(src, dst, 40000, 80, 5, L4Mode::SynAck.raw_tcp_flags().unwrap())
                .unwrap();
        let (_, tcp) = parse_tcp(&pkt);
        assert!(tcp.syn && tcp.ack, "SYN+ACK must set both");
        assert!(!tcp.fin && !tcp.rst && !tcp.psh && !tcp.urg, "SYN+ACK sets nothing else");
        assert_eq!(tcp.acknowledgment_number, 6, "ACK number accompanies the ACK bit");
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

    /// Parse a fragment into its IPv4 header and the bytes it carries.
    fn parse_frag(pkt: &[u8]) -> (etherparse::Ipv4Header, &[u8]) {
        etherparse::Ipv4Header::from_slice(pkt).expect("parse IPv4 header")
    }

    /// The whole point of the mode: the pieces are a datagram nobody on the path
    /// can read without holding all of them. So the offsets have to chain, the
    /// MF bit has to be set on all but the last, the identification has to be
    /// shared, and gluing them back together has to reproduce the original UDP
    /// datagram byte for byte.
    #[test]
    fn udp_fragments_chain_into_one_reassemblable_datagram() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let payload = [0xABu8; 64];
        let frags = build_udp_fragments(src, dst, 40000, 53, &payload, 0x4242).unwrap();

        assert_eq!(frags.len(), 2, "UDP header, then payload");
        let mut reassembled = Vec::new();
        for (i, frag) in frags.iter().enumerate() {
            let (h, body) = parse_frag(frag);
            assert_eq!(h.protocol, etherparse::IpNumber::UDP);
            assert_eq!(h.source, src.octets(), "real source on every fragment");
            assert_eq!(h.identification, 0x4242, "one id per datagram");
            assert!(!h.dont_fragment, "DF must be clear on a fragment");
            assert_eq!(
                h.fragment_offset.value() as usize * FRAG_BLOCK,
                reassembled.len(),
                "fragment {i} must start where the previous one ended"
            );
            assert_eq!(h.more_fragments, i + 1 < frags.len(), "MF on all but the last");
            reassembled.extend_from_slice(body);
        }
        assert_eq!(reassembled.len(), UDP_HEADER_LEN + payload.len());
        assert_eq!(&reassembled[UDP_HEADER_LEN..], &payload, "payload survives the cut");
        assert_eq!(
            u16::from_be_bytes([reassembled[2], reassembled[3]]),
            53,
            "the destination port is only readable after reassembly"
        );
    }

    /// A fragmented SYN's *flags* live past the first 8 bytes of the TCP header,
    /// so fragment 0 carries the ports and nothing that says what the segment is.
    #[test]
    fn tcp_fragments_split_the_header_so_the_flags_are_not_in_the_first_fragment() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let syn = TcpFlags { syn: true, ..TcpFlags::NONE };
        let frags = build_tcp_fragments(src, dst, 40000, 443, 99, syn, 7).unwrap();

        assert_eq!(frags.len(), 3, "a 20-byte TCP header cuts into 8 + 8 + 4");
        let (_, first) = parse_frag(&frags[0]);
        assert_eq!(first.len(), FRAG_BLOCK, "fragment 0 is one 8-byte block");
        assert_eq!(u16::from_be_bytes([first[2], first[3]]), 443, "ports are in fragment 0");

        let mut reassembled = Vec::new();
        for (i, frag) in frags.iter().enumerate() {
            let (h, body) = parse_frag(frag);
            assert_eq!(h.protocol, etherparse::IpNumber::TCP);
            assert_eq!(h.identification, 7);
            assert_eq!(h.more_fragments, i + 1 < frags.len());
            reassembled.extend_from_slice(body);
        }
        assert_eq!(reassembled.len(), 20, "the whole segment is on the wire, in pieces");
        // Byte 13 holds the control bits; it is in fragment 1, not fragment 0.
        assert_eq!(reassembled[13] & 0x02, 0x02, "SYN is set once reassembled");
        let (_, second) = parse_frag(&frags[1]);
        assert_eq!(second[5] & 0x02, 0x02, "and it arrives in the second fragment");
    }

    /// Same guarantee as the unfragmented builders: the source is carried
    /// verbatim, on every fragment, with no other producer of the value.
    #[test]
    fn every_fragment_carries_the_supplied_source_address() {
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        for src in ["10.0.0.1", "192.0.2.55", "127.0.0.1"] {
            let src: Ipv4Addr = src.parse().unwrap();
            let syn = TcpFlags { syn: true, ..TcpFlags::NONE };
            let frags = build_tcp_fragments(src, dst, 1, 2, 3, syn, 1)
                .unwrap()
                .into_iter()
                .chain(build_udp_fragments(src, dst, 1, 2, &[0u8; 16], 1).unwrap());
            for frag in frags {
                let (h, _) = parse_frag(&frag);
                assert_eq!(h.source, src.octets(), "source must be carried verbatim");
            }
        }
    }

    /// The summary's "1 unit = N fragments" note is a constant in `mode`, and the
    /// number of fragments is a property of the cut rule here. This is the seam
    /// that holds the two together, across the payload sizes a run can ask for.
    #[test]
    fn fragment_counts_match_the_builder() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let syn = TcpFlags { syn: true, ..TcpFlags::NONE };
        for size in [1usize, 8, 64, 1472] {
            let payload = vec![0u8; size];
            assert_eq!(
                build_udp_fragments(src, dst, 1, 2, &payload, 1).unwrap().len(),
                L4Mode::UdpFrag.packets_per_unit(),
                "udp payload {size}"
            );
        }
        assert_eq!(
            build_tcp_fragments(src, dst, 1, 2, 3, syn, 1).unwrap().len(),
            L4Mode::TcpFrag.packets_per_unit()
        );
    }

    /// A GRE packet is protocol 47 carrying a version-0 header and a *real* inner
    /// IPv4 packet — including an inner source address that is the host's own, the
    /// one place a payload could have carried a chosen one.
    #[test]
    fn gre_packet_is_protocol_47_around_an_inner_packet_with_the_same_real_source() {
        let src: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let pkt = build_gre_packet(src, dst, 40000, 4789, &[0x5Au8; 32], 0x1111).unwrap();

        let (outer, body) = parse_frag(&pkt);
        assert_eq!(outer.protocol, etherparse::IpNumber(IPPROTO_GRE), "IP protocol 47");
        assert_eq!(outer.source, src.octets());
        assert_eq!(outer.destination, dst.octets());
        assert!(!outer.more_fragments, "a GRE packet is not itself fragmented");

        assert_eq!(&body[..4], &GRE_HEADER, "version-0 GRE header, EtherType IPv4");
        let (inner, inner_body) = parse_frag(&body[4..]);
        assert_eq!(inner.protocol, etherparse::IpNumber::UDP, "an IPv4/UDP datagram inside");
        assert_eq!(inner.source, src.octets(), "the encapsulated source is ours too");
        assert_eq!(inner.destination, dst.octets());
        assert_eq!(
            u16::from_be_bytes([inner_body[2], inner_body[3]]),
            4789,
            "the inner datagram addresses the run's port"
        );
        assert_eq!(inner_body.len(), UDP_HEADER_LEN + 32);
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

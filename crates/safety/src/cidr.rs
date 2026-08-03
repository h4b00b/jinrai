//! In-house CIDR parsing and matching (IPv4 + IPv6), std-only.
//!
//! We do not pull an external crate for this: the allowlist check is the most
//! security-critical path in the tool, so it stays auditable in-house with zero
//! third-party code.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// A single CIDR block, e.g. `10.0.0.0/8` or `2001:db8::/32`.
///
/// The representation is sealed: [`FromStr`] and the [`From`] conversions below
/// are the only ways to build one, so every `Cidr` in existence has been through
/// the prefix-length bound, the host-bit normalisation and the IPv4-mapped
/// refusal. It used to be an enum with public fields, which made
/// `Cidr::V4 { network, prefix: 200 }` — a block that matches by a mask the
/// parser would never have produced — an ordinary safe expression, in the one
/// crate whose documented job is that invalid states are unrepresentable. Sealed
/// the same way [`DnsRule`](crate::dns::DnsRule) is, for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr(CidrKind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CidrKind {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

/// Error parsing a CIDR string.
#[derive(Debug, PartialEq, Eq)]
pub enum CidrParseError {
    MissingSlash,
    BadAddress(String),
    BadPrefix(String),
    PrefixTooLong { prefix: u8, max: u8 },
    /// An IPv4-mapped IPv6 entry (`::ffff:a.b.c.d`), which would match nothing.
    Ipv4Mapped(String),
}

impl std::fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CidrParseError::MissingSlash => write!(f, "missing '/' in CIDR"),
            CidrParseError::BadAddress(s) => write!(f, "invalid network address: {s}"),
            CidrParseError::BadPrefix(s) => write!(f, "invalid prefix length: {s}"),
            CidrParseError::PrefixTooLong { prefix, max } => {
                write!(f, "prefix /{prefix} exceeds maximum /{max}")
            }
            CidrParseError::Ipv4Mapped(s) => write!(
                f,
                "IPv4-mapped address {s} would authorize nothing — write it as \
                 an IPv4 block instead (e.g. 10.0.0.1/32)"
            ),
        }
    }
}

impl std::error::Error for CidrParseError {}

impl Cidr {
    /// Does this block contain `ip`?
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (&self.0, ip) {
            (CidrKind::V4 { network, prefix }, IpAddr::V4(addr)) => {
                let mask = v4_mask(*prefix);
                (u32::from(addr) & mask) == (*network & mask)
            }
            (CidrKind::V6 { network, prefix }, IpAddr::V6(addr)) => {
                // Fail-closed on IPv4-mapped IPv6 (`::ffff:a.b.c.d`). Such an
                // address *is* an IPv4 host wearing a v6 costume: an OS/socket
                // connect to it lands on the embedded IPv4 target. Honouring it
                // against a v6 block (e.g. the operator writes `::/0` meaning
                // "all IPv6") would let traffic reach an IPv4 host that was
                // never listed in IPv4 terms — a fail-open surprise. It also
                // does not match any v4 block (family mismatch), so refusing it
                // outright is the only fail-closed answer: a mapped address is
                // authorized by nothing and the gate returns NotAllowlisted.
                if addr.to_ipv4_mapped().is_some() {
                    return false;
                }
                let mask = v6_mask(*prefix);
                (u128::from(addr) & mask) == (*network & mask)
            }
            // Address family mismatch never matches.
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, prefix_str) = s.split_once('/').ok_or(CidrParseError::MissingSlash)?;
        let prefix: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|_| CidrParseError::BadPrefix(prefix_str.to_string()))?;

        match IpAddr::from_str(addr_str.trim()) {
            Ok(IpAddr::V4(a)) => {
                if prefix > 32 {
                    return Err(CidrParseError::PrefixTooLong { prefix, max: 32 });
                }
                // Normalise: zero out host bits so `network` is canonical.
                let network = u32::from(a) & v4_mask(prefix);
                Ok(Cidr(CidrKind::V4 { network, prefix }))
            }
            Ok(IpAddr::V6(a)) => {
                if prefix > 128 {
                    return Err(CidrParseError::PrefixTooLong { prefix, max: 128 });
                }
                // An IPv4-mapped entry (`::ffff:10.0.0.1/128`) authorizes exactly
                // nothing, and does so silently. `contains` fail-closes on mapped
                // *candidates* (they are IPv4 hosts in a v6 costume), and a plain
                // v4 address never matches a v6 rule on family — so the operator
                // gets a rule that looks like it opened something and did not,
                // which on an allowlist is the worst way to be wrong. Say so at
                // parse time and name the spelling that works.
                if a.to_ipv4_mapped().is_some() {
                    return Err(CidrParseError::Ipv4Mapped(addr_str.trim().to_string()));
                }
                let network = u128::from(a) & v6_mask(prefix);
                Ok(Cidr(CidrKind::V6 { network, prefix }))
            }
            Err(_) => Err(CidrParseError::BadAddress(addr_str.to_string())),
        }
    }
}

/// Build a left-aligned bitmask for an IPv4 prefix. `/0` -> 0, `/32` -> all ones.
fn v4_mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    }
}

fn v6_mask(prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        p if p >= 128 => u128::MAX,
        p => u128::MAX << (128 - p),
    }
}

// Convenience conversions used in tests / callers. A single host is already
// canonical at /32 and /128, so there are no host bits to normalise.
impl From<Ipv4Addr> for Cidr {
    fn from(a: Ipv4Addr) -> Self {
        Cidr(CidrKind::V4 { network: u32::from(a), prefix: 32 })
    }
}

impl From<Ipv6Addr> for Cidr {
    fn from(a: Ipv6Addr) -> Self {
        Cidr(CidrKind::V6 { network: u128::from(a), prefix: 128 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    fn ip_v6(s: &str) -> Ipv6Addr {
        Ipv6Addr::from_str(s).unwrap()
    }

    #[test]
    fn parses_and_matches_v4() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains(ip("10.1.2.3")));
        assert!(c.contains(ip("10.255.255.255")));
        assert!(!c.contains(ip("11.0.0.1")));
        assert!(!c.contains(ip("9.255.255.255")));
    }

    #[test]
    fn host_bits_are_normalised() {
        // 192.168.1.55/24 should canonicalise to network 192.168.1.0.
        let c: Cidr = "192.168.1.55/24".parse().unwrap();
        assert!(c.contains(ip("192.168.1.0")));
        assert!(c.contains(ip("192.168.1.255")));
        assert!(!c.contains(ip("192.168.2.0")));
    }

    #[test]
    fn slash_zero_matches_all_v4() {
        let c: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(c.contains(ip("1.2.3.4")));
        assert!(c.contains(ip("255.255.255.255")));
    }

    #[test]
    fn slash_thirtytwo_is_single_host() {
        let c: Cidr = "127.0.0.1/32".parse().unwrap();
        assert!(c.contains(ip("127.0.0.1")));
        assert!(!c.contains(ip("127.0.0.2")));
    }

    #[test]
    fn parses_and_matches_v6() {
        let c: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(c.contains(ip("2001:db8::1")));
        assert!(c.contains(ip("2001:db8:ffff::1")));
        assert!(!c.contains(ip("2001:db9::1")));
    }

    #[test]
    fn family_mismatch_never_matches() {
        let v4: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(!v4.contains(ip("::1")));
        let v6: Cidr = "::/0".parse().unwrap();
        assert!(!v6.contains(ip("10.0.0.1")));
    }

    #[test]
    fn ipv4_mapped_v6_never_matches_v4_block() {
        // A v4-mapped v6 address vs an IPv4 allowlist: family mismatch => refuse.
        let v4: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(!v4.contains(ip("::ffff:10.0.0.1")));
    }

    /// An allowlist entry that can never match is worse than a rejected one: the
    /// operator believes they authorized a host and did not. Refuse at parse and
    /// name the spelling that works.
    #[test]
    fn ipv4_mapped_allowlist_entries_are_refused_rather_than_silently_inert() {
        for pattern in ["::ffff:10.0.0.1/128", "::ffff:0:0/96", "::FFFF:192.168.1.0/120"] {
            let err = pattern.parse::<Cidr>().unwrap_err();
            assert!(
                matches!(err, CidrParseError::Ipv4Mapped(_)),
                "{pattern} should be refused as v4-mapped, got {err:?}"
            );
            assert!(err.to_string().contains("10.0.0.1/32"), "the error must name the fix");
        }
        // Ordinary v6 blocks, including the catch-all, still parse.
        assert!("::/0".parse::<Cidr>().is_ok());
        assert!("2001:db8::/32".parse::<Cidr>().is_ok());
        assert!("::1/128".parse::<Cidr>().is_ok());
    }

    #[test]
    fn ipv4_mapped_v6_refused_by_v6_block_fail_closed() {
        // Regression: an operator listing ONLY a v6 block (even the catch-all
        // `::/0`) must NOT authorize a v4-mapped address, because connecting to
        // `::ffff:10.0.0.1` actually reaches the IPv4 host 10.0.0.1. Refuse it.
        let all_v6: Cidr = "::/0".parse().unwrap();
        assert!(!all_v6.contains(ip("::ffff:10.0.0.1")));

        // Even a v6 block that literally covers the mapped range refuses it:
        // mapped addresses are never authorized by anything (strictly closed).
        //
        // Built through the private representation rather than parsed, because
        // the parser now refuses such an entry outright (see
        // `ipv4_mapped_allowlist_entries_are_refused_rather_than_silently_inert`)
        // — and no caller outside this module can build one at all. Both layers
        // are wanted: the parser stops the operator writing a rule that
        // authorizes nothing, and this stops the *matcher* honouring one if it
        // ever arrives by another route.
        let mapped_block =
            Cidr(CidrKind::V6 { network: u128::from(ip_v6("::ffff:0:0")), prefix: 96 });
        assert!(!mapped_block.contains(ip("::ffff:10.0.0.1")));
    }

    #[test]
    fn genuine_v6_still_matches_after_mapped_guard() {
        // The mapped-address guard must not affect ordinary IPv6 matching.
        let c: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(c.contains(ip("2001:db8::1")));
        // ::1 is loopback, not a v4-mapped address, so normal rules apply.
        let all_v6: Cidr = "::/0".parse().unwrap();
        assert!(all_v6.contains(ip("::1")));
    }

    #[test]
    fn slash_128_is_single_v6_host() {
        let c: Cidr = "2001:db8::1/128".parse().unwrap();
        assert!(c.contains(ip("2001:db8::1")));
        assert!(!c.contains(ip("2001:db8::2")));
    }

    #[test]
    fn slash_zero_matches_all_v6() {
        let c: Cidr = "::/0".parse().unwrap();
        assert!(c.contains(ip("2001:db8::dead:beef")));
        assert!(c.contains(ip("fe80::1")));
    }

    #[test]
    fn v6_host_bits_are_normalised() {
        // 2001:db8::abcd/32 canonicalises to network 2001:db8::.
        let c: Cidr = "2001:db8::abcd/32".parse().unwrap();
        assert!(c.contains(ip("2001:db8::")));
        assert!(c.contains(ip("2001:db8:ffff:ffff::1")));
        assert!(!c.contains(ip("2001:db9::")));
    }

    #[test]
    fn leading_zero_octets_are_rejected_not_reinterpreted() {
        // std IpAddr parsing rejects octal-looking octets outright (no silent
        // reinterpretation of `010` as 8), so the whole CIDR fails to parse.
        assert!(matches!(
            "010.0.0.0/8".parse::<Cidr>(),
            Err(CidrParseError::BadAddress(_))
        ));
        assert!(matches!(
            "10.0.0.01/32".parse::<Cidr>(),
            Err(CidrParseError::BadAddress(_))
        ));
    }

    #[test]
    fn surrounding_whitespace_is_tolerated_but_internal_junk_is_not() {
        // Leading/trailing whitespace around address and prefix is trimmed.
        assert!(" 10.0.0.0 / 8 ".parse::<Cidr>().is_ok());
        // Embedded junk in the address is rejected (fail-closed).
        assert!("10.0.0/8".parse::<Cidr>().is_err());
    }

    #[test]
    fn empty_and_missing_prefix_rejected() {
        assert_eq!("10.0.0.0/".parse::<Cidr>(), Err(CidrParseError::BadPrefix(String::new())));
        assert_eq!("".parse::<Cidr>(), Err(CidrParseError::MissingSlash));
    }

    #[test]
    fn v6_prefix_too_long_rejected() {
        assert_eq!(
            "2001:db8::/129".parse::<Cidr>(),
            Err(CidrParseError::PrefixTooLong { prefix: 129, max: 128 })
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!("10.0.0.0".parse::<Cidr>(), Err(CidrParseError::MissingSlash));
        assert_eq!(
            "10.0.0.0/33".parse::<Cidr>(),
            Err(CidrParseError::PrefixTooLong { prefix: 33, max: 32 })
        );
        assert!(matches!(
            "not-an-ip/24".parse::<Cidr>(),
            Err(CidrParseError::BadAddress(_))
        ));
        assert!(matches!(
            "10.0.0.0/xx".parse::<Cidr>(),
            Err(CidrParseError::BadPrefix(_))
        ));
    }
}

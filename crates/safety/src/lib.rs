//! # jinrai-safety — the authorization gate
//!
//! This crate is the trust anchor of the whole tool. Every traffic-generating
//! module (`l34`, `l7`) can only ever act on an [`AuthorizedTarget`], and an
//! `AuthorizedTarget` can *only* be produced by passing a target through an
//! [`Authorization`] backed by an operator-supplied [`Allowlist`].
//!
//! ## Design invariant (enforced by the type system)
//!
//! There is no public constructor for [`AuthorizedTarget`]. The only way to get
//! one is [`Authorization::authorize`], which checks the allowlist. Traffic
//! modules take `&[AuthorizedTarget]` in their APIs, so "fire at something that
//! was never authorized" is not an expressible program state — it fails to
//! compile.
//!
//! The allowlist is **not** hard-coded: it is passed in at runtime (mixed
//! CIDR blocks and DNS-name patterns), because different test campaigns target
//! different networks and services.
//!
//! ## Datum-based validation
//!
//! The gate validates the **datum the operator supplied**, matched only against
//! its own rule type:
//!
//!  - an **IP literal** is checked against the IP/CIDR rules ([`Allowlist::permits`]);
//!  - a **DNS name** is checked against the DNS rules ([`Allowlist::permits_host`]).
//!
//! There is no cross-check between the two (a name is never resolved and then
//! IP-checked, and an IP is never reverse-resolved). Each datum matches only its
//! own kind, or it is refused (fail-closed).

#![forbid(unsafe_code)]

mod cidr;
mod dns;

pub use cidr::{Cidr, CidrParseError};
pub use dns::{DnsParseError, DnsRule};

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A set of rules the operator has explicitly authorized for this run: IP/CIDR
/// blocks and/or DNS-name patterns.
///
/// Built at runtime from `--allow` parameters. An empty allowlist authorizes
/// **nothing** (fail-closed).
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    blocks: Vec<Cidr>,
    dns: Vec<DnsRule>,
}

/// Error building an [`Allowlist`] from mixed `--allow` entries.
#[derive(Debug, PartialEq, Eq)]
pub enum AllowParseError {
    /// An entry that looked like an IP/CIDR failed to parse.
    Cidr(CidrParseError),
    /// An entry treated as a DNS pattern failed to parse.
    Dns(DnsParseError),
}

impl std::fmt::Display for AllowParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllowParseError::Cidr(e) => write!(f, "{e}"),
            AllowParseError::Dns(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AllowParseError {}

/// One parsed allowlist rule.
enum Rule {
    Ip(Cidr),
    Dns(DnsRule),
}

/// Classify and parse a single `--allow` entry. IP-ness is detected first so a
/// bare IP (no `/`) becomes a `/32` (or `/128`) IP rule, never a DNS name.
fn parse_entry(entry: &str) -> Result<Rule, AllowParseError> {
    let t = entry.trim();
    // Bare IP literal (no prefix) => single-host IP rule.
    if let Ok(ip) = t.parse::<IpAddr>() {
        let cidr = match ip {
            IpAddr::V4(a) => Cidr::from(a),
            // The same refusal the CIDR parser makes, for the same reason: a
            // mapped entry authorizes nothing and does so silently. Without this
            // the two spellings disagreed — `--allow ::ffff:10.0.0.1/128` was
            // rejected loudly while the bare `--allow ::ffff:10.0.0.1` built an
            // inert /128 the operator believed had opened something. Fail-closed
            // either way, but only one of them tells them so.
            IpAddr::V6(a) => {
                if a.to_ipv4_mapped().is_some() {
                    return Err(AllowParseError::Cidr(CidrParseError::Ipv4Mapped(t.to_string())));
                }
                Cidr::from(a)
            }
        };
        return Ok(Rule::Ip(cidr));
    }
    // Anything containing '/' must be a valid CIDR (fail-closed if not).
    if t.contains('/') {
        return t.parse::<Cidr>().map(Rule::Ip).map_err(AllowParseError::Cidr);
    }
    // Otherwise it is a DNS-name pattern.
    DnsRule::parse(t).map(Rule::Dns).map_err(AllowParseError::Dns)
}

impl Allowlist {
    /// Build an IP-only allowlist from CIDR strings.
    ///
    /// Retained for callers/tests that deal purely in CIDRs. Fails on the first
    /// malformed entry — we never silently drop a block, because a dropped block
    /// could let an unintended target through or make an intended one
    /// unreachable. Both must be loud.
    pub fn from_cidrs<I, S>(cidrs: I) -> Result<Self, CidrParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let blocks = cidrs
            .into_iter()
            .map(|s| s.as_ref().parse::<Cidr>())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { blocks, dns: Vec::new() })
    }

    /// Build a mixed allowlist from `--allow` entries, each of which may be a
    /// CIDR/IP or a DNS-name pattern. Fails on the first malformed entry.
    pub fn from_patterns<I, S>(entries: I) -> Result<Self, AllowParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut blocks = Vec::new();
        let mut dns = Vec::new();
        for entry in entries {
            match parse_entry(entry.as_ref())? {
                Rule::Ip(c) => blocks.push(c),
                Rule::Dns(r) => dns.push(r),
            }
        }
        Ok(Self { blocks, dns })
    }

    /// Total number of rules (IP blocks + DNS patterns).
    pub fn len(&self) -> usize {
        self.blocks.len() + self.dns.len()
    }

    /// True when the allowlist contains no rules of any kind.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty() && self.dns.is_empty()
    }

    /// Is `ip` covered by any IP/CIDR block? Empty => always false.
    pub fn permits(&self, ip: IpAddr) -> bool {
        self.blocks.iter().any(|b| b.contains(ip))
    }

    /// Is `host` authorized by any DNS rule? Empty => always false.
    pub fn permits_host(&self, host: &str) -> bool {
        self.dns.iter().any(|r| r.matches(host))
    }
}

/// Why a target was refused authorization.
#[derive(Debug, PartialEq, Eq)]
pub enum SafetyError {
    /// The target IP is not covered by any IP/CIDR rule.
    NotAllowlisted(IpAddr),
    /// The target host name is not covered by any DNS rule.
    NotAllowlistedHost(String),
    /// The allowlist is empty — nothing can be authorized (fail-closed).
    EmptyAllowlist,
    /// The kill-switch has been tripped; no new targets may be authorized.
    Aborted,
}

impl std::fmt::Display for SafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyError::NotAllowlisted(ip) => {
                write!(f, "target {ip} is not in the authorized allowlist")
            }
            SafetyError::NotAllowlistedHost(host) => {
                write!(f, "host {host} is not in the authorized DNS allowlist")
            }
            SafetyError::EmptyAllowlist => {
                write!(f, "allowlist is empty: refusing to authorize any target")
            }
            SafetyError::Aborted => write!(f, "run aborted: kill-switch is tripped"),
        }
    }
}

impl std::error::Error for SafetyError {}

/// A cooperative, thread-safe abort signal shared across all traffic workers.
///
/// Traffic loops must check [`KillSwitch::is_tripped`] frequently and stop
/// immediately when set. `trip()` can be wired to SIGINT/SIGTERM or a
/// dead-man's-timer by the CLI.
#[derive(Debug, Clone, Default)]
pub struct KillSwitch {
    tripped: Arc<AtomicBool>,
}

impl KillSwitch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trip the switch. Idempotent.
    pub fn trip(&self) {
        self.tripped.store(true, Ordering::SeqCst);
    }

    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }
}

/// What kind of datum passed the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Authorized {
    /// An authorized IP literal.
    Ip(IpAddr),
    /// An authorized DNS host name (normalized, lowercase, no trailing dot).
    Host(String),
}

/// A datum that has been checked against the allowlist and authorized. It
/// represents **either** an authorized IP **or** an authorized host name.
///
/// Construct only via [`Authorization::authorize`] / [`Authorization::authorize_host`].
/// There is intentionally no other public constructor, so an `AuthorizedTarget`
/// always means "passed the gate".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedTarget {
    inner: Authorized,
    // Private field with no public constructor => cannot be forged outside
    // this module.
    _sealed: (),
}

impl AuthorizedTarget {
    /// The authorized IP, if this target is an IP literal (else `None`).
    pub fn as_ip(&self) -> Option<IpAddr> {
        match &self.inner {
            Authorized::Ip(ip) => Some(*ip),
            Authorized::Host(_) => None,
        }
    }

    /// The authorized host name, if this target is a DNS name (else `None`).
    pub fn host(&self) -> Option<&str> {
        match &self.inner {
            Authorized::Host(h) => Some(h.as_str()),
            Authorized::Ip(_) => None,
        }
    }

    /// True when this target is an IP literal (rather than a host name).
    pub fn is_ip(&self) -> bool {
        matches!(self.inner, Authorized::Ip(_))
    }
}

/// The gate. Wraps an [`Allowlist`] plus the shared [`KillSwitch`] and is the
/// sole producer of [`AuthorizedTarget`]s.
#[derive(Debug, Clone)]
pub struct Authorization {
    allowlist: Allowlist,
    kill: KillSwitch,
}

impl Authorization {
    pub fn new(allowlist: Allowlist, kill: KillSwitch) -> Self {
        Self { allowlist, kill }
    }

    pub fn kill_switch(&self) -> &KillSwitch {
        &self.kill
    }

    /// Authorize a single target **IP** against the IP/CIDR rules.
    pub fn authorize(&self, ip: IpAddr) -> Result<AuthorizedTarget, SafetyError> {
        if self.kill.is_tripped() {
            return Err(SafetyError::Aborted);
        }
        if self.allowlist.is_empty() {
            return Err(SafetyError::EmptyAllowlist);
        }
        if !self.allowlist.permits(ip) {
            return Err(SafetyError::NotAllowlisted(ip));
        }
        Ok(AuthorizedTarget { inner: Authorized::Ip(ip), _sealed: () })
    }

    /// Authorize a target **host name** against the DNS rules.
    ///
    /// The name string itself is validated — it is deliberately *not* resolved
    /// and IP-checked. The stored host is normalized (lowercase, trailing dot
    /// stripped) so downstream code compares canonical forms.
    pub fn authorize_host(&self, name: &str) -> Result<AuthorizedTarget, SafetyError> {
        if self.kill.is_tripped() {
            return Err(SafetyError::Aborted);
        }
        if self.allowlist.is_empty() {
            return Err(SafetyError::EmptyAllowlist);
        }
        if !self.allowlist.permits_host(name) {
            return Err(SafetyError::NotAllowlistedHost(name.to_string()));
        }
        Ok(AuthorizedTarget {
            inner: Authorized::Host(dns::normalize_host(name)),
            _sealed: (),
        })
    }

    /// Authorize a batch of IPs, failing on the first refused target.
    pub fn authorize_all<I>(&self, ips: I) -> Result<Vec<AuthorizedTarget>, SafetyError>
    where
        I: IntoIterator<Item = IpAddr>,
    {
        ips.into_iter().map(|ip| self.authorize(ip)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    fn auth(cidrs: &[&str]) -> Authorization {
        let allowlist = Allowlist::from_cidrs(cidrs).unwrap();
        Authorization::new(allowlist, KillSwitch::new())
    }

    fn auth_patterns(entries: &[&str]) -> Authorization {
        let allowlist = Allowlist::from_patterns(entries).unwrap();
        Authorization::new(allowlist, KillSwitch::new())
    }

    #[test]
    fn authorizes_in_range_target() {
        let a = auth(&["10.0.0.0/8"]);
        let t = a.authorize(ip("10.1.2.3")).unwrap();
        assert_eq!(t.as_ip(), Some(ip("10.1.2.3")));
        assert!(t.is_ip());
        assert_eq!(t.host(), None);
    }

    #[test]
    fn refuses_out_of_range_target() {
        let a = auth(&["10.0.0.0/8"]);
        assert_eq!(
            a.authorize(ip("192.168.0.1")),
            Err(SafetyError::NotAllowlisted(ip("192.168.0.1")))
        );
    }

    #[test]
    fn empty_allowlist_fails_closed() {
        let a = auth(&[]);
        assert_eq!(a.authorize(ip("10.0.0.1")), Err(SafetyError::EmptyAllowlist));
    }

    #[test]
    fn multiple_networks_are_supported() {
        let a = auth(&["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"]);
        assert!(a.authorize(ip("10.9.9.9")).is_ok());
        assert!(a.authorize(ip("192.168.5.5")).is_ok());
        assert!(a.authorize(ip("2001:db8::dead")).is_ok());
        assert!(a.authorize(ip("172.16.0.1")).is_err());
    }

    #[test]
    fn tripped_kill_switch_blocks_authorization() {
        let a = auth(&["10.0.0.0/8"]);
        a.kill_switch().trip();
        assert_eq!(a.authorize(ip("10.0.0.1")), Err(SafetyError::Aborted));
    }

    #[test]
    fn authorize_all_fails_on_first_bad_target() {
        let a = auth(&["10.0.0.0/8"]);
        let res = a.authorize_all([ip("10.0.0.1"), ip("8.8.8.8")]);
        assert_eq!(res, Err(SafetyError::NotAllowlisted(ip("8.8.8.8"))));
    }

    #[test]
    fn ipv4_mapped_target_refused_even_with_catch_all_v6_allowlist() {
        // Fail-closed regression: `::/0` (all IPv6) must NOT authorize a
        // v4-mapped address, since connecting to it reaches an IPv4 host.
        let a = auth(&["::/0"]);
        let mapped = ip("::ffff:10.0.0.1");
        assert_eq!(a.authorize(mapped), Err(SafetyError::NotAllowlisted(mapped)));
    }

    #[test]
    fn ipv4_mapped_target_refused_against_matching_v4_allowlist() {
        // Even when the embedded IPv4 (10.0.0.1) *is* allowlisted, the mapped
        // v6 form is refused: only the honest IPv4 form is authorized.
        let a = auth(&["10.0.0.0/8"]);
        let mapped = ip("::ffff:10.0.0.1");
        assert_eq!(a.authorize(mapped), Err(SafetyError::NotAllowlisted(mapped)));
        // The plain IPv4 form is still authorized normally.
        assert!(a.authorize(ip("10.0.0.1")).is_ok());
    }

    #[test]
    fn whitespace_only_allowlist_entry_fails_to_build() {
        // A blank/whitespace `--allow` value is not a silent no-op: it errors,
        // so the operator can never accidentally run with a dropped block.
        assert!(Allowlist::from_cidrs(["   "]).is_err());
        assert!(Allowlist::from_cidrs([""]).is_err());
    }

    #[test]
    fn kill_switch_tripped_mid_batch_aborts_remaining() {
        // Trip the switch between two authorizations: the gate refuses from that
        // point on, so a mid-run kill halts new targets immediately.
        let a = auth(&["10.0.0.0/8"]);
        assert!(a.authorize(ip("10.0.0.1")).is_ok());
        a.kill_switch().trip();
        assert_eq!(a.authorize(ip("10.0.0.2")), Err(SafetyError::Aborted));
    }

    #[test]
    fn kill_switch_precedence_over_empty_and_notallowlisted() {
        // When tripped, Aborted wins regardless of allowlist contents.
        let empty = Authorization::new(Allowlist::default(), KillSwitch::new());
        empty.kill_switch().trip();
        assert_eq!(empty.authorize(ip("10.0.0.1")), Err(SafetyError::Aborted));
    }

    // ---- datum-based DNS validation (new rule) --------------------------------

    #[test]
    fn name_authorized_by_exact_dns_rule() {
        let a = auth_patterns(&["api.staging.internal"]);
        let t = a.authorize_host("api.staging.internal").unwrap();
        assert_eq!(t.host(), Some("api.staging.internal"));
        assert!(!t.is_ip());
        assert_eq!(t.as_ip(), None);
        // A different host is refused.
        assert!(matches!(
            a.authorize_host("other.staging.internal"),
            Err(SafetyError::NotAllowlistedHost(_))
        ));
    }

    #[test]
    fn name_authorized_by_wildcard_rule() {
        let a = auth_patterns(&["*.staging.internal"]);
        assert!(a.authorize_host("api.staging.internal").is_ok());
        assert!(a.authorize_host("a.b.staging.internal").is_ok());
        // Apex not covered by the wildcard.
        assert!(matches!(
            a.authorize_host("staging.internal"),
            Err(SafetyError::NotAllowlistedHost(_))
        ));
    }

    #[test]
    fn name_not_matching_dns_rule_refused_even_if_ip_is_allowlisted() {
        // Mixed allowlist: the IP 127.0.0.1 IS allowlisted, but the *name* is
        // matched only against DNS rules — and it matches none, so refuse. The
        // resolved IP is intentionally irrelevant here.
        let a = auth_patterns(&["127.0.0.0/8", "api.staging.internal"]);
        assert!(matches!(
            a.authorize_host("evil.example.com"),
            Err(SafetyError::NotAllowlistedHost(_))
        ));
    }

    #[test]
    fn ip_literal_validated_against_cidr_rules_only() {
        // With both IP and DNS rules, an IP datum is judged solely by CIDR rules.
        let a = auth_patterns(&["10.0.0.0/8", "*.staging.internal"]);
        assert!(a.authorize(ip("10.1.2.3")).is_ok());
        assert_eq!(a.authorize(ip("192.168.0.1")), Err(SafetyError::NotAllowlisted(ip("192.168.0.1"))));
    }

    #[test]
    fn name_authorized_when_only_dns_rules_exist() {
        // No IP rules at all, but the allowlist is not empty: a matching name is
        // authorized, while an IP datum is NotAllowlisted (not EmptyAllowlist).
        let a = auth_patterns(&["*.staging.internal"]);
        assert!(a.authorize_host("api.staging.internal").is_ok());
        assert_eq!(a.authorize(ip("10.0.0.1")), Err(SafetyError::NotAllowlisted(ip("10.0.0.1"))));
    }

    #[test]
    fn malformed_or_empty_dns_entry_rejected_at_build_time() {
        assert!(Allowlist::from_patterns(["*."]).is_err());
        assert!(Allowlist::from_patterns([""]).is_err());
        assert!(Allowlist::from_patterns(["a..b"]).is_err());
        // A bare IP is an IP rule, not a DNS name.
        let a = Allowlist::from_patterns(["10.0.0.5"]).unwrap();
        assert!(a.permits(ip("10.0.0.5")));
        assert!(!a.permits(ip("10.0.0.6")));
    }

    #[test]
    fn empty_allowlist_fails_closed_for_host_too() {
        let a = auth_patterns(&[]);
        assert_eq!(
            a.authorize_host("api.staging.internal"),
            Err(SafetyError::EmptyAllowlist)
        );
    }

    #[test]
    fn kill_switch_precedence_for_authorize_host() {
        // Aborted must win over both EmptyAllowlist and NotAllowlistedHost.
        let a = auth_patterns(&["api.staging.internal"]);
        a.kill_switch().trip();
        assert_eq!(a.authorize_host("api.staging.internal"), Err(SafetyError::Aborted));
        assert_eq!(a.authorize_host("nope.example.com"), Err(SafetyError::Aborted));

        let empty = Authorization::new(Allowlist::default(), KillSwitch::new());
        empty.kill_switch().trip();
        assert_eq!(empty.authorize_host("api.staging.internal"), Err(SafetyError::Aborted));
    }

    // ---- datum-kind confusion: an IP is always an IP, a name always a name ----

    #[test]
    fn bare_ip_entry_is_ip_rule_never_dns_name() {
        // A bare IPv4/IPv6 literal in --allow becomes a single-host IP rule.
        let a = Allowlist::from_patterns(["10.0.0.5", "::1"]).unwrap();
        assert!(a.permits(ip("10.0.0.5")));
        assert!(a.permits(ip("::1")));
        // It is NOT a DNS rule: the numeric string is not authorized as a host.
        assert!(!a.permits_host("10.0.0.5"));
        assert!(!a.permits_host("::1"));
    }

    #[test]
    fn bare_ipv4_mapped_entry_is_refused_like_its_cidr_spelling() {
        // Regression: the CIDR path refused `::ffff:10.0.0.1/128` loudly, but the
        // bare-IP path built a /128 rule from the same address — a rule that
        // `contains` then always refuses. Fail-closed, but the operator believed
        // they had authorized a host and had not, which is the exact failure the
        // mapped check exists to prevent. Both spellings must answer the same way.
        for entry in ["::ffff:10.0.0.1", "::FFFF:192.168.1.7"] {
            let err = Allowlist::from_patterns([entry]).unwrap_err();
            assert!(
                matches!(err, AllowParseError::Cidr(CidrParseError::Ipv4Mapped(_))),
                "{entry} should be refused as v4-mapped, got {err:?}"
            );
        }
        // Ordinary bare literals of both families are unaffected.
        assert!(Allowlist::from_patterns(["10.0.0.5", "::1", "2001:db8::1"]).is_ok());
    }

    #[test]
    fn numeric_looking_name_is_a_name_not_reinterpreted_as_ip() {
        // Strings that are NOT valid IPs (hex/octal-looking, over-long) are names.
        let a = Allowlist::from_patterns(["0x10.example.com", "99999.example.com"]).unwrap();
        assert!(a.permits_host("0x10.example.com"));
        assert!(a.permits_host("99999.example.com"));
        // And they are not silently reinterpreted as an IP rule.
        assert!(!a.permits(ip("10.0.0.1")));
    }

    #[test]
    fn bracketed_ipv6_entry_is_rejected_at_build_not_silently_a_name() {
        // `[::1]` is not a bare IpAddr (brackets), and brackets are illegal DNS
        // chars => the whole build fails loudly (fail-closed), never a stray rule.
        assert!(Allowlist::from_patterns(["[::1]"]).is_err());
    }

    // ---- from_patterns: mixed lists, loud failure, no silent drops -------------

    #[test]
    fn mixed_cidr_and_dns_patterns_build_and_apply_by_kind() {
        let a = Allowlist::from_patterns(["10.0.0.0/8", "*.staging.internal", "1.2.3.4"]).unwrap();
        assert_eq!(a.len(), 3);
        assert!(a.permits(ip("10.9.9.9")));
        assert!(a.permits(ip("1.2.3.4")));
        assert!(a.permits_host("api.staging.internal"));
        // Cross-kind never leaks: the IP rule does not authorize a name, etc.
        assert!(!a.permits_host("10.0.0.0"));
        assert!(!a.permits(ip("8.8.8.8")));
    }

    #[test]
    fn one_malformed_entry_fails_the_whole_build() {
        // A bad entry anywhere aborts the build; nothing is silently dropped.
        assert!(Allowlist::from_patterns(["10.0.0.0/8", "*.ok.internal", "a..bad"]).is_err());
        // A '/'-bearing entry must be a valid CIDR or the build fails.
        assert!(Allowlist::from_patterns(["*.staging.internal/24"]).is_err());
        // Surrounding whitespace is tolerated (entry is trimmed) and classified.
        let a = Allowlist::from_patterns(["  10.0.0.0/8  ", "  api.internal  "]).unwrap();
        assert!(a.permits(ip("10.1.1.1")));
        assert!(a.permits_host("api.internal"));
    }
}

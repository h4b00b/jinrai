//! In-house DNS-name allowlist rules (std-only).
//!
//! The gate validates the **datum the operator supplied**. When that datum is a
//! DNS name (not an IP literal), it is matched against these name rules — the
//! name string itself is the trust boundary; it is never resolved-then-checked
//! as an IP. Kept in-house (no third-party crate) so the allowlist decision
//! stays fully auditable, like the CIDR matcher next door.
//!
//! ## Match semantics
//!
//! Comparison is case-insensitive; a single trailing dot (the DNS root) is
//! stripped from both patterns and queried names before comparing.
//!
//!  - `api.staging.internal` — [`DnsRule::Exact`]: matches that host only.
//!  - `*.staging.internal`   — [`DnsRule::Wildcard`]: matches any *proper*
//!    subdomain (`x.staging.internal`, `a.b.staging.internal`) but **not**
//!    `staging.internal` itself. Matching aligns on a label boundary (the stored
//!    suffix keeps its leading dot), so there is no substring/partial matching.
//!
//! Anything malformed (empty, empty label, stray `*`, illegal characters) is
//! rejected at build time — fail-closed.

/// A single DNS allowlist rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRule {
    /// Exact host match. Stored normalized (lowercase, no trailing dot).
    Exact(String),
    /// Wildcard suffix match for proper subdomains. Stored *with* the leading
    /// dot, e.g. `.staging.internal`, so `ends_with` aligns on a label boundary.
    Wildcard(String),
}

/// Error parsing a DNS allowlist pattern.
#[derive(Debug, PartialEq, Eq)]
pub enum DnsParseError {
    /// The pattern was empty after normalization.
    Empty,
    /// A label between dots was empty (e.g. `a..b`, leading/trailing dot).
    EmptyLabel(String),
    /// A malformed wildcard (e.g. `*`, `*.`, `**.a`, `*foo.com`).
    BadWildcard(String),
    /// A label contained a character outside `[A-Za-z0-9-_]`.
    IllegalChar(String),
}

impl std::fmt::Display for DnsParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsParseError::Empty => write!(f, "empty DNS name"),
            DnsParseError::EmptyLabel(s) => write!(f, "DNS name has an empty label: {s}"),
            DnsParseError::BadWildcard(s) => write!(f, "malformed wildcard DNS pattern: {s}"),
            DnsParseError::IllegalChar(s) => write!(f, "illegal character in DNS name: {s}"),
        }
    }
}

impl std::error::Error for DnsParseError {}

/// Normalize a host or pattern: trim, strip one trailing dot, lowercase.
pub(crate) fn normalize_host(s: &str) -> String {
    let t = s.trim();
    let t = t.strip_suffix('.').unwrap_or(t);
    t.to_ascii_lowercase()
}

/// Validate a bare domain (no wildcard): at least one non-empty label, each
/// label using only `[A-Za-z0-9-_]`.
fn validate_domain(s: &str) -> Result<(), DnsParseError> {
    if s.is_empty() {
        return Err(DnsParseError::EmptyLabel(s.to_string()));
    }
    for label in s.split('.') {
        if label.is_empty() {
            return Err(DnsParseError::EmptyLabel(s.to_string()));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(DnsParseError::IllegalChar(s.to_string()));
        }
    }
    Ok(())
}

impl DnsRule {
    /// Parse one `--allow` DNS pattern. Fail-closed on anything malformed.
    pub fn parse(pattern: &str) -> Result<Self, DnsParseError> {
        let norm = normalize_host(pattern);
        if norm.is_empty() {
            return Err(DnsParseError::Empty);
        }
        if let Some(rest) = norm.strip_prefix("*.") {
            // The remainder must be a well-formed domain with no further `*`.
            validate_domain(rest).map_err(|_| DnsParseError::BadWildcard(pattern.to_string()))?;
            Ok(DnsRule::Wildcard(format!(".{rest}")))
        } else {
            if norm.contains('*') {
                return Err(DnsParseError::BadWildcard(pattern.to_string()));
            }
            validate_domain(&norm)?;
            Ok(DnsRule::Exact(norm))
        }
    }

    /// Does this rule authorize `host`?
    pub fn matches(&self, host: &str) -> bool {
        let h = normalize_host(host);
        // Fail-closed unless the queried name is itself a well-formed domain
        // (non-empty labels, DNS charset only). Without this, a suffix
        // `ends_with` check lets malformed names satisfy a wildcard rule:
        // `x..staging.internal` (empty label), `api .staging.internal`
        // (embedded whitespace) and `api\0.staging.internal` (embedded null —
        // a resolver null-truncation trap) would all match `*.staging.internal`.
        // Because name-based validation trusts the later DNS resolution, such a
        // name must never pass the gate. (Also covers the empty-string case.)
        if validate_domain(&h).is_err() {
            return false;
        }
        match self {
            DnsRule::Exact(name) => &h == name,
            // Suffix carries its leading dot, so this only matches a *proper*
            // subdomain and never the apex (`staging.internal` does not end with
            // `.staging.internal`).
            DnsRule::Wildcard(suffix) => h.len() > suffix.len() && h.ends_with(suffix.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_matches_only_that_host() {
        let r = DnsRule::parse("api.staging.internal").unwrap();
        assert!(r.matches("api.staging.internal"));
        assert!(r.matches("API.Staging.Internal")); // case-insensitive
        assert!(r.matches("api.staging.internal.")); // trailing dot
        assert!(!r.matches("x.api.staging.internal"));
        assert!(!r.matches("staging.internal"));
        assert!(!r.matches("api.staging.internalx"));
    }

    #[test]
    fn wildcard_matches_proper_subdomains_only() {
        let r = DnsRule::parse("*.staging.internal").unwrap();
        assert!(r.matches("api.staging.internal"));
        assert!(r.matches("a.b.staging.internal"));
        assert!(r.matches("API.staging.internal"));
        // Apex is NOT matched by the wildcard.
        assert!(!r.matches("staging.internal"));
        // No partial/substring matching on a label boundary.
        assert!(!r.matches("evilstaging.internal"));
        assert!(!r.matches("staging.internal.evil.com"));
    }

    #[test]
    fn wildcard_refuses_malformed_query_names_fail_closed() {
        // Regression: name-based validation trusts the later DNS resolution, so a
        // malformed name must never satisfy a wildcard via a naive suffix check.
        let r = DnsRule::parse("*.staging.internal").unwrap();
        assert!(!r.matches("x..staging.internal")); // empty label
        assert!(!r.matches("api .staging.internal")); // embedded whitespace
        assert!(!r.matches("api\0.staging.internal")); // embedded null (truncation trap)
        assert!(!r.matches(".staging.internal")); // leading empty label
        assert!(!r.matches("")); // empty
        assert!(!r.matches("   ")); // whitespace-only
    }

    #[test]
    fn exact_refuses_malformed_query_names() {
        let r = DnsRule::parse("api.staging.internal").unwrap();
        assert!(!r.matches("api.staging..internal"));
        assert!(!r.matches("api.staging.internal\0"));
        assert!(!r.matches("api .staging.internal"));
    }

    #[test]
    fn wildcard_still_matches_legit_subdomains_after_guard() {
        // The well-formed-name guard must not break legitimate matches.
        let r = DnsRule::parse("*.staging.internal").unwrap();
        assert!(r.matches("api.staging.internal"));
        assert!(r.matches("a.b.staging.internal"));
        assert!(r.matches("api.staging.internal.")); // trailing root dot
        assert!(r.matches("API.STAGING.INTERNAL")); // case-insensitive
        assert!(r.matches("host_1.staging.internal")); // underscore label
    }

    #[test]
    fn unicode_idn_confusable_refused() {
        // A Cyrillic 'а' homograph must not match an ASCII rule (rules are
        // ASCII-only; ascii-lowercasing leaves non-ASCII untouched => no match).
        let r = DnsRule::parse("api.staging.internal").unwrap();
        assert!(!r.matches("\u{0430}pi.staging.internal"));
        let w = DnsRule::parse("*.staging.internal").unwrap();
        assert!(!w.matches("\u{0430}pi.staging.internal"));
    }

    #[test]
    fn malformed_patterns_rejected() {
        assert_eq!(DnsRule::parse(""), Err(DnsParseError::Empty));
        assert_eq!(DnsRule::parse("   "), Err(DnsParseError::Empty));
        assert!(matches!(DnsRule::parse("*."), Err(DnsParseError::BadWildcard(_))));
        assert!(matches!(DnsRule::parse("*"), Err(DnsParseError::BadWildcard(_))));
        assert!(matches!(DnsRule::parse("*foo.com"), Err(DnsParseError::BadWildcard(_))));
        assert!(matches!(DnsRule::parse("**.a.com"), Err(DnsParseError::BadWildcard(_))));
        assert!(matches!(DnsRule::parse("a..b"), Err(DnsParseError::EmptyLabel(_))));
        assert!(matches!(DnsRule::parse("a b.com"), Err(DnsParseError::IllegalChar(_))));
    }
}

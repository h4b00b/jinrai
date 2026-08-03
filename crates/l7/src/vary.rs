//! How each L7 request differs from the last.
//!
//! The fast request flood sent one identical request N times. That is the right
//! shape for measuring a single endpoint's ceiling and the wrong shape for four
//! things a test plan asks for by name:
//!
//!   - **random-path flood** — every request asks for a URI that does not exist,
//!     so nothing is cacheable and the origin answers every one of them
//!     (404-generation, logging, and often a framework's whole routing table);
//!   - **valid-random flood** — the same, but drawn from a list of paths that
//!     *do* exist, so the load lands on real handlers rather than the 404 path;
//!   - **search-field flood** — a unique search term per request, which is the
//!     one query a cache can never serve and the backend can rarely index its
//!     way out of;
//!   - **session exhaustion** — a distinct, unrecognised session cookie per
//!     request, so the target allocates or looks up session state for each one
//!     instead of reusing a single session for the whole run.
//!
//! All four are the same missing primitive: vary the request per unit. That is
//! all this module is.
//!
//! ## The guardrail
//!
//! Variation touches the **path, query, body and cookie** — never the host, the
//! port or the scheme. The datum authorization and the pinned DNS resolution are
//! properties of the origin, so a variation that could move the origin would
//! void both. For generated paths that is true by construction (`path_segments_mut`
//! and `query_pairs_mut` cannot reach the host). For an operator-supplied path
//! list it is not, so every entry is joined against the base URL and checked to
//! land on the same origin **before the run starts** — see
//! [`Variation::check_paths`]. A list that moves the origin refuses the run
//! rather than being silently dropped at request time.

use std::sync::Arc;

use reqwest::Url;

/// Which path each request asks for.
#[derive(Debug, Clone, Default)]
pub enum PathMode {
    /// The URL's own path, unchanged.
    #[default]
    Fixed,
    /// Append a fresh random segment to the URL's path, so every request asks
    /// for a URI that (almost certainly) does not exist.
    RandomSegment,
    /// Draw from an operator-supplied list of paths. `Arc` because the list is
    /// shared, read-only, across every dispatched request of the run.
    FromList(Arc<Vec<String>>),
}

/// The per-request variation of one run: what changes between unit *n* and unit
/// *n+1*. Captured once and shared across dispatched tasks.
#[derive(Debug, Clone, Default)]
pub struct Variation {
    /// Append a unique `_cb=<n>` query parameter so caches/CDNs cannot serve a
    /// stored response.
    pub cache_bust: bool,
    /// Which path each request asks for.
    pub path: PathMode,
    /// Name of a parameter carrying a fresh random term per request — the
    /// search-field flood. Goes in the query for GET/HEAD and in a
    /// form-encoded body for POST.
    pub search_param: Option<String>,
    /// Name of a session cookie to send with a fresh unrecognised value per
    /// request (`JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`, `connect.sid`, …).
    pub session_cookie: Option<String>,
    /// Per-run seed, mixed into every generated token so two runs against the
    /// same target do not replay each other's paths and terms — which would let
    /// a cache warmed by the first run absorb the second.
    seed: u64,
}

/// One request's worth of variation, resolved.
pub struct Varied {
    /// The URL to request. Same origin as the base URL, always.
    pub url: Url,
    /// Full `NAME=value` cookie header value, when a session cookie is churned.
    pub cookie: Option<String>,
    /// Form-encoded body (`NAME=term`) when the search term belongs in the body
    /// rather than the query — i.e. for POST.
    pub form_body: Option<String>,
}

impl Variation {
    /// Build the variation a run's flags describe, seeded for that run.
    ///
    /// A constructor rather than a struct literal because `seed` is private:
    /// an unseeded `Variation` would generate the same URIs on every run, so a
    /// cache warmed by one run would absorb the next, and that is not a mistake
    /// a caller should be able to make by forgetting a field.
    pub fn new(
        cache_bust: bool,
        path: PathMode,
        search_param: Option<String>,
        session_cookie: Option<String>,
    ) -> Self {
        Variation { cache_bust, path, search_param, session_cookie, seed: 0 }.seeded()
    }

    /// Seed from the clock. Deliberately not a dependency: the requirement is
    /// "two runs do not generate the same URIs", not unpredictability, and
    /// nothing security-relevant rests on the sequence — where a request may go
    /// is decided by the safety gate long before this type exists.
    fn seeded(mut self) -> Self {
        self.seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        self
    }

    /// Whether every request of this run is identical — the historical shape,
    /// and the one that needs none of the work below.
    pub fn is_fixed(&self) -> bool {
        !self.cache_bust
            && matches!(self.path, PathMode::Fixed)
            && self.search_param.is_none()
            && self.session_cookie.is_none()
    }

    /// Short operator-facing list of what varies, for the run summary and the
    /// dry-run print. `None` when nothing does. The bare list, not a sentence:
    /// the two callers frame it differently.
    pub fn label(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.cache_bust {
            parts.push("cache-bust".to_string());
        }
        match &self.path {
            PathMode::Fixed => {}
            PathMode::RandomSegment => parts.push("random path".to_string()),
            PathMode::FromList(list) => parts.push(format!("{} paths", list.len())),
        }
        if let Some(p) = &self.search_param {
            parts.push(format!("random {p}"));
        }
        if self.session_cookie.is_some() {
            parts.push("fresh session".to_string());
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(", "))
        }
    }

    /// Refuse a path list that could move the origin, **before the run starts**.
    ///
    /// The syntactic rule (an entry must start with a single `/`) is enforced
    /// when the list is read, but syntax is the wrong thing to trust here: URL
    /// joining has its own normalisation rules for backslashes and
    /// protocol-relative forms, and a list that slipped one past the syntax
    /// check would send authorized-looking load to a host the gate never saw.
    /// So this checks the *result*: join each entry and require the origin to
    /// come back unchanged. It runs once, at setup, which is why the hot path
    /// below can join without checking.
    pub fn check_paths(&self, base: &Url) -> Result<(), String> {
        let PathMode::FromList(list) = &self.path else {
            return Ok(());
        };
        if list.is_empty() {
            return Err("the path list is empty: nothing to request".to_string());
        }
        for entry in list.iter() {
            let joined = base
                .join(entry)
                .map_err(|e| format!("path list entry {entry:?} is not a usable path: {e}"))?;
            if joined.scheme() != base.scheme()
                || joined.host_str() != base.host_str()
                || joined.port_or_known_default() != base.port_or_known_default()
            {
                return Err(format!(
                    "path list entry {entry:?} resolves to {} — a different origin than {}; \
                     entries must be paths on the authorized target, not URLs",
                    joined.origin().ascii_serialization(),
                    base.origin().ascii_serialization(),
                ));
            }
        }
        Ok(())
    }

    /// Build request *n*'s variation from the base URL.
    ///
    /// `n` is the run's unit counter, so callers need no shared generator state:
    /// the token is a hash of `(seed, n)` rather than a draw from a locked RNG,
    /// which matters at the rates this engine dispatches at.
    ///
    /// `body_search` says where a search term belongs — the body (POST) or the
    /// query (GET/HEAD).
    pub fn apply(&self, base: &Url, n: u64, body_search: bool) -> Varied {
        let mut url = base.clone();

        match &self.path {
            PathMode::Fixed => {}
            PathMode::RandomSegment => {
                // `path_segments_mut` fails only for cannot-be-a-base URLs
                // (`mailto:`), which `prepare` has already rejected by scheme.
                if let Ok(mut segments) = url.path_segments_mut() {
                    segments.push(&token(self.seed ^ PATH_SALT, n));
                }
            }
            PathMode::FromList(list) => {
                // Checked at setup: every entry joins onto the same origin.
                let pick = (mix(self.seed ^ LIST_SALT, n) % list.len() as u64) as usize;
                if let Ok(joined) = base.join(&list[pick]) {
                    url = joined;
                }
            }
        }

        if self.cache_bust {
            url.query_pairs_mut().append_pair("_cb", &n.to_string());
        }

        let mut form_body = None;
        if let Some(param) = &self.search_param {
            let term = word(self.seed ^ TERM_SALT, n);
            if body_search {
                form_body = Some(form_encode(param, &term));
            } else {
                url.query_pairs_mut().append_pair(param, &term);
            }
        }

        let cookie = self
            .session_cookie
            .as_ref()
            .map(|name| format!("{name}={}", token(self.seed ^ COOKIE_SALT, n)));

        Varied { url, cookie, form_body }
    }
}

/// Distinct salts so the path, the list index, the search term and the cookie of
/// the same unit are not the same value wearing four hats — a target that keys
/// on any one of them would otherwise see them move in lockstep.
const PATH_SALT: u64 = 0x5061_7468_5f76_3031;
const LIST_SALT: u64 = 0x4c69_7374_5f76_3031;
const TERM_SALT: u64 = 0x5465_726d_5f76_3031;
const COOKIE_SALT: u64 = 0x436f_6f6b_5f76_3031;

/// splitmix64 finaliser. A counter alone makes predictable, sequential URIs; one
/// round of this turns it into something that looks like unrelated traffic
/// without any shared mutable state on the request path.
fn mix(seed: u64, n: u64) -> u64 {
    let mut z = seed.wrapping_add(n.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A base-36 token: URL- and cookie-safe with no escaping.
fn token(seed: u64, n: u64) -> String {
    let mut v = mix(seed, n);
    let mut out = String::with_capacity(13);
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    while v > 0 {
        out.push(ALPHABET[(v % 36) as usize] as char);
        v /= 36;
    }
    if out.is_empty() {
        out.push('0');
    }
    out
}

/// A pronounceable-ish lowercase word, for a search term. A hex blob would be
/// just as uncacheable, but a term that looks like a term is what reaches the
/// same code path a real query does — some search stacks reject or short-circuit
/// input that is obviously not a word.
fn word(seed: u64, n: u64) -> String {
    const CONSONANTS: &[u8] = b"bcdfghjklmnprstvwz";
    const VOWELS: &[u8] = b"aeiou";
    let mut v = mix(seed, n);
    let mut out = String::with_capacity(8);
    for i in 0..8 {
        let table = if i % 2 == 0 { CONSONANTS } else { VOWELS };
        out.push(table[(v % table.len() as u64) as usize] as char);
        v /= table.len() as u64;
    }
    out
}

/// Percent-encode a form field. Hand-rolled rather than reaching for a helper:
/// both halves are our own generated tokens plus an operator-supplied parameter
/// name, so the alphabet is small and known.
fn form_encode(name: &str, value: &str) -> String {
    let mut out = String::with_capacity(name.len() + value.len() + 1);
    for part in [name, value] {
        if !out.is_empty() {
            out.push('=');
        }
        for b in part.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
    }
    out
}

/// Read a path list: one path per line, `#` comments and blank lines skipped.
///
/// The syntactic rule is that an entry must start with exactly one `/`. It is
/// the first of two gates — [`Variation::check_paths`] re-checks the joined
/// result — and it exists to give the operator a message that names the bad line
/// rather than a surprise at setup.
pub fn parse_path_list(contents: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (i, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with('/') || line.starts_with("//") {
            return Err(format!(
                "path list line {}: {line:?} is not a path on the target — entries must start \
                 with a single '/' (an absolute URL or a '//host' form would move the run off \
                 the authorized origin)",
                i + 1
            ));
        }
        out.push(line.to_string());
    }
    if out.is_empty() {
        return Err("the path list contains no paths".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("http://10.1.2.3:8080/app/search").unwrap()
    }

    #[test]
    fn the_default_variation_changes_nothing() {
        let v = Variation::default();
        assert!(v.is_fixed());
        assert_eq!(v.label(), None);
        let out = v.apply(&base(), 7, false);
        assert_eq!(out.url, base());
        assert!(out.cookie.is_none() && out.form_body.is_none());
    }

    /// The point of the random-path flood: consecutive requests must not ask for
    /// the same URI, or the whole run is one cacheable request repeated.
    #[test]
    fn random_paths_differ_per_unit_and_keep_the_origin() {
        let v = Variation { path: PathMode::RandomSegment, ..Default::default() }.seeded();
        let mut seen = std::collections::HashSet::new();
        for n in 0..500 {
            let out = v.apply(&base(), n, false);
            assert_eq!(out.url.host_str(), base().host_str(), "host must never move");
            assert_eq!(out.url.port(), base().port(), "port must never move");
            assert!(out.url.path().starts_with("/app/search/"), "path was {}", out.url.path());
            seen.insert(out.url.path().to_string());
        }
        assert_eq!(seen.len(), 500, "every unit should ask for a distinct URI");
    }

    /// Two runs must not replay each other's URIs — otherwise a cache warmed by
    /// the first run absorbs the second, and the second run measures the cache.
    #[test]
    fn two_seeded_runs_do_not_generate_the_same_paths() {
        let a = Variation { path: PathMode::RandomSegment, ..Default::default() }.seeded();
        // The clock may not have moved between two `seeded()` calls, so this
        // asserts the property the seed provides, not the resolution of the
        // clock: distinct seeds give distinct URI streams.
        let mut b = a.clone();
        b.seed = a.seed ^ 0xABCD;
        assert_ne!(a.apply(&base(), 0, false).url, b.apply(&base(), 0, false).url);
    }

    #[test]
    fn a_path_list_is_drawn_from_and_joined_onto_the_target() {
        let list = parse_path_list("/a\n# a comment\n\n/b/c?x=1\n/d\n").expect("list parses");
        assert_eq!(list, vec!["/a", "/b/c?x=1", "/d"]);
        let v =
            Variation { path: PathMode::FromList(Arc::new(list)), ..Default::default() }.seeded();
        v.check_paths(&base()).expect("all entries are on the target");

        let mut seen = std::collections::HashSet::new();
        for n in 0..200 {
            let out = v.apply(&base(), n, false);
            assert_eq!(out.url.host_str(), base().host_str());
            seen.insert(out.url.path().to_string());
        }
        assert_eq!(seen.len(), 3, "all three list entries should be drawn: {seen:?}");
    }

    /// The fail-closed half. A list entry that moves the origin must refuse the
    /// run, not be quietly skipped at request time: quietly skipping means the
    /// operator's list ran differently than it reads.
    #[test]
    fn a_path_list_that_moves_the_origin_is_refused() {
        // Rejected on syntax, with the line number.
        for bad in ["http://evil.example/x", "//evil.example/x", "evil.example/x"] {
            let err = parse_path_list(&format!("/ok\n{bad}\n")).expect_err("must be refused");
            assert!(err.contains("line 2"), "{err}");
        }
        // And rejected again on the joined result, which is the gate that does
        // not depend on out-guessing URL normalisation.
        let v = Variation {
            path: PathMode::FromList(Arc::new(vec!["/ok".into(), "http://evil.example/x".into()])),
            ..Default::default()
        };
        let err = v.check_paths(&base()).expect_err("a different origin must refuse the run");
        assert!(err.contains("different origin"), "{err}");
    }

    #[test]
    fn an_empty_path_list_is_refused_rather_than_run_as_no_variation() {
        assert!(parse_path_list("\n# nothing but comments\n").is_err());
        let v = Variation { path: PathMode::FromList(Arc::new(Vec::new())), ..Default::default() };
        assert!(v.check_paths(&base()).is_err());
    }

    /// A search term goes in the query for GET and in the body for POST — the
    /// two ways a real search field is submitted.
    #[test]
    fn a_search_term_lands_in_the_query_or_the_body_by_method() {
        let v = Variation { search_param: Some("q".into()), ..Default::default() }.seeded();

        let get = v.apply(&base(), 1, false);
        let q: Vec<(String, String)> =
            get.url.query_pairs().map(|(k, val)| (k.into_owned(), val.into_owned())).collect();
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, "q");
        assert!(get.form_body.is_none(), "a GET term must not also produce a body");

        let post = v.apply(&base(), 1, true);
        assert!(post.url.query().is_none(), "a POST term must not also land in the query");
        let body = post.form_body.expect("a POST term becomes a form body");
        assert!(body.starts_with("q="), "body was {body:?}");
        assert_eq!(body.trim_start_matches("q="), q[0].1, "same term, different carrier");
    }

    #[test]
    fn search_terms_are_distinct_per_unit() {
        let v = Variation { search_param: Some("q".into()), ..Default::default() }.seeded();
        let terms: std::collections::HashSet<String> = (0..500)
            .map(|n| v.apply(&base(), n, true).form_body.expect("body"))
            .collect();
        assert_eq!(terms.len(), 500, "a cacheable run would repeat terms");
    }

    /// Session exhaustion needs the cookie to be *unrecognised and different*
    /// each time; a constant one is a single session held open, which is a
    /// different (and much weaker) test.
    #[test]
    fn session_cookies_are_fresh_per_unit() {
        let v = Variation { session_cookie: Some("JSESSIONID".into()), ..Default::default() }
            .seeded();
        let cookies: std::collections::HashSet<String> =
            (0..500).map(|n| v.apply(&base(), n, false).cookie.expect("cookie")).collect();
        assert_eq!(cookies.len(), 500);
        assert!(cookies.iter().all(|c| c.starts_with("JSESSIONID=")));
    }

    #[test]
    fn variations_compose_and_the_label_names_them() {
        let v = Variation {
            cache_bust: true,
            path: PathMode::RandomSegment,
            search_param: Some("q".into()),
            session_cookie: Some("PHPSESSID".into()),
            ..Default::default()
        }
        .seeded();
        assert!(!v.is_fixed());
        assert_eq!(
            v.label().as_deref(),
            Some("cache-bust, random path, random q, fresh session")
        );
        let out = v.apply(&base(), 3, false);
        assert!(out.url.path().starts_with("/app/search/"));
        let keys: Vec<String> = out.url.query_pairs().map(|(k, _)| k.into_owned()).collect();
        assert_eq!(keys, vec!["_cb", "q"]);
        assert!(out.cookie.is_some());
    }

    #[test]
    fn form_encoding_escapes_what_it_must() {
        assert_eq!(form_encode("q", "abc"), "q=abc");
        assert_eq!(form_encode("a b", "c&d"), "a+b=c%26d");
    }
}

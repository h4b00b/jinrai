//! Which destination port each L3/L4 unit goes to.
//!
//! A run used to target exactly one port, which is the right shape for the
//! single-service tests (`syn` at 443, `udp` at 53) but not for the two families
//! an operator actually gets asked for:
//!
//!   - **random-port floods** — the load is spread over a port range so the
//!     target cannot absorb it with one per-port rule, and every packet lands on
//!     a port with no listener, exercising the closed-port path (RST / ICMP
//!     port-unreachable generation, conntrack entries for flows that go nowhere);
//!   - **carpet bombing** — the same, spread across several `--target`s at once,
//!     so no single destination address or port looks like an attack on its own.
//!
//! Both are the same missing primitive: a *set* of ports, and a rule for picking
//! one per unit. That is all this module is.
//!
//! ## What it is not
//!
//! It does not touch the *source* port, and it never will. The no-spoofing
//! guardrail is about the source address, but source-port randomisation is the
//! neighbouring move that makes flows unattributable, and the raw builder keeps
//! its own deterministic source port for exactly that reason. This module only
//! decides where a unit is *sent*, which is bounded by the allowlist and by
//! `--target` either way.

use std::fmt;

/// How a run walks its port set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortOrder {
    /// Walk the set in order, advancing once per full pass over the targets, so
    /// a multi-target run enumerates the whole target x port cross-product
    /// instead of pairing each target with a fixed port. Deterministic, and for
    /// a one-port set it is byte-for-byte what every release before port sets
    /// did.
    #[default]
    Sequential,
    /// Draw a port uniformly at random per unit. This is what "random ports"
    /// means in a test plan: consecutive packets are unrelated, so a rule keyed
    /// on one port sees a trickle rather than the run.
    Random,
}

impl PortOrder {
    /// Parse the `--port-order` value.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "sequential" | "seq" => Ok(PortOrder::Sequential),
            "random" | "rand" => Ok(PortOrder::Random),
            other => Err(format!("unknown --port-order: {other} (want sequential|random)")),
        }
    }

    fn label(self) -> &'static str {
        match self {
            PortOrder::Sequential => "sequential",
            PortOrder::Random => "random",
        }
    }
}

/// The destination ports of one run, held as inclusive ranges rather than an
/// expanded list: `1-65535` is a legitimate spec and materialising it would
/// allocate 128 KiB to say something two integers already say.
#[derive(Debug, Clone)]
pub struct PortSet {
    /// Inclusive `(low, high)` ranges, in the order the operator wrote them —
    /// deliberately not sorted or merged, so the sequential walk is the order on
    /// the command line and the label echoes back what was typed.
    ranges: Vec<(u16, u16)>,
    /// Total port count across `ranges`. `u32` because 65535 ranges of one port
    /// each overflows `u16`, and a saturating `u16` would silently truncate the
    /// modulus that selects a port.
    total: u32,
    order: PortOrder,
}

impl PortSet {
    /// The one-port set. Kept as a plain constructor (no validation) because it
    /// is also how the portless ICMP modes carry their unused port.
    pub fn single(port: u16) -> Self {
        PortSet { ranges: vec![(port, port)], total: 1, order: PortOrder::Sequential }
    }

    /// Parse a `--port` spec: comma-separated single ports and `low-high`
    /// ranges, e.g. `80`, `1000-2000`, `80,443,8000-8100`.
    ///
    /// Port 0 is refused everywhere it can appear. It is not a destination an
    /// operator can mean — it is the kernel's "pick one" sentinel for *binding*,
    /// and the raw packet builder rewrites it to 1 — so accepting it would send
    /// traffic to a port nobody asked for.
    pub fn parse(spec: &str, order: PortOrder) -> Result<Self, String> {
        let mut ranges = Vec::new();
        let mut total: u32 = 0;
        for item in spec.split(',') {
            let item = item.trim();
            if item.is_empty() {
                return Err(format!("empty port in --port spec: {spec}"));
            }
            let (low, high) = match item.split_once('-') {
                Some((l, h)) => (parse_port(l.trim())?, parse_port(h.trim())?),
                None => {
                    let p = parse_port(item)?;
                    (p, p)
                }
            };
            if low > high {
                return Err(format!("inverted port range in --port: {item} (want low-high)"));
            }
            ranges.push((low, high));
            total += u32::from(high - low) + 1;
        }
        // `split(',')` on a non-empty string always yields at least one item, and
        // an empty one is rejected above, so `ranges` cannot be empty here.
        Ok(PortSet { ranges, total, order })
    }

    /// How many destination ports this run can hit. Named `count` rather than
    /// `len` because a `PortSet` is non-empty by construction, so the `is_empty`
    /// that conventionally accompanies `len` would be a method that only ever
    /// answers `false`.
    pub fn count(&self) -> u32 {
        self.total
    }

    /// Whether the set is a single port — the shape that predates port sets, and
    /// the one whose label should stay `port 443` rather than `ports 443`.
    pub fn is_single(&self) -> bool {
        self.total == 1
    }

    /// The `i`-th port, counting across the ranges in spec order. `i` is taken
    /// modulo the set size, so callers may pass a monotonically increasing unit
    /// counter without doing their own wrap.
    pub fn nth(&self, i: u32) -> u16 {
        let mut i = i % self.total;
        for &(low, high) in &self.ranges {
            let width = u32::from(high - low) + 1;
            if i < width {
                // `i < width` and `width` fits a `u16` span from `low`, so the
                // sum is inside the range and cannot overflow.
                return low + i as u16;
            }
            i -= width;
        }
        // Unreachable: `i` started below `total`, which is the sum of the widths
        // just walked. Answering with the first port rather than panicking keeps
        // a send loop alive if that arithmetic ever drifts.
        self.ranges[0].0
    }

    /// The port for the unit at sequential index `seq`.
    ///
    /// `seq` is the *pass* counter, not the unit counter: the engine advances it
    /// once per full pass over the targets so a multi-target sequential run
    /// enumerates target x port instead of pinning each target to one port.
    pub fn pick(&self, seq: u64, rng: &mut Rng) -> u16 {
        match self.order {
            PortOrder::Sequential => self.nth((seq % u64::from(self.total)) as u32),
            PortOrder::Random => self.nth(rng.below(self.total)),
        }
    }

    /// How the run label names this set: `port 443`, or
    /// `ports 1000-2000 (random)` once there is more than one.
    pub fn label(&self) -> String {
        if self.is_single() {
            format!("port {}", self.ranges[0].0)
        } else {
            format!("ports {self} ({})", self.order.label())
        }
    }
}

impl fmt::Display for PortSet {
    /// The spec in canonical form — what the operator typed, normalised.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, &(low, high)) in self.ranges.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            if low == high {
                write!(f, "{low}")?;
            } else {
                write!(f, "{low}-{high}")?;
            }
        }
        Ok(())
    }
}

fn parse_port(s: &str) -> Result<u16, String> {
    let p: u16 = s.parse().map_err(|_| format!("invalid port in --port: {s}"))?;
    if p == 0 {
        return Err("--port 0 is not a destination port (got 0)".to_string());
    }
    Ok(p)
}

/// A tiny xorshift64\* generator, used only to choose a destination port.
///
/// Deliberately hand-rolled rather than pulling in `rand`: the workspace keeps
/// its dependency set near-std, and the requirement here is "spread the load
/// over the range", not unpredictability. Nothing security-relevant depends on
/// this sequence — the allowlist bounds where traffic can go, and it does so
/// before this type is ever constructed.
#[derive(Debug)]
pub struct Rng(u64);

impl Rng {
    /// Seed from the wall clock. Two runs started in the same nanosecond would
    /// share a sequence; for spreading packets over a port range that is a
    /// non-event, and it keeps the seed path dependency-free.
    pub fn from_clock() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        // xorshift64* is degenerate at zero, so a clock that reads exactly the
        // epoch must not produce a generator that only ever returns 0.
        Rng(nanos | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value in `0..n`. Uses the high bits of a 64-bit draw scaled by `n`
    /// (Lemire's multiply-shift), which avoids the modulo bias a plain `% n`
    /// leaves behind — cheap enough to just do correctly.
    fn below(&mut self, n: u32) -> u32 {
        if n <= 1 {
            return 0;
        }
        ((u128::from(self.next_u64()) * u128::from(n)) >> 64) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_port_spec_matches_the_old_behaviour() {
        let set = PortSet::parse("443", PortOrder::Sequential).expect("443 parses");
        assert!(set.is_single());
        assert_eq!(set.count(), 1);
        assert_eq!(set.label(), "port 443");
        let mut rng = Rng::from_clock();
        for seq in 0..10 {
            assert_eq!(set.pick(seq, &mut rng), 443);
        }
    }

    #[test]
    fn a_range_enumerates_every_port_in_order() {
        let set = PortSet::parse("1000-1003", PortOrder::Sequential).expect("range parses");
        assert_eq!(set.count(), 4);
        let mut rng = Rng::from_clock();
        let picks: Vec<u16> = (0..6).map(|s| set.pick(s, &mut rng)).collect();
        // Wraps at the end of the set rather than running off it.
        assert_eq!(picks, vec![1000, 1001, 1002, 1003, 1000, 1001]);
    }

    #[test]
    fn a_mixed_spec_keeps_operator_order_and_spans_ranges() {
        let set = PortSet::parse("80,443,8000-8002", PortOrder::Sequential).expect("spec parses");
        assert_eq!(set.count(), 5);
        assert_eq!(set.to_string(), "80,443,8000-8002");
        let ports: Vec<u16> = (0..5).map(|i| set.nth(i)).collect();
        assert_eq!(ports, vec![80, 443, 8000, 8001, 8002]);
    }

    /// The point of the random order: consecutive units are not consecutive
    /// ports. A run that quietly fell back to sequential would still "work" and
    /// would still be the wrong test, so assert the sequence is not the walk.
    #[test]
    fn random_order_stays_inside_the_set_and_is_not_the_walk() {
        let set = PortSet::parse("2000-2999", PortOrder::Random).expect("range parses");
        let mut rng = Rng::from_clock();
        let picks: Vec<u16> = (0..200).map(|s| set.pick(s, &mut rng)).collect();
        for p in &picks {
            assert!((2000..=2999).contains(p), "picked {p}, outside the set");
        }
        let sequential: Vec<u16> = (0..200).map(|i| set.nth(i as u32)).collect();
        assert_ne!(picks, sequential, "random order produced the sequential walk");
        // 200 draws from 1000 ports: a generator stuck on one value is the
        // failure this catches, not a distribution claim.
        let distinct: std::collections::HashSet<u16> = picks.iter().copied().collect();
        assert!(distinct.len() > 100, "only {} distinct ports in 200 draws", distinct.len());
    }

    /// Every rejection here is a spec that would otherwise send traffic
    /// somewhere the operator did not name.
    #[test]
    fn malformed_specs_are_refused() {
        for spec in ["", "0", "80,0", "0-100", "100-80", "80,,443", "http", "80-", "-80", "70000"] {
            assert!(
                PortSet::parse(spec, PortOrder::Sequential).is_err(),
                "spec {spec:?} should be refused"
            );
        }
    }

    #[test]
    fn the_full_range_is_a_legal_spec() {
        let set = PortSet::parse("1-65535", PortOrder::Random).expect("full range parses");
        assert_eq!(set.count(), 65535);
        assert_eq!(set.nth(0), 1);
        assert_eq!(set.nth(65534), 65535);
        // The modulus is taken on a u32, so the port count is not truncated.
        assert_eq!(set.nth(65535), 1);
    }

    #[test]
    fn port_order_parses_its_spellings() {
        assert_eq!(PortOrder::parse("sequential"), Ok(PortOrder::Sequential));
        assert_eq!(PortOrder::parse("random"), Ok(PortOrder::Random));
        assert!(PortOrder::parse("shuffle").is_err());
    }
}

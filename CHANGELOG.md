# Changelog

All notable changes to **jinrai** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Because jinrai is an internal, dual-use resilience tester, changes that affect
the safety gate, authorization, or auditability are called out under
**Security** even when they are additive.

## [Unreleased]

_Nothing yet._

## [0.1.0] — 2026-07-08

First end-to-end version: the safety gate wired through real L7 and L3/L4
traffic generation, with a tamper-evident audit trail. Covers roadmap
Phases 0–4.

### Added

- **Workspace scaffolding** (Phase 0) — Cargo workspace with six crates:
  `core`, `safety`, `l34`, `l7`, `metrics`, `cli`. Pinned toolchain,
  `panic = "abort"` release profile, `forbid(unsafe_code)` across all crates.
- **`core`** (Phase 1) — shared engine vocabulary (`Layer`, `RateCap`,
  `RunPlan`, `RunReport`) and the `StressModule` contract every traffic module
  implements. Every entry point consumes `AuthorizedTarget`, so a module author
  cannot sidestep the gate. Dependency-free.
- **`l7`** (Phase 2) — L7 HTTP/API engine on tokio + reqwest (rustls, no
  system TLS). Constant-rate GET load; latency percentiles (p50/p90/p99/max)
  computed with `hdrhistogram` and surfaced in `RunReport`. The engine
  resolves the URL host once and pins reqwest to the gate-authorized IP(s) via
  `resolve_to_addrs`, defeating DNS rebinding.
- **`l34`** (Phase 3) — L3/L4 packet generation for isolated-lab networks:
  UDP flood, TCP connect flood (holds connections open), and TCP SYN flood
  (raw socket via `socket2` + `etherparse`, IPv4-only). Kept
  `forbid(unsafe_code)`. Preflight fails fast (non-zero exit) on a missing
  `CAP_NET_RAW` capability or an unreachable/unsupported target.
- **`metrics`** (Phase 4) — human-readable run summaries, plus a
  **tamper-evident, append-only audit log** (`audit.rs`): JSONL, one record per
  line, chained with SHA-256 (each record carries the previous record's hash).
  Events: `RunAuthorized`, `RunCompleted`, `RunRefused`. `AuditLog::open`
  recovers the chain state so records continue the same chain across process
  runs; `verify()` walks the log and names the first inconsistency. RFC 3339
  timestamps are computed without a date dependency.
- **`cli`** — the `jinrai` binary: std-only argument parsing, the operator
  gate, and orchestration for both layers. New flags `--audit-log <PATH>`
  (opt-in audit trail; operator identity from `$JINRAI_OPERATOR`, else the OS
  user) and `--verify-audit <PATH>` (verify a log's integrity and exit).

### Security

- **The gate (`safety`, Phase 1)** — std-only, zero external dependencies,
  `forbid(unsafe_code)`. `AuthorizedTarget` has no public constructor: the sole
  way to obtain one is `Authorization::authorize`, which checks an
  operator-supplied allowlist passed at runtime. "Fire at an unauthorized
  target" is therefore not an expressible program state. Fail-closed: an empty
  allowlist authorizes nothing.
- **Datum-based validation** — a target is validated *as given*, not by its
  resolution. An IP literal is checked against the IP/CIDR rules; a DNS name is
  checked (as a string, label-boundary, case-insensitive, ASCII-only) against
  the DNS rules. A name that resolves to an allowlisted IP but matches no DNS
  rule is refused.
- **No source-IP spoofing (`l34`)** — a hard guardrail: the SYN source address
  is always the host's real OS-routed local address. There is no flag, API, or
  config anywhere to set, forge, or randomize it. No reflection/amplification
  primitives. L3/L4 runs additionally require an explicit `--ack-l34-lab`
  acknowledgement.
- **Kill switch** — a shared abort signal wired to Ctrl-C in the CLI; workers
  poll it and stop promptly, and the run reports what it managed to send.
- **Tamper-evident audit log (Phase 4)** — the SHA-256 hash chain makes editing,
  deleting, reordering, or truncating records detectable. The log is opened
  *before* any traffic and a write failure aborts the run, so traffic never
  outruns its own record. Scope is tamper-evidence, not cryptographic
  non-repudiation (a full rewrite can recompute a clean chain; closing that gap
  would need an HMAC key or external anchoring).

### Fixed

- L7: IPv4-mapped IPv6 (`::ffff:a.b.c.d`) could bypass an allowlist;
  `Cidr::contains` now refuses mapped addresses (fail-closed).
- `safety`: malformed / null-byte host names (e.g. `api\0.staging.internal`)
  could match a `*.` wildcard; the query is now validated before matching.
- CLI: exit code is now non-zero when an L3/L4 run aborts or emits zero units
  while every attempt errored, instead of reporting a hollow success.
- `l34`: UDP and SYN modes now refuse IPv6 targets up front (fail-closed)
  rather than silently sending nothing and exiting zero.

### Removed

- Deleted the dead, uncompiled `crates/l34/src/syn.rs`, which exposed a
  `build_syn_packet(src, …)` signature taking an arbitrary source address — the
  exact spoofing shape the project forbids. The live SYN path in `l34/lib.rs`
  builds packets from the real source only.

[Unreleased]: https://github.com/h4b00b/jinrai/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/h4b00b/jinrai/releases/tag/v0.1.0

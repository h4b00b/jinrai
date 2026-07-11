# Changelog

All notable changes to **jinrai** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Because jinrai is an internal, dual-use resilience tester, changes that affect
the safety gate, authorization, or auditability are called out under
**Security** even when they are additive.

## [Unreleased]

### Added

- **TCP flag floods (Phase 7)** — `--l4-mode` gains `ack`, `fin`, and `rst`
  alongside the existing `syn`. Each crafts an IPv4+TCP packet with exactly one
  control flag set and reuses the SYN primitive's raw socket, packet-crafting,
  and real-source-address machinery. SYN exercises the accept backlog; ACK / FIN
  / RST exercise a target's connection-tracking / stateful-firewall handling of
  packets that match no established connection. Like SYN they are IPv4-only,
  require `CAP_NET_RAW`/root, and are gated behind `--ack-l34-lab` + the
  allowlist.
- **Load profiles (Phase 6)** — the L7 fast engine no longer only runs a flat
  rate. `--profile` shapes the load over time: `constant` (default), `soak` (a
  long flat hold), `ramp` (step the rate up from `--ramp-start` to the ceiling in
  `--ramp-steps` stages), and `spike` (hold `--spike-base`, jump to the ceiling
  for `--spike-secs`, fall back). Internally a profile compiles to a sequence of
  constant-rate stages the engine runs back-to-back, so one dispatch mechanism
  executes every shape. Runs with no `--profile` behave exactly as before.
- **Breaking-point discovery (Phase 6)** — `--discover-knee` ramps toward the
  ceiling and, evaluating the SLO's rate thresholds over each stage, **stops at
  the first stage that breaches** rather than pushing further, reporting the
  capacity *knee*: the highest rate the target held within SLO and the rate at
  which it broke (`knee(sustained=N/s broke_at=M/s)`). Finding the knee is the
  goal, so a discovery run exits `0` whether or not a knee is found; it needs a
  `--slo-max-*-rate` to detect the breach and refuses fail-closed without one.
  The live watchdog is suppressed during discovery (the run is meant to reach a
  breach and stop cleanly, not abort).
- **Response classification & SLO verdict (Phase 5)** — the L7 fast engine now
  classifies every completed response by status class (`status_2xx/3xx/4xx/5xx`)
  and separates *completed-but-failing* responses (a `500` is a completion, not a
  transport error) from real transport failures (`errors`, with `timeouts` as a
  named subset). Operators can declare a Service-Level Objective with
  `--slo-max-error-rate`, `--slo-max-5xx-rate`, `--slo-max-4xx-rate` (off by
  default) and `--slo-max-p99-ms`; the run prints a `SLO: PASS/FAIL(...)` verdict
  and **exits non-zero when the target misses the SLO**, so automation can tell
  "the target held" from "the target buckled". Runs with no `--slo-*` flag behave
  exactly as before. The verdict and the status breakdown are recorded in the
  audit log's `run_completed` event.
- **Inline health-watchdog (Phase 5)** — `--watchdog` runs a background task that
  evaluates the trailing window of traffic against the SLO's *rate* thresholds
  and trips the shared kill-switch after `--watchdog-breaches` consecutive
  breaching `--watchdog-window`s, auto-aborting a run that is hurting the target.
  A watchdog abort is reported (`aborted_by_watchdog`) and exits non-zero.

### Security

- **The no-spoofing guarantee extends to every TCP flag flood (Phase 7)** — the
  new `ack`/`fin`/`rst` modes go through the same `source_ipv4_for` route lookup
  as SYN: the source address is always the host's real, OS-routed outbound
  address. There is still no API anywhere to set, randomise, or spoof it, and no
  reflection/amplification path — these remain direct self-tests, not weapons.
- **Load profiles cannot escape the rate ceiling (Phase 6)** — `--rate` remains a
  hard safety cap, not just a knob. Every stage a profile compiles to is clamped
  to it (`RateCap::clamped_to`), so a ramp, spike, or a fat-fingered profile can
  only ever shape traffic *up to* `--rate`, never above it. `--discover-knee`
  ramps only toward the same ceiling and stops at the first SLO breach, so it does
  not blindly escalate load past the breaking point.
- The watchdog is **fail-safe by construction**: it can only ever *stop* traffic
  (via the existing `KillSwitch` that every engine already polls) and has no path
  to generate any. It does not touch the `AuthorizedTarget` invariant, so the
  authorization gate is unchanged. A lull (a window with zero attempts) resets
  the breach streak rather than counting as a breach, and the worst-case
  time-to-abort is bounded by `window * breaches` of *sustained* breach so a
  transient spike cannot abort a legitimate run.

- **L7 request primitives** — the L7 engine is no longer GET-only. `--l7-method`
  selects `get` | `post` | `head` (fast, reqwest-based, constant-rate) plus two
  slow-connection primitives, `slowloris` and `slowbody`. `--body` supplies a
  POST body; `--cache-bust` appends a unique `_cb=<n>` query to every request so
  caches/CDNs cannot serve a stored response.
- **Slow-connection L7 engine (`l7::slow`)** — Slowloris (partial request
  headers, never terminated) and slow-body / RUDY (oversized `Content-Length`
  with the body trickled a byte at a time). Bounded by `--slow-connections`
  (concurrent ceiling) and `--drip-ms` (keep-alive interval); the rate cap is
  reinterpreted as connections-opened-per-second. Header-profile techniques
  (null/oddball `User-Agent`, `Cookie`, `Referer`, …) are expressed via the
  existing `--header` flag rather than hard-coded vendor "bypass" presets.

### Security

- The fast and slow L7 primitives share the **identical** trust boundary: the
  URL host is authorized as a datum and resolved exactly once to a pinned connect
  address, so every request/connection only ever reaches the gate-authorized
  target. The cache-buster mutates only the query string — never the host — so
  the datum authorization and the pinned resolution still hold for every request.
- Slow mode is **http-only** for now: an `https` URL is refused fail-closed
  (dribbling raw bytes through a TLS session is not implemented).

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

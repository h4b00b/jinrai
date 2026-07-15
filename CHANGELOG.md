# Changelog

All notable changes to **jinrai** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Because jinrai is an internal, dual-use resilience tester, changes that affect
the safety gate, authorization, or auditability are called out under
**Security** even when they are additive.

While the tool is pre-1.0, each additive feature increment gets its own minor
release (`0.MINOR.0`); breaking changes would too, until the API stabilises at
1.0.

## [Unreleased]

Nothing yet.

## [0.20.0] — 2026-07-15

L7 (extension): stream-based HTTP/2 floods — closes the in-scope HTTP/2 gap
with three new `--l7-method` primitives in a shared `h2_stream_flood` engine.
Unlike the connection-level control-frame floods, these open **real request
streams** (a minimal hand-rolled HPACK request block, std-only, no new dep).

### Added

- **`h2-made-you-reset`** — MadeYouReset (CVE-2025-8671): open a complete request
  (`HEADERS` with `END_STREAM`), then send a **zero-increment `WINDOW_UPDATE`** on
  that stream. RFC 9113 §6.9 makes a zero increment a *stream* error, so the
  **server** emits `RST_STREAM` — the client never sends `RST_STREAM` itself,
  side-stepping Rapid-Reset mitigations while the reset streams stop counting
  against `MAX_CONCURRENT_STREAMS`. Rate cap = reset cycles/sec.
- **`h2-empty-data`** — empty-DATA flood (CVE-2019-9518): open a stream that does
  not end (`HEADERS` without `END_STREAM`), then flood **zero-length `DATA`
  frames** without `END_STREAM`; the peer does per-frame work disproportionate to
  the near-zero bandwidth. Rate cap = frames/sec.
- **`h2-bomb`** — HTTP/2 Bomb (CVE-2026-49975 / CVE-2026-47774): each `HEADERS`
  frame inserts one 1-byte HPACK dynamic-table entry and then references it
  thousands of times (1 byte each), so the server materialises thousands of header
  entries per frame (HPACK amplification). The opening `SETTINGS` advertises
  `INITIAL_WINDOW_SIZE = 0` so the server can never send a response body and free
  the stream, pinning the amplified memory. Rate cap = bomb frames/sec.

### Notes

- All three reuse the shared raw-framing primitives in `l7::h2_frames` (extended
  with `DATA`/`END_STREAM`/`END_HEADERS` constants) and the same safety boundary
  as the other L7 engines: datum-authorized, pinned connect address, `https` via
  ALPN `h2` / `http` via prior-knowledge h2c, bounded by duration + rate cap +
  kill switch. The amplification is **server-side memory/CPU** from bytes the
  client really sends from its real address — no spoofing, no network reflection.
  `forbid(unsafe_code)` retained; no new dependency.

## [0.19.0] — 2026-07-15

L7 (extension): connection-concurrency cap for the fast request flood — the
controlled form of keep-alive connection exhaustion.

### Added

- **`--max-connections <N>`** caps the number of concurrent in-flight requests
  (≈ concurrent keep-alive connections) for the fast `get`/`post`/`head` flood.
  A dispatch tick that would exceed the cap is **skipped, not queued**, so the
  load holds at most `N` connections busy rather than an unbounded rate-driven
  fan-out. This pins the connection count so an operator can probe a server's
  connection-slot / worker-pool / keep-alive limit directly (the controlled,
  bounded form of GoldenEye/XerXes-style keep-alive load) — reusing the existing
  engine, connection pooling, `--cache-bust`, profiles and SLO machinery.
  Default `0` = unbounded (the historical behaviour). `--rate` still caps the
  request rate on top: connections are held busy *up to* that ceiling.

### Notes

- Implemented as a `tokio::sync::Semaphore` around the dispatched request tasks
  (permit held for each request's lifetime); no new dependency, `forbid(unsafe_code)`
  retained. Verified by a concurrency-peak test (peak simultaneous handlers ≤ cap).

## [0.18.0] — 2026-07-15

L7 (extension): slow-read connection primitive — the read-side mirror of slowbody.

### Added

- **Slow-read** — `--l7-method slow-read` opens connections (like the other slow
  primitives), sends a *complete* HTTP request, then drains the response one small
  64-byte chunk per `--drip-ms` tick while advertising a shrunken receive window
  (`SO_RCVBUF` set as small as the OS allows). The server's send buffer stays full
  and it cannot retire the connection — exercising the response-write / send
  timeout, the counterpart to `slowbody`'s request-body read timeout. Works over
  http and `https` (slow-TLS), reusing the connection-holding engine.
- The slow engine's per-connection driver is now generic over the concrete stream
  (plaintext `TcpStream` or TLS session), so read and write slow modes share one
  code path with no trait-object boxing.

### Changed

- `--drip-ms` is now documented as the general per-tick interval: the keep-alive
  write interval for `slowloris`/`slowbody`, or the read interval for `slow-read`.

### Dependencies

- `jinrai-l7` gains `socket2` (already in the workspace tree via `l34`), used only
  to shrink `SO_RCVBUF` on a connected stream for slow-read (`SockRef` borrow — no
  `unsafe`, no second socket). `forbid(unsafe_code)` is retained.

## [0.17.0] — 2026-07-15

Phase 7 (extension): ICMP timestamp + address-mask query floods (L3).

### Added

- **ICMP timestamp-request flood** — `--l4-mode icmp-timestamp` sends ICMPv4
  timestamp requests (type 13): a 20-byte message carrying three 32-bit
  timestamps (originate set from the per-packet sequence, receive/transmit zero),
  forcing the target's ICMP timestamp handler and probing hosts that answer — and
  potentially leak clock state — under load.
- **ICMP address-mask-request flood** — `--l4-mode icmp-address-mask` sends ICMPv4
  address-mask requests (type 17): a 12-byte message with a zero mask field,
  forcing the address-mask handler.
- Both extend the existing L3 echo flood: they are **query** messages the target
  answers directly (never forged error/redirect/router messages, which only make
  sense spoofed and remain out of scope). The ICMP builder was generalised to
  emit echo/timestamp/address-mask from one shared code path (same `IPPROTO_ICMP`
  raw socket, kernel-supplied IP header with the host's **real** source address —
  no spoofing — IPv4-only, `CAP_NET_RAW`, portless, gated behind `--ack-l34-lab`
  + the allowlist).

## [0.16.0] — 2026-07-15

Phase 7 (extension): extended anomalous TCP flag floods (L4).

### Added

- **URG / CWR / ECE single-flag floods** — `--l4-mode urg|cwr|ece` send an
  otherwise-empty raw TCP segment carrying only that one rarely-standalone bit
  (the urgent flag with a zero pointer, or a lone ECN Congestion-Window-Reduced /
  ECN-Echo bit), probing how the target stack and any middlebox treat these flags
  outside an established connection.
- **SYN+FIN / SYN+RST illegal-combination floods** — `--l4-mode syn-fin|syn-rst`
  set mutually-contradictory flag fields (open+close, open+reset) that match no
  RFC-legal TCP state — classic firewall/IDS flag-handling probes, alongside the
  existing `xmas` and `null` anomaly floods.
- The shared `TcpFlags` gained `cwr`/`ece` bits; all seven new/extended modes reuse
  the existing raw-TCP flag-flood machinery (same `IPPROTO_RAW` socket, real
  route-local source address — **never spoofed** — IPv4-only, `CAP_NET_RAW`).

## [0.15.0] — 2026-07-15

Phase 7 (extension): TCP-options bomb (L4).

### Added

- **TCP-options bomb** — `--l4-mode tcp-options` is a raw SYN flood whose every
  packet carries the maximal 40-byte TCP option block (MSS + SACK-permitted +
  timestamp + window scale, NOP-padded to the limit). Each SYN forces the target's
  TCP stack to parse a full-size option field and allocate SACK/timestamp state,
  amplifying the per-SYN cost over a bare SYN. It reuses the existing raw-TCP flag
  flood machinery (same `IPPROTO_RAW` socket, real route-local source address,
  per-packet checksum), differing only in attaching the option block; the
  timestamp folds in the per-packet counter so successive SYNs are not
  byte-identical. Same constraints as the flag floods: `CAP_NET_RAW`/root,
  IPv4-only, gated behind `--ack-l34-lab` + the allowlist.

### Security

- The options bomb is a **direct** self-test with the same guarantees as the rest
  of `l34`: crafted only for gate-authorized targets, from the host's real
  OS-routed source address (obtained by asking the kernel which local address
  routes to the target — never forged), with **no** spoofing and no
  reflection/amplification.

## [0.14.0] — 2026-07-15

Phase 7 (extension): HTTP/2 WINDOW_UPDATE & PRIORITY floods.

### Added

- **HTTP/2 WINDOW_UPDATE & PRIORITY floods** — `--l7-method h2-window-update`
  (CVE-2019-9514) floods connection-level `WINDOW_UPDATE` frames on stream 0, each
  obliging the server to process a flow-control credit update; the increment is a
  fixed, valid non-zero value (a 0 increment is a protocol error), so the
  connection is never torn down. `--l7-method h2-priority` (CVE-2019-9513, the
  "Resource Loop") floods `PRIORITY` frames, each of which reshuffles the server's
  priority tree — work it must do even though no request stream is opened. Both
  extend the existing `H2FrameFloodEngine` and reuse `l7::h2_frames`, so they share
  the same connection setup, rate-capped drive loop, and safety boundary as the
  SETTINGS/PING floods. The rate cap is reinterpreted as *frames per second*;
  `https` negotiates HTTP/2 via ALPN, `http` uses prior-knowledge h2c.

### Security

- The two new frame floods keep the **identical trust boundary** as the other L7
  primitives: the URL host is authorized as a datum and pinned to a single connect
  address, so the connection only ever reaches the gate-authorized target. Direct
  self-tests — no source-IP spoofing, no reflection/amplification.

## [0.13.0] — 2026-07-12

Phase 7 (extension): TCP data (PSH-ACK) flood.

### Added

- **TCP data flood (PSH-ACK)** — `--l4-mode data` establishes a bounded pool of
  **real** TCP connections through the OS stack and writes application data into
  them, filling the target's receive / application buffers rather than just its
  accept backlog (SYN) or connection-tracking state (ACK/FIN/RST). Each flushed
  write emits a PSH-ACK segment; a write that blocks on a full send buffer is
  *pressure applied* (the target is not draining) and counts as a unit, while a
  reset/broken connection is retired and replaced. `--payload-size` sets the
  per-write size. Unlike the raw-TCP floods it needs **no** `CAP_NET_RAW` and
  works over **IPv4 and IPv6** (like the TCP-connect flood), still gated behind
  `--ack-l34-lab` + the allowlist.

### Security

- The data flood is a **direct** self-test with the same guarantees as the rest of
  `l34`: it connects only to gate-authorized targets, from the host's real OS
  source address (the kernel owns the connection), with **no** spoofing and no
  reflection/amplification. Because it uses the OS TCP stack it never crafts a
  packet, so there is no source-address surface at all.

## [0.12.0] — 2026-07-12

Phase 7 (extension): HTTP/2 control-frame floods (SETTINGS / PING).

### Added

- **HTTP/2 SETTINGS & PING floods** — `--l7-method h2-settings` (CVE-2019-9515)
  floods empty `SETTINGS` frames, each of which the server must apply and answer
  with a `SETTINGS` ACK; `--l7-method h2-ping` (CVE-2019-9512) floods `PING`
  frames, each of which the server must answer with a `PING` ACK (PONG). Both turn
  one cheap client frame into guaranteed server work + egress, on stream 0, with
  no request stream — so there is no flow-control credit to exhaust and no stream
  state to manage. The rate cap is reinterpreted as *frames per second*. `https`
  negotiates HTTP/2 via ALPN; `http` uses prior-knowledge h2c.
- **Shared raw-framing module (`l7::h2_frames`)** — the HTTP/2 connection preface,
  frame type/flag constants, and the frame encoder are factored out of
  `l7::h2_continuation` so both it and the new frame-flood engine share one
  implementation. No new dependency (still std-only hand-crafted frames).

### Security

- The frame floods keep the **identical trust boundary** as the other L7
  primitives: the URL host is authorized as a datum and pinned to a single connect
  address, so the connection only ever reaches the gate-authorized target. Direct
  self-tests — no source-IP spoofing, no reflection/amplification. Accept-any-cert
  TLS is the same scoped choice documented for the other h2 primitives.

## [0.11.0] — 2026-07-12

Phase 7 (extension): TLS handshake flood (THC-SSL-DoS class).

### Added

- **TLS handshake flood** — `--l7-method tls-handshake` repeatedly opens a TCP
  connection, completes a **full** TLS handshake, and immediately drops it —
  concurrently, so a slow server does not throttle the dispatch rate. A handshake
  is deeply asymmetric (the server spends far more CPU on key exchange + signing
  than the client spends requesting it), so flooding fresh handshakes drives the
  server's CPU at little client cost — the THC-SSL-DoS resource asymmetry, exposed
  as a self-test. `https`-only (a plaintext target has no handshake and is refused
  fail-closed). The rate cap is reinterpreted as *handshakes per second*.
- **Session resumption is now disabled** in the shared `l7::tls` client config, so
  every connection is a full handshake. This is a no-op for the single-connection
  slow / rapid-reset / continuation engines but is what makes the handshake flood
  meaningful — a resumed handshake is cheap for the server and would defeat the
  test. No new dependency (reuses the rustls/ring stack already in the tree).

### Security

- The handshake flood keeps the **identical trust boundary** as the other L7
  primitives: the URL host is authorized as a datum and pinned to a single connect
  address, so every connection only ever reaches the gate-authorized target. It is
  a **direct** self-test — no source-IP spoofing and no reflection/amplification.
  The accept-any-certificate stance is the same scoped choice documented for
  slow-TLS (transport to an authorized host; no secrets sent, no response trusted).

## [0.10.0] — 2026-07-12

Phase 7 (extension): TCP anomalous-flag floods (Xmas / NULL).

### Added

- **TCP Xmas & NULL floods** — `--l4-mode` gains `xmas` (FIN+PSH+URG set at once)
  and `null` (no control flags set). Where the existing SYN/ACK/FIN/RST floods
  each set exactly one flag, these craft **illegal flag combinations** to probe
  how a stateful firewall / connection-tracker / TCP stack handles segments that
  match no RFC-legal state. They reuse the raw-TCP flag-flood machinery
  end-to-end: same raw socket, packet crafting, per-target real-source-address
  lookup, rate cap, kill-switch and preflight. Like the other raw-TCP modes they
  are IPv4-only, require `CAP_NET_RAW`/root, and are gated behind `--ack-l34-lab`
  + the allowlist.
- The single-flag `TcpFlag` enum is generalised to a `TcpFlags` set and the packet
  builder applies flags imperatively, so any combination is expressible through
  one code path (SYN/ACK/FIN/RST/Xmas/NULL all flow through it).

### Security

- **The no-spoofing guarantee extends to the anomalous-flag floods** — Xmas and
  NULL go through the same `source_ipv4_for` route lookup as the other raw-TCP
  modes: the source address is always the host's real, OS-routed outbound
  address. There is still no API anywhere to set, randomise, or spoof it, and no
  reflection/amplification path — they remain direct self-tests, not weapons.

## [0.9.0] — 2026-07-12

Phase 7 (extension): HTTP/2 CONTINUATION flood — completes the h2 frame-abuse pair.

### Added

- **HTTP/2 CONTINUATION flood (CVE-2024-27316)** — `--l7-method h2-continuation`
  opens one HTTP/2 stream with a HEADERS frame that **withholds `END_HEADERS`**,
  then streams `CONTINUATION` frames that also never set `END_HEADERS`. The server
  must buffer the concatenated header-block fragments for a block that is never
  completed. Because `CONTINUATION` frames are **not flow-controlled** (only
  `DATA` is), the client forces unbounded server-side header buffering at almost
  no cost to itself — the resource asymmetry that makes this a DoS class. Exposed
  as a resilience self-test so an operator can measure whether their own stack
  bounds header accumulation. The rate cap is reinterpreted as *CONTINUATION
  frames per second*. `https` negotiates HTTP/2 via ALPN; `http` uses
  prior-knowledge h2c.
- Unlike the `h2`-crate-based rapid-reset, this primitive needs **frame-level
  control** (`h2` only ever emits complete, `END_HEADERS`-terminated blocks), so
  the HTTP/2 preface and frames are crafted by hand directly on the byte stream —
  std-only, exactly as `l34` crafts packets. No new dependency, no new TLS/HTTP
  stack (it reuses the shared `l7::tls` accept-any-cert config with ALPN `h2`).

### Security

- The CONTINUATION engine keeps the **identical trust boundary** as the other L7
  primitives: the URL host is authorized as a datum and pinned to a single connect
  address, so the HTTP/2 connection only ever reaches the gate-authorized target.
  It is a **direct** self-test — no source-IP spoofing and no
  reflection/amplification path — meaningful only against infrastructure the
  operator is authorized to test, which the allowlist enforces by construction.
  The accept-any-cert TLS stance is the same scoped choice documented for
  slow-TLS and rapid-reset (transport to an authorized host, no secrets sent, no
  response trusted).

## [0.8.0] — 2026-07-11

Phase 7 (part 4, completes Phase 7): HTTP/2 rapid-reset.

### Added

- **HTTP/2 rapid-reset (Phase 7, CVE-2023-44487)** — `--l7-method h2-rapid-reset`
  opens HTTP/2 streams and **immediately cancels each with `RST_STREAM`** before
  the server responds. Because a reset frees its concurrency slot instantly, the
  client creates server-side work far faster than it spends — the resource
  asymmetry that makes this a DoS class. Exposed as a resilience self-test so an
  operator can measure whether their own stack is patched / rate-limited. The
  rate cap is reinterpreted as *streams-reset per second*. `https` negotiates
  HTTP/2 via ALPN; `http` uses prior-knowledge h2c. Uses the `h2`/`http` crates
  already in the tree (via reqwest/hyper), so no new TLS or HTTP stack.
- **Shared TLS module (`l7::tls`)** — the accept-any-certificate rustls config
  and SNI helper are factored out of `l7::slow` so both the slow-connection and
  rapid-reset engines share one verifier (rapid-reset adds ALPN `h2`).

### Security

- The rapid-reset engine keeps the **identical trust boundary** as the other L7
  primitives: the URL host is authorized as a datum and pinned to a single
  connect address, so the HTTP/2 connection only ever reaches the gate-authorized
  target. As a denial-of-service technique it is only meaningful against
  infrastructure the operator is authorized to test — the allowlist enforces that
  by construction. The accept-any-cert TLS stance is the same scoped choice
  documented for slow-TLS (transport to an authorized host, no secrets sent, no
  response trusted).

## [0.7.0] — 2026-07-11

Phase 7 (part 3): ICMP / L3 echo flood.

### Added

- **ICMP echo flood (Phase 7)** — `--l4-mode icmp` adds a true **L3** primitive:
  ICMPv4 echo-request packets on a raw socket. It reuses the L3/L4 engine's rate
  cap, kill-switch, and preflight, reports as `Layer::L3`, and needs no `--port`
  (`--port` is now optional for `icmp`, still required for the other modes). Like
  the raw-TCP modes it is IPv4-only, requires `CAP_NET_RAW`/root, and is gated
  behind `--ack-l34-lab` + the allowlist. The ICMP message (type 8 + Internet
  checksum) is crafted std-only; no new dependency.

### Security

- **ICMP keeps the no-spoofing guarantee.** The echo flood uses an `IPPROTO_ICMP`
  raw socket, so the **kernel** writes the IPv4 header and the source is the
  host's real routed address — there is, as everywhere else in `l34`, no path to
  set, forge, or randomise it, and no reflection/amplification.

## [0.6.0] — 2026-07-11

Phase 7 (part 2): slow-connection primitives over TLS.

### Added

- **Slow-TLS (Phase 7)** — the slow-connection engine (`slowloris` / `slowbody`)
  now accepts `https` targets, which were previously refused. An https run
  completes a real rustls (ring) TLS handshake over the pinned TCP connection and
  then dribbles the same partial-request bytes *inside* the TLS session. No new
  flag: `--l7-method slowloris`/`slowbody` with an `https://` URL just works. The
  `L7Error::SlowHttpsUnsupported` variant is removed.

### Security

- **Slow-TLS accepts any server certificate — deliberately and in scope.** The
  safety boundary for these primitives is *which host we connect to*, already
  enforced by datum authorization + the single pinned connect address; the peer's
  certificate identity is not used for any decision, and the primitive sends no
  secrets and never reads a response. Verifying against a public trust chain would
  make it useless against the self-signed / internal-CA certs typical of lab
  targets. The relaxed verifier is confined to `l7::slow`; the fast
  `L7Engine` keeps reqwest's normal certificate verification. rustls is pinned to
  the `ring` provider already in the tree, so no second TLS stack is added.

## [0.5.0] — 2026-07-11

Phase 7 (part 1): TCP flag floods.

### Added

- **TCP flag floods (Phase 7)** — `--l4-mode` gains `ack`, `fin`, and `rst`
  alongside the existing `syn`. Each crafts an IPv4+TCP packet with exactly one
  control flag set and reuses the SYN primitive's raw socket, packet-crafting,
  and real-source-address machinery. SYN exercises the accept backlog; ACK / FIN
  / RST exercise a target's connection-tracking / stateful-firewall handling of
  packets that match no established connection. Like SYN they are IPv4-only,
  require `CAP_NET_RAW`/root, and are gated behind `--ack-l34-lab` + the
  allowlist.

### Security

- **The no-spoofing guarantee extends to every TCP flag flood (Phase 7)** — the
  new `ack`/`fin`/`rst` modes go through the same `source_ipv4_for` route lookup
  as SYN: the source address is always the host's real, OS-routed outbound
  address. There is still no API anywhere to set, randomise, or spoof it, and no
  reflection/amplification path — these remain direct self-tests, not weapons.

## [0.4.0] — 2026-07-11

Phase 6: load profiles and breaking-point discovery.

### Added

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

### Security

- **Load profiles cannot escape the rate ceiling (Phase 6)** — `--rate` remains a
  hard safety cap, not just a knob. Every stage a profile compiles to is clamped
  to it (`RateCap::clamped_to`), so a ramp, spike, or a fat-fingered profile can
  only ever shape traffic *up to* `--rate`, never above it. `--discover-knee`
  ramps only toward the same ceiling and stops at the first SLO breach, so it does
  not blindly escalate load past the breaking point.

## [0.3.0] — 2026-07-11

Phase 5: response classification, SLO verdict, and the inline health-watchdog.

### Added

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

- The watchdog is **fail-safe by construction**: it can only ever *stop* traffic
  (via the existing `KillSwitch` that every engine already polls) and has no path
  to generate any. It does not touch the `AuthorizedTarget` invariant, so the
  authorization gate is unchanged. A lull (a window with zero attempts) resets
  the breach streak rather than counting as a breach, and the worst-case
  time-to-abort is bounded by `window * breaches` of *sustained* breach so a
  transient spike cannot abort a legitimate run.

## [0.2.0] — 2026-07-09

Phase 2 (continued): non-GET request primitives and slow-connection engines.

### Added

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
- Slow mode is **http-only** in this release: an `https` URL is refused
  fail-closed (dribbling raw bytes through a TLS session is not implemented yet).

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

[Unreleased]: https://github.com/h4b00b/jinrai/compare/v0.17.0...HEAD
[0.17.0]: https://github.com/h4b00b/jinrai/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/h4b00b/jinrai/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/h4b00b/jinrai/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/h4b00b/jinrai/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/h4b00b/jinrai/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/h4b00b/jinrai/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/h4b00b/jinrai/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/h4b00b/jinrai/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/h4b00b/jinrai/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/h4b00b/jinrai/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/h4b00b/jinrai/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/h4b00b/jinrai/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/h4b00b/jinrai/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/h4b00b/jinrai/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/h4b00b/jinrai/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/h4b00b/jinrai/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/h4b00b/jinrai/releases/tag/v0.1.0

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

### Documentation

- **"jinrai 101" opening section in the README.** Operator feedback: the README
  documented every flag but never answered the first question an operator
  actually has — *which test do I launch, and what does it tell me?* The
  reference material described each primitive one at a time, in the order it was
  built, so choosing between `slowloris`, `--max-connections` and `l4-mode tcp`
  meant reading all three and inferring that they pressure the same resource.
  The new section leads the README with the five decisions every run is made of,
  a layer-choice rule of thumb (start at L7), and a catalogue **indexed by the
  resource under pressure** — throughput capacity, concurrency limits, handshake
  cost, HTTP/2 protocol asymmetry, packet volume, stateful-middlebox handling —
  rather than by primitive name. It ends with four runs to do in order, guidance
  on picking `--rate`/concurrency safely, and an explicit statement of what the
  tool will not do (no spoofing, no reflection/amplification, no forged ICMP).
  Also fixed a stale line that still called `h2-rapid-reset` and
  `h2-continuation` "the two HTTP/2 primitives" — there are now nine.

## [0.23.0] — 2026-07-30

Operator-feedback release. A technician ran `tcp-connect-flood` against a lab
target at `--rate 10000` and got the same answer six times over, across two
`--concurrency` settings and three durations: **~320 attempts/s, "3% of the
10000/s cap", zero failures.** The number that moved between runs was not the
concurrency setting — it was the target's round-trip time. The flood was
measuring network latency, and the runs said nothing about the target's capacity.

### Fixed

- **The TCP connect flood no longer runs one handshake at a time.** The send loop
  called a blocking `connect_timeout` inline, so attempt N+1 could not start until
  attempt N resolved and the achievable rate was pinned to `1 / RTT` — about
  330/s against a 3 ms target, regardless of `--rate`. `--rate` was
  unreachable by construction at any setting above that, and the reported
  "% of cap" was a property of jinrai, not of the target. Handshakes now run on a
  pool of worker threads sized from `--concurrency`, so the ceiling is
  `--concurrency / RTT` and the rate cap is the binding constraint again.
  Measured against a lab blackhole at a 250 ms attempt cost: **24 → 1539 attempts**
  in 6 s at `--concurrency 64`, i.e. the full 64× the parallelism allows. Against
  a real listener: 70,882 completed handshakes in 5 s (14,128/s) with no failures.
- **Evicted connections are closed abortively (`SO_LINGER 0`, RST not FIN).** A
  graceful close made jinrai the active closer, parking every ephemeral port in
  `TIME_WAIT` for 60 s. That capped a *sustainable* connect flood at roughly 450/s
  from one source address — above it the default ~28k-port range is exhausted
  mid-run and the tool starts failing on `EADDRNOTAVAIL`, reporting a local limit
  as if it were a result. Fixing the concurrency bug without this would have hit
  the wall within seconds. A 70,882-connection run now leaves **0** sockets in
  `TIME_WAIT`. Steady-state pressure on the target is unchanged: it comes from the
  `--concurrency` connections held established, not from the closed ones.

### Changed

- **`--concurrency` now bounds sockets mid-handshake as well as established
  ones**, and so doubles as the connect flood's parallelism. The descriptor
  ceiling is the same number it always was — admission requires
  `held + in-flight < N`, so the local footprint still depends on `--concurrency`
  alone and never on `--duration` or `--rate`. The acceptance tests that pin the
  fd count to a plateau are unchanged and still pass.

### Added

- **The run summary explains a run that could not reach its rate cap.** A new
  `bound by` line applies Little's law — `concurrency / median-attempt` — and says
  so when that product lands below the cap:

  ```
   attempts   37877 total, 12621.1/s achieved (13% of the 100000/s cap)
   bound by   concurrency, not the target: 1 in flight at a 20us median
              attempt tops out near 50000/s, below the 100000/s cap — raise
              --concurrency to offer more load
  ```

  Silent when the run got near its cap, when no latency was measured (the
  stateless floods), or when concurrency had the headroom and the shortfall is
  therefore a finding *about the target* — the case where blaming the knob would
  point the operator at the wrong thing.

## [0.22.0] — 2026-07-30

Operator-feedback release. A technician running the tool asked two questions the
tool could not answer: *"how do I run an HTTP/1.1 attack instead of HTTP/2?"* —
there was no way, and no indication of which version was in use — and *"the
end-of-run output on sent/errors isn't saying much, same for the audit output"*.

### Added

- **`--http-version <auto|1.1|2>`** for the fast `get`/`post`/`head` methods. The
  version was previously whatever the client negotiated, which for an `https`
  target means ALPN — so a run the operator read as HTTP/1.1 was silently tested
  over HTTP/2 whenever the server offered it, a materially different test
  (multiplexed streams, HPACK, different server-side limits). `1.1` forces
  HTTP/1.1; `2` forces HTTP/2 (ALPN `h2` only for https, prior-knowledge h2c for
  http) and deliberately does **not** fall back, so a target that cannot do h2
  fails loudly instead of downgrading into a hollow pass. Warns and is ignored for
  the slow modes (HTTP/1.1 by construction) and the `h2-*` methods (HTTP/2 by
  construction).
- **The negotiated HTTP version is reported** per run — `RunReport.http_versions`,
  rendered as `protocol HTTP/1.1 5994` in the summary and `proto(...)` in the line
  form. Recorded even for `auto`: it is the only way to see that an "HTTP/1.1" run
  against an https target actually ran over h2.
- **Readable end-of-run summary** (`--output human`, now the default) replacing the
  single line as the operator-facing report: offered vs. **achieved** load
  (`6000 total, 199.4/s achieved (100% of the 200/s cap)`), status classes and
  protocol with percentages, latency in ms/s rather than raw microseconds, a
  plain-language `outcome` line that names *who* ended the run (completion /
  operator Ctrl-C / SLO watchdog / capacity knee), and an explicit warning when a
  run completed nothing. `--output line` keeps the historical machine-friendly
  line for scripts.
- **L7 failures are now bucketed by cause**, as the L3/L4 layer already was:
  `ECONNREFUSED` / `timeout` / `EMFILE` / … plus a new `ErrnoBucket::Protocol` for
  failures above the socket (typically a forced `--http-version` the target does
  not speak). Previously every L7 transport failure was an anonymous increment in
  `errors=<n>`, which is the same number for "the target refused us", "nobody
  answered", and "we ran out of local descriptors".
- **`--verify-audit` now prints the log it verifies**, one readable line per
  record (`#seq  timestamp  operator  AUTHORIZED/COMPLETED/REFUSED  …`) instead of
  only asserting that the hash chain adds up. Each record gained a human `summary`
  field plus structured `attempts`, `errno` and `http_versions` fields; the summary
  lives inside the hashed body, so it cannot be edited to disagree with the numbers
  beside it. Records written before 0.22.0 verify as before and display their raw
  body.

### Fixed

- **An L7 run that completed nothing now exits non-zero.** `units_sent == 0` with
  only failures means the target was never reached and nothing was stress-tested;
  the L3/L4 path already refused to call that a success, while L7 reported exit 0.
  A `--http-version 2` run against an HTTP/1.1-only target is the case that
  surfaced it.

### Changed

- `ErrnoBucket::from_io_error` moved into `core` (from a private helper in `l34`)
  so both traffic layers bucket the same OS failure identically.

## [0.21.0] — 2026-07-30

L4 (fix): the `tcp-connect-flood` had no completion path. Every `TcpStream` was
pushed into a `Vec` that lived for the whole run, so no descriptor was ever
closed, the in-flight count grew as `rate × duration`, and the run's local
footprint was a function of how long it ran. Measured: fd count rising
monotonically 3 → 1899 over a 10s run at rate 200 with **zero** closes; under a
default `ulimit -n 1024` exactly 1021 connects succeeded and every later attempt
failed, reported only as an anonymous `errors=957`.

### Fixed

- **Connection completion + bounded footprint.** Each attempt now awaits handshake
  resolution, records its outcome, and the held set is a **bounded FIFO** capped by
  the new `--concurrency`: eviction happens *before* the next connect, so the open
  descriptor count never exceeds the cap even momentarily. Resource usage is now
  independent of `--duration` — verified at 5s/10s/20s, peak fd identical.
- **Latency is actually measured.** The handshake is timed from attempt initiation
  to resolution and fed to an `hdrhistogram`, so `latency_us(p50/p90/p99/max)` is
  populated instead of reporting all-zero after thousands of successful connects.
  (`connect_timeout` is blocking and returns only once the handshake has resolved,
  so there is no `EINPROGRESS` to mis-measure.)
- The `data` flood's connection pool is now sized by `--concurrency` too, replacing
  a hard-coded `MAX_DATA_CONNS = 128`.

### Added

- **`--concurrency <N>`** (default 256) — the ceiling on simultaneously open
  sockets for the connection-holding L4 modes (`tcp`, `data`). Makes the three
  knobs orthogonal: `--rate` is offered load, `--concurrency` is the local
  footprint, `--duration` is wall-clock length only. A cap of `0` clamps to `1`
  rather than silently disabling the mode.
- **`--connect-timeout-ms <MS>`** (default 500) — previously hard-coded.
- **Per-errno failure breakdown** in the summary line, e.g.
  `errno(EMFILE=1964 ECONNREFUSED=3 timeout=1)`, via `ErrnoBucket` / `ErrnoTally`
  in `core`. A bare `errors=<n>` is the same number for four causes with four
  different fixes: `EMFILE`/`ENFILE`/`ENOBUFS`/`EADDRNOTAVAIL` are *local* limits
  on the host running jinrai, while `ECONNREFUSED`/`ETIMEDOUT`/`ECONNRESET` are the
  target rejecting traffic. Our own expired `--connect-timeout-ms` gets a `timeout`
  bucket distinct from the kernel's `ETIMEDOUT`; anything unrecognised keeps its
  raw code as `os:<code>`, so no failure is ever an anonymous increment.
- **`RLIMIT_NOFILE` raised at startup** (soft → hard) with the resulting ceiling
  logged as `fd ceiling: <n> (hard limit <n>)`. A shell's `ulimit -n` is
  shell-local and absent under systemd or cron, so descriptor headroom must not
  depend on how the run was launched. This is headroom, **not** a fix — the cap is
  what bounds the footprint, and `errno(EMFILE=…)` now says so out loud rather than
  letting a local limit masquerade as target behaviour.
- `scripts/lab_listener.py` + `scripts/verify_criteria.sh` —  reproduce the
  fd-footprint, latency, errno and pacing measurements against a local listener.

### Notes

- **The pacer was left alone, deliberately.** The reported 2–10% shortfall in
  `sent` was a *consequence* of the leak (the missing units were EMFILE failures),
  not independent drift: with the footprint bounded, attempts land at 100.0% /
  100.0% / 99.8% / 99.4% / 99.2% of `rate × duration` at rates 50 / 100 / 200 /
  400 / 800 per second. The loop already schedules on absolute deadlines
  (`next += interval`). At 1600/s it reaches 94.4%, the floor set by
  `thread::sleep` granularity against a 625µs period — and closing that last gap
  would require bursting to repay accumulated debt, which `RateCap` exists to
  forbid. Honouring the rate ceiling is worth a few percent at extreme rates.
- No change to allowlist enforcement or the `--ack-l34-lab` gate.

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

[Unreleased]: https://github.com/h4b00b/jinrai/compare/v0.23.0...HEAD
[0.23.0]: https://github.com/h4b00b/jinrai/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/h4b00b/jinrai/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/h4b00b/jinrai/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/h4b00b/jinrai/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/h4b00b/jinrai/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/h4b00b/jinrai/compare/v0.17.0...v0.18.0
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

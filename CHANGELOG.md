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

- **`docs/playbook.md`** — one test-plan row per section, each with the ready
  command and a table explaining **every switch in it**, plus what lands on the
  wire and how to read the result. Covers the whole use-case list (L3/L4 1–19,
  L7 20–36, capacity 37–40), what is out of scope and why, the colour key of the
  run summary, audit-log verification, and the reason a run can report
  `50000 completed (100%), failed 0` while reaching nothing: a stateful device on
  the path drops the eleven out-of-state modes after the local `sendto()` has
  already succeeded, which the summary cannot see. Addresses in the examples are
  placeholders, not any real environment.

## [0.44.0] — 2026-08-04

Four ways the run summary answered a question with the wrong number, or with a
number that could not be acted on. All four came out of one real POST run against
a login endpoint: `2xx 875 / 4xx 121`, four `internal` failures, and a body the
target never parsed.

### Added

- **Exact status codes beside their classes** — `RunReport::status_codes`, an
  `of which 200 x875   429 x118   400 x3` row in the summary, `codes(...)` in the
  line form, and a `status_codes` object in the audit record. `4xx 121` is three
  opposite findings and the class could not tell them apart: a `400` says the
  request *jinrai* sent was malformed and the run measured nothing, a `401`/`403`
  is the target behaving normally, and a `429` is the rate limiter engaging —
  usually the result the run went looking for. `5xx` splits the same way (a `503`
  from a shedding balancer is not a `500` from a crashing handler). Ranked by
  count so the dominant code leads; silent for an all-`2xx` run, where it would
  only repeat the class row.

### Fixed

- **`--body` was sent with no `Content-Type`, and nothing said so.** The engine
  sends the bytes verbatim and adds no type of its own, which is the right
  behaviour — guessing `application/json` from a leading `{` would put a header
  on the wire the operator never wrote. But a target that cannot tell what the
  body *is* rejects it (`415`/`400`) or ignores it, so the parsing, validation
  and persistence cost the run was meant to measure is never paid, and the `4xx`
  that comes back reads as a finding about the target rather than a broken
  request. jinrai now **warns** when `--body` arrives without the header, naming
  the fix; `--help` and the playbook's POST case carry it too.
- **The `internal` errno bucket printed the packet-layer meaning on L7 runs.**
  `refused before the OS (structural mismatch, e.g. IPv6 vs IPv4-only)` describes
  a condition the L7 path cannot produce: it is decided at setup and refuses the
  whole run, never four requests out of a thousand. On L7 the same bucket means
  the opposite end of the stack — the socket worked and the HTTP stack itself
  failed the request with a synthetic `io::Error` carrying no errno, typically
  one in flight when the peer closed the connection under it (an HTTP/2 `GOAWAY`,
  a per-connection request limit, an idle reaper). The explanation is now chosen
  per layer, and says that a share which grows with `--rate` is the target's
  per-connection ceiling.
- **An L7 run was told to raise `--concurrency`** — a flag L7 warns about and
  then ignores, so the summary was giving advice the tool itself would refuse to
  take. Both the `not sent` row and the `bound by` note now name the ceiling flag
  of the layer that ran (`--max-connections` for L7, `--concurrency` for L3/L4).
- **The `not offered` row ran its label into its own value** — `not
  offered8855 attempts skipped` — in every release build. The label was 13
  characters for an 11-character column; the width guard below `row` is a
  `debug_assert`, and no test had ever rendered that row. It is `not sent` now,
  with the phrase moved into the value where it has room to be a sentence.

## [0.43.0] — 2026-08-04

Two ways a run measured the appliance in front of the target instead of the
target. Both produced the same unfalsifiable result: a status class in the
summary that the operator could not reproduce with a browser against the same
URL, and no line anywhere explaining the gap. A real run against a WAF-fronted
login endpoint reported `3xx 100%` while the WAF's own log showed `404` for the
same requests.

### Fixed

- **The fast `get`/`post`/`head` flood sent no `User-Agent` at all.** The engine
  built its header map from `--header` alone, and `reqwest` adds no UA of its
  own — so every request went out with the header absent. That is not the
  neutral request it looks like: WAFs, CDNs and bot filters answer a headerless
  request differently from the same request carrying *any* UA, typically with a
  challenge or a redirect. The run then measured the filter's opinion of an
  unusual client, and reported it as the target's behaviour. Requests now carry
  `User-Agent: jinrai/<version>` — the same identification the raw-socket
  engines (`slowloris`, `slowbody`, `slow-read`, `websocket`, `sse`) have always
  sent, now a single shared constant. `--header "User-Agent: ..."` overrides it,
  as before; the default is a default, not a policy, and the engine still ships
  no vendor-specific evasion of its own.

### Added

- **`--follow-redirects <N>`** (default `0`, max 10) — follow up to `N`
  **same-origin** redirect hops per request, so the status recorded is the one at
  the end of the chain rather than the `3xx` that started it. At `0` (unchanged
  behaviour) a target that answers `302` to a login page reports `3xx 100%`,
  while a browser would end on the `404` two hops later; the summary and the
  target's log then disagree about the same traffic.
- The flag **costs rate, and says so**: a followed hop is a second request
  `--rate` never counted, so `N` hops can put up to `(1 + N) x --rate`
  requests/sec on the target. The rate cap still bounds what jinrai *dispatches*;
  it no longer bounds what the target receives. Opt-in for that reason, capped at
  10 for the same one, and the run summary prints
  `following up to N same-origin redirects` — without it `attempts` would quietly
  stop meaning "requests the target saw".

### Security

- **The redirect control was narrowed to what it actually protects, not
  loosened.** `Policy::none()` existed because `resolve_to_addrs` pins one host:
  a `Location:` naming another origin would resolve through the system resolver
  to a host the gate never saw, carrying the operator's `--header` values with
  it. What that has to prevent is the client *moving*, not the client
  *following*. So at any `N > 0` the hop is taken only when the `Location:` still
  names the approved datum — same host, same port, same scheme — which the DNS
  pin already covers and the headers already belong to. Anything else stops the
  chain and reports the `3xx`, exactly as at `N = 0`. The peer cannot choose
  where the client connects at any setting of the flag, and a test asserts that
  with following turned up to 5.
- Off-origin redirects `stop()` rather than `error()`: "it left the authorized
  origin" is answered honestly by reporting the `3xx` that says so, not by
  turning the response into a transport failure the errno breakdown cannot
  explain.

## [0.42.0] — 2026-08-03

HTTP/3 and QUIC. Every technique jinrai had reached the target's TCP front door;
the UDP one had coverage of exactly zero. That gap is worth more than its size
suggests, because an HTTP/3 endpoint is usually a *different* code path behind a
*different* protocol, and the rate limits, connection caps and idle reapers that
protect port 443/TCP are frequently absent from port 443/UDP — a target can pass
every existing run and still have an unguarded front door.

### Added

- **`--l7-method quic-handshake`** — QUIC handshake flood. Complete a full
  handshake, drop it, repeat concurrently. The same CPU asymmetry
  `tls-handshake` measures, except QUIC moves the work *further forward*: the
  server decrypts an Initial, parses a ClientHello and signs with its private key
  for a client that has proved nothing beyond being able to receive one round
  trip. `--rate` counts handshakes/sec, `--max-connections` caps those in flight.
- **`--l7-method quicloris`** — QUICLORIS. Hold connections open, each carrying a
  proper HTTP/3 control stream with `SETTINGS` and one request stream whose
  `HEADERS` frame promises 4 KiB and delivers a byte per `--drip-ms`. Not just
  Slowloris again: an HTTP/1.1 Slowloris is retired by a request-header read
  timeout, and QUIC's equivalent budget is the **idle timeout** — which a
  dribbling connection never reaches. `--slow-connections` is the ceiling.
- Both are `https`-only (there is no plaintext QUIC), speak ALPN `h3`, and share
  the datum-authorization + resolve-once-and-pin boundary of every other L7
  engine.
- A third outcome in the summary, on the pattern the TLS-hello and WebSocket
  engines set: **refused** (the peer answered in QUIC and declined — almost
  always no `h3` ALPN, a finding about the endpoint rather than its capacity) is
  reported apart from **errors** (nothing came back at all). QUIC makes the
  distinction matter more than TCP does, because a dropped Initial produces no
  `ECONNREFUSED` and no `RST` — just silence.

### Security

- **No spoofing in the QUIC path either, and it is load-bearing.** QUIC is the
  protocol most easily turned into a reflector, and every amplification variant
  needs a forged Initial. jinrai binds an ordinary client UDP socket on `:0` and
  lets the OS assign the source; there is no source-address option anywhere in
  the module, which is enforced by a test asserting the bind address is
  unspecified with port 0. Because the source is real, RFC 9000's
  anti-amplification limit is satisfied rather than evaded — the server answers
  us. QUIC Retry / token-replay amplification and reflection via the certificate
  exchange stay out of scope by design.
- **A run that reaches nothing no longer reads as a clean sweep.** QUIC gives a
  silent target no way to fail fast, so every attempt against a filtered or dead
  UDP port is still handshaking when the window closes. Counting only *resolved*
  attempts reported such a run as `0 attempts, 0 failed, ran to completion` — the
  hollow success this project has fixed once before, in `l34`. Attempts are now
  counted at spawn and anything unresolved at the deadline is an error, so the
  run exits non-zero and says so.

### Fixed

- **A QUIC run no longer outlives its `--duration`.** Closing the endpoint waits
  out the draining period (three PTOs) per connection, which against a target
  that never answered added seconds to a two-second run — and an elapsed time
  that disagrees with the planned one makes every rate in the report a different
  number than it claims. The close is now bounded by a 500 ms grace.

### Dependencies

- **`quinn` 0.11** (`default-features = false`, `runtime-tokio` + `rustls-ring`)
  — the first primitive family that could not be hand-rolled the way the raw
  HTTP/2 framing and the TLS ClientHello bytes were. QUIC carries its handshake
  *inside* AEAD-protected packets, so reaching the server's crypto work at all
  means implementing header protection, packet-number spaces and loss recovery
  first. The supply-chain cost is smaller than the policy suggests: `reqwest`
  already declares these exact versions behind its unused `http3` feature, so
  they were resolved and reviewed in `Cargo.lock` before this release; quinn
  drives the same `rustls` 0.23 and `ring` provider the crate already uses, so
  no second TLS stack and no second crypto backend enter the tree. Default
  features are off, which keeps out `platform-verifier` — an entire OS
  trust-store stack, useless to an engine that accepts any certificate by design.
  Net effect on the build graph: 13 crates, 127 → 140.
- **`rcgen` 0.13, dev-only.** Nothing observes a QUIC stream without completing a
  handshake first, so verifying that jinrai's HTTP/3 bytes actually arrive means
  standing up a real QUIC listener in the tests, and that means a certificate. It
  never reaches the shipped binary.

### Verified

- Against a real QUIC listener, in-test: handshakes complete and report zero
  errors; an `h3`-less listener lands in **refused** rather than errors; and a
  QUICLORIS run delivers a byte-exact HTTP/3 control stream and a `HEADERS` frame
  that is still unfinished when the run ends, with the request stream never
  finished. Plus RFC 9000 varint encoding at all three form boundaries.
- End to end through the CLI: both methods run, the scheme and gate refusals exit
  non-zero, and a run against a dead UDP port reports `40 attempts, 40 failed`
  and exits 1.

## [0.41.0] — 2026-08-03

Colour in the run summary. The block already said everything an operator needs;
what it did not do was let them find it. `completed`, `failed`, `2xx`, `5xx`,
`ABORTED` and `ran to completion` all arrive as the same grey text, so the one
number that decides whether the test passed has to be located by reading the
labels — which is exactly what a tester at the end of a run does not do.

### Added

- **`--color <auto|always|never>`** (default `auto`). `auto` paints only when
  stdout is a terminal, `$NO_COLOR` is unset and `$TERM` is not `dumb`, so a
  redirected or piped report is byte-for-byte the plain block it has always been.
- Three senses, not a palette: **green** = the run did what it set out to do
  (`completed > 0`, `failed 0`, `2xx`, `SLO: PASS`, `ran to completion`),
  **yellow** = a caveat about *our* side (`bound by`, `not offered`, the local
  errno ceilings, an operator abort, `4xx`), **red** = failure and the target's
  own errors (`failed`, `5xx`, a remote errno, `SLO: FAIL`, a watchdog abort,
  the hollow-run `WARNING`). Anything finer would be decoration.
- `Palette` in `jinrai-metrics`, taken by `render_summary` as a parameter rather
  than sniffed from the environment inside it: the same report is read on a
  terminal and written to a file, and only the caller knows which.

### Changed

- **A completion count of zero is red, and a hollow run's outcome is yellow.**
  `completed` is not a green row by name — `0 (0.0%)` is the worst line the block
  can print, and "ran to completion" above a red `WARNING` would be the
  confidently-wrong green this whole block exists to prevent. An empty status
  class stays plain for the same reason in reverse: painting `5xx 0 (0.0%)` red
  puts alarm on the healthiest possible line.
- The one-line `--output line` form is untouched. It is the scriptable one, and a
  stable line is worth more there than a readable one.

### Verified

Colour cannot move a line break: the wrapper measures visible width with escapes
skipped, and a test asserts the painted and plain blocks have identical line
counts *and* identical per-line widths over a report that wraps in four places.
A second test asserts the plain palette emits no escape byte at all. Live
loopback runs confirm both readings — a clean UDP flood (green completions,
green `failed 0`) and a refused TCP connect flood (red `0 (0.0%)`, red
`ECONNREFUSED`, yellow outcome, red `WARNING`). Suite 309 green, clippy clean.

## [0.40.0] — 2026-08-03

IP fragmentation and GRE. Every primitive jinrai had so far put **one packet** on
the wire per unit and let the target read it as-is. These three do not: two of
them cut a datagram into pieces the target has to hold and rebuild before it can
read anything, and one wraps a whole packet inside another. What they exercise is
the IP layer itself — the reassembly table and the protocol demultiplexer — which
is why they report as L3 even though the bytes inside are a UDP datagram or a SYN.

### Added

- **`--l4-mode udp-frag` and `--l4-mode tcp-frag`** — IPv4 fragmentation floods.
  The cut is deliberate rather than an MTU accident: the datagram is split on
  8-byte boundaries *inside its transport header*, so `udp-frag` puts the 8-byte
  UDP header in fragment 0 and the payload in fragment 1 (the destination port is
  unreadable until both land), and `tcp-frag` fragments a SYN whose 20-byte header
  cuts into 8 + 8 + 4 — ports in fragment 0, **control flags in fragment 1**, so
  nothing on the path can tell it is a SYN without reassembling first. Each unit
  carries its own IP identification, so reassembly entries accumulate instead of
  overwriting one another. Works with the existing `--port` sets, which is where
  the fragmentation + random-ports shape comes from: add `--port-order random`.
- **`--l4-mode gre`** — a GRE flood (IP protocol 47): an outer IPv4 header, the
  4-byte version-0 GRE header (RFC 2784, no checksum/key/sequence), and an
  encapsulated IPv4/UDP datagram. A target that accepts protocol 47 must
  recognise it, strip the outer header and re-enter its IP stack with the inner
  packet — roughly two packets' worth of processing for one packet of bandwidth.
  `--port` sets the encapsulated destination port.
- All three are raw-socket modes: `CAP_NET_RAW`/root, IPv4-only, real source
  address, and covered by the existing per-vector preflight — so a missing
  capability is refused before any traffic, including inside a multi-vector run.
- `route_source`, `require_ipv4` and `varying_source_port` in the L3/L4 engine:
  the three steps every packet-crafting mode already performed, now performed in
  one place each rather than copied per sender.

### Security

- **The GRE builder cannot write a source address it was not given — inside the
  encapsulation either.** A GRE payload is the one place an IP source could be
  set where no kernel would ever validate it, which would be a spoofing path in a
  tool whose central guarantee is that it has none. The encapsulated datagram is
  therefore addressed from the same real source as the outer packet, and the
  builder has no argument with which to express anything else.
- Fragmentation changes what a packet is cut into, never who it claims to be
  from. Every fragment carries the route-local address from `source_ipv4_for`,
  the single producer it has always come from, and a test asserts this over the
  whole fragment set of both modes.
- **`--rate` counts datagrams, and the summary says what that costs.** One
  `udp-frag` unit is 2 packets on the wire, one `tcp-frag` unit is 3. Counting
  the datagram is the honest measure of offered load — it is the thing the target
  reassembles — but it is 2–3× short of the packet count, so the report states
  the multiplier rather than leaving `units_sent` to be read as packets. The
  fragment count lives as a constant next to the mode and is held to the builder's
  actual output by a test, across every payload size a run can ask for.
- A `udp-frag` payload is floored at 8 bytes. Below one byte there is nothing
  past the UDP header to cut off, so the run would emit ordinary unfragmented
  datagrams while reporting a fragmentation flood — the hollow-run shape 0.36.0
  spent a release removing.
- The GRE payload is capped so the whole packet still fits the same MTU budget
  the other modes keep to. A GRE packet the *local* kernel had to fragment on its
  way out would be measuring our MTU, not the target's decapsulation path.

## [0.39.0] — 2026-08-03

Multi-vector L3/L4 runs. The primitives were all there; what was missing was
running them **at the same time**, which is how a test plan asks for them
("UDP MultiVector", "UDP/TCP/ICMP Multivectors"). So `--l4-mode` became
repeatable, and nothing else had to be invented.

### Added

- **`--l4-mode` is repeatable.** Each occurrence adds a vector; they run
  concurrently against the same targets, one thread each. A thread per vector
  rather than one interleaved loop because each primitive already owns blocking
  state — a connect pool, a raw socket, a data-flood connection table — and
  interleaving them would let the slowest (a `data` write blocking on a full
  buffer) set the pace for the packet floods beside it, which is the opposite of
  what running them together is supposed to show.
- They share everything that bounds a run: one `--duration`, one kill-switch
  (Ctrl-C and the watchdog stop all of them), one audit record, one summary.
- Mixing ICMP with a port mode is allowed; `--port` is then still required, for
  the vectors that address one. An all-ICMP run reports as L3, a mixed run as L4
  — calling a run that floods a port "L3" because one vector is ICMP would
  understate it.
- `RateCap::split_across(n)` and `ErrnoTally::absorb` in `core`.

### Security

- **The `--rate` ceiling is shared between vectors, not applied per vector.**
  Three vectors at `--rate 6000` emit 2000/s *each*. The alternative would make
  `--rate` mean `--rate` × the vector count, so the number the operator typed,
  acknowledged with `--ack-lab`, and had written to the audit log would be a
  fraction of the traffic actually sent — and a safety ceiling that multiplies
  behind the operator's back is not a ceiling. The split's shares sum to the cap
  exactly (the remainder is spread one unit at a time, never rounded up), which
  is asserted over a grid of rates and vector counts.
- A `--rate` too small to split (fewer units/s than vectors) is **refused**
  rather than rounding a vector to 0/s. A vector the operator asked for that runs
  and sends nothing is the hollow-run shape 0.36.0 spent a release removing.
  `--rate 0` stays the deliberate whole-run no-op it always was.
- **Preflight checks every vector, not just the leading one.** A multi-vector run
  that preflighted only its first mode would pass, start, and then fail every raw
  packet — partial success reported for a `CAP_NET_RAW` problem the operator
  could have been told about before any traffic. Same for the IPv6 refusal: one
  IPv6-incapable vector refuses the run, because a run that quietly drops a
  vector is not the run that was described.
- Repeating the same mode is refused: two identical vectors are one vector at the
  same total rate, so it is always a typo.

### Changed

- `L34Config.mode: L4Mode` became `modes: Vec<L4Mode>`; `L34Engine::run` is now a
  dispatcher over a per-vector `run_vector`, so the single-vector path is
  byte-for-byte the loop it always was.
- The summary reports the total **and** a per-vector breakdown through the
  existing `of which` row — one total cannot tell "both vectors landed" from "one
  did all the work". The notes line says how many vectors share the ceiling, so a
  per-vector count does not read as a shortfall against the full `--rate`.
- The `bound by concurrency` note is single-vector only: it describes one pool
  pacing one send loop, and applying it to a run whose other vectors are packet
  floods would blame a ceiling that never touched them.
- Run label and audit records name the vector list
  (`multi-vector [udp-flood + tcp-connect-flood]`).

**This is not Phase 8.** Declarative scenario files and multi-*source*
orchestration are still open; this is the multi-vector shape, which turned out
not to need either.

### Verified

Live on loopback with a UDP and a TCP listener counting what actually arrived.
Single vector, `--rate 2000` for 3s: 6000 datagrams. Two vectors, same ceiling:
**6000 total, split exactly 3000 UDP / 3000 TCP** — the shared ceiling holds on
the wire, and an unshared one would have landed near 12 000. A three-vector dry
run (udp + tcp + data) over a random port range across two targets prints the
whole plan. Suite 297 green, clippy clean.

## [0.38.0] — 2026-08-03

The L7 counterpart to 0.37.0's port sets. The fast flood sent one identical
request N times, which measures a single endpoint's ceiling and is the wrong
shape for four floods asked for by name. All four are the same missing
primitive: vary the request per unit.

### Added

- **`--random-path`** — a fresh random segment appended to the URL path, so every
  request asks for a URI that does not exist. The random-path flood: nothing is
  cacheable, and the origin generates (and usually logs) all of it.
- **`--path-file <PATH>`** — draw the path from a list of endpoints that *do*
  exist, one per line, `#` comments and blank lines skipped. The valid-random
  flood: load lands on real handlers rather than the 404 path.
- **`--search-param <NAME>`** — a fresh random term as `NAME=<term>` per request.
  The search-field flood, and the one query a cache can never serve. Query for
  `get`/`head`, form-encoded body (with the matching `Content-Type`) for `post`,
  where it replaces `--body`. The term is a pronounceable lowercase word, not a
  hex blob: a hex blob is equally uncacheable, but a term that looks like a term
  reaches the same code path a real query does.
- **`--session-cookie <NAME>`** — a distinct, unrecognised `NAME=<value>` cookie
  per request, so the target allocates or looks up session state for each one
  instead of reusing a single session for the whole run. Session exhaustion.
- New `l7::vary` module (`Variation`, `PathMode`), and the shaping applies to the
  fast `get`/`post`/`head` flood only. The other l7 methods build their own
  requests or raw frames, so a shaping flag there is now **warned about** rather
  than silently ignored — `--cache-bust` included, which had been the quiet
  exception since it was added.

### Security

- **A `--path-file` entry that would move the run to another origin refuses the
  run.** This is the one variation that could send authorized-looking load past
  the gate, so it gets two gates: a syntax rule at load time (an entry must start
  with a single `/`) that names the offending line, and — because syntax is the
  wrong thing to trust when URL joining has its own normalisation rules for
  backslashes and protocol-relative forms — a check of the *joined result*
  against the authorized origin, run once at setup before any request exists. An
  offending entry is never silently skipped: skipping means the operator's list
  ran differently than it reads. New `L7Error::BadPathList`, classified as a
  `Refused` (a policy event), not a `Setup` failure.
- Everything else touches the path, query, body and cookie **only**. The host is
  never altered, so the datum authorization and the pinned DNS resolution hold
  for every request of the run — for generated paths by construction, since
  `path_segments_mut`/`query_pairs_mut` cannot reach the host.

### Changed

- The run summary and `--dry-run` both name what varied (`varying: random path,
  fresh session`), so a run with a 100% 4xx rate reads as the random-path flood
  it was rather than as a target problem. `dry_run_summary` now takes a
  `(label, value)` detail line — the port set for l3/l4, the variation for l7.
- `RequestSpec.cache_bust: bool` became `RequestSpec.variation: Variation`.
- Contradictions are refused rather than resolved: `--random-path` with
  `--path-file` (both decide the path), `--body` with `--search-param` (both
  decide the POST body), and an empty name for either `--search-param` or
  `--session-cookie`. A `--path-file` that cannot be read fails at argument-parse
  time, before the lab acknowledgement and the audit record.

No new dependency. Tokens are a splitmix64 hash of `(per-run seed, unit counter)`
rather than draws from a shared generator — at the rates this engine dispatches
at, a locked RNG on the request path would be the run's own bottleneck. Distinct
salts per field so the path, the list index, the term and the cookie of one unit
are not the same value wearing four hats. The per-run seed means two runs do not
replay each other's URIs, so a cache warmed by the first cannot absorb the
second.

### Verified

Live against a recording HTTP server, 400 requests per run: baseline 1 distinct
path/query/cookie/body (unchanged); `--random-path` **400 distinct paths**;
`--path-file` drew exactly its 3 entries, splitting `/app/d?x=1` into path and
query correctly; `--search-param` **400 distinct queries** (GET) and **400
distinct bodies** (POST); `--session-cookie` **400 distinct cookies**; all four
together compose. A list entry on another origin refused the run with exit 1
naming the line. Suite 292 green, clippy clean.

## [0.37.0] — 2026-08-03

Destination ports become a **set**. Every release until now sent a whole L3/L4
run to exactly one port, which is right for a single-service test and wrong for
the two shapes a test plan asks for by name — random-port floods and carpet
bombing. Both are the same missing primitive: a set of ports, and a rule for
picking one per packet.

### Added

- **`--port` takes a spec, not a number.** A single port (`443`), a comma list
  (`80,443,8080`), an inclusive range (`1000-2000`), or a mix (`80,8000-8100`).
  Held as ranges rather than an expanded list, so `1-65535` is a legitimate spec
  that costs two integers. Port 0 is still refused, everywhere it can appear in a
  spec.
- **`--port-order <sequential|random>`.** `sequential` (the default) walks the set
  in the order written, advancing once per pass over the targets so a multi-target
  run enumerates the whole target x port cross-product — advancing per *unit*
  instead would lock each target to its own port whenever the target and port
  counts share a factor, which is the opposite of what a carpet-bombing run is
  asked to produce. `random` draws a port per packet: consecutive packets are
  unrelated, so a rule keyed on one port sees a trickle rather than the run.
  A single-port run is byte-for-byte what it was before either flag existed.
- **Carpet bombing** now falls out of the two flags together: `--target` was
  already repeatable, so several destination addresses x a port range is one
  command line. Documented in the README with both the UDP and the raw-SYN shape.

The draw uses a hand-rolled xorshift64\* seeded from the clock, not a new
dependency — the requirement is "spread the load over the range", not
unpredictability, and nothing security-relevant rests on the sequence. `below()`
uses Lemire multiply-shift so the low ports of a range are not favoured by modulo
bias.

**The guardrail is unchanged and this is deliberate:** only the *destination*
port varies. The source address is never spoofed and the source port stays
deterministic. Source-port randomisation is the neighbouring move that makes
flows unattributable, and it is absent for the same reason source-IP spoofing is.

### Changed

- The run label and both audit records name the set (`ports 1000-2000 (random)`)
  rather than a single port. The pre-traffic `RunAuthorized` record carries it
  too — a run may now span a whole range, so "which primitive ran" is not fully
  answered without it, and that record is the only one a refused or aborted run
  leaves behind.
- `--port-order` is listed among the flags an `--layer l7` run warns about as
  not-applicable, alongside `--port`.

### Verified

Loopback run, 50 UDP sockets bound across `31000-31049`, `--port-order random`
at 2000/s for 3s: **all 50 ports received traffic**, 6000 datagrams observed,
94–144 per port against an expected 120 — the spread is real on the wire, not
just in the picker. Unit tests cover both orders' coverage of their set, spec
rejection (`0`, `80,0`, `100-80`, `80,,443`, `70000`, ...), and the full
`1-65535` range. Suite 277 green, clippy clean.

## [0.36.0] — 2026-08-03

Code-review remediation. No new primitives — this release is about the run
reporting what actually happened.

Three of these are the same failure in different clothes: the tool drew a
confident conclusion from a run that had not earned it. A ramp that skipped its
own silent stages reported a shape it never ran; a discovery run that reached
nothing printed "the target held the full ramp"; a saturated pool dropped
attempts that appeared in no counter, so "the target absorbed everything" and "we
never offered it" printed identically.

### Fixed

- **A zero-rate load stage is silent, not absent (L7).** The engine filtered
  stages with `rate == 0` out of the compiled profile, which is exactly the
  regression `RateCap`'s own documentation describes: `--ramp-start 0
  --duration 60` with 10 steps finished early and reached every later rate ahead
  of schedule, so the shape in the summary was not the shape that ran. The
  silent-stage handler further down the same function had been dead code since.
  Only zero-*duration* stages are dropped now, and a regression test asserts the
  wall time of a ramp whose first three stages truncate to rate 0.
- **Knee discovery no longer reports a hollow run as success.** The
  `--discover-knee` path returned `Ok(())` unconditionally, bypassing the
  check that every other L7 run goes through. Against an unreachable target it
  printed "no breaking point found: target held the full ramp" and exited 0 — the
  confidently-wrong green that `a_run_that_tested_nothing_is_a_failure` exists to
  prevent. The check now runs *before* the conclusion is printed.
- **`--l4-mode data` is abortable again.** Connections were opened with a
  blocking `TcpStream::connect_timeout` on the pacing thread, and the kill switch
  is only polled between units — so `--connect-timeout-ms 60000` meant Ctrl-C was
  ignored for up to a minute, in a crate that documents a 250 ms abort bound. The
  connect now runs on its own thread and is waited on in kill-poll slices;
  aborting detaches it and reports the attempt as `abandoned` rather than
  pretending it never happened.
- **A data-flood connection that dies on its priming write is no longer counted
  as sent.** `write_pshack`'s result was discarded, so a connection the target
  reset immediately still entered the pool — a dead descriptor occupying a slot
  the pool would then never refill, because `conns.len()` said it was full.
- **In-run memory no longer grows with `rate × duration` (L7).** Three engines
  (`fast`, `tls-handshake`, `tls-*-hello`) spawned a task per tick but joined the
  `JoinSet` only after the run loop. Tokio retains a completed task's output until
  it is joined, so the concurrency semaphore bounded what was *in flight* and
  nothing bounded what had finished. Finished tasks are now reaped each tick.
- **`--allow ::ffff:10.0.0.1` is refused like its CIDR spelling.** The bare-IP
  path built a `/128` rule that `contains` always refuses, while the equivalent
  `--allow ::ffff:10.0.0.1/128` was rejected loudly. Fail-closed either way, but
  only one of them told the operator that the rule they wrote authorizes nothing.

### Security

- **The audit log verifies its whole chain at `open`, not just its tail.**
  Recomputing only the last record left the same hole one line further up: a
  record edited in the *middle* of the file, with an intact last line, opened
  cleanly and got honest records chained onto poisoned history — discoverable
  only if somebody later happened to run `--verify-audit`. Finding the end of the
  file already reads every line, so full verification costs one SHA-256 per
  record. (Baseline item 5.)
- **`--l4-mode data` has a hard connection ceiling.** The pool was bounded by
  `--concurrency` and, past that, by the process descriptor limit; there was no
  in-crate equivalent of `MAX_CONNECT_WORKERS`. "The OS will stop us" is not a
  limit this crate gets to rely on, and the failure it allowed — EMFILE part-way
  through a run — measures our own box rather than the target. (Baseline item 2.)
- **`Cidr` is sealed.** It was a public enum with public fields, so
  `Cidr::V4 { network, prefix: 200 }` — a block matching by a mask the parser
  would never produce — was an ordinary safe expression in the crate whose stated
  job is that invalid states are unrepresentable. Now a newtype over a private
  representation, like `DnsRule`. (Baseline item 7.)
- **An unevaluatable SLO is reported as such, instead of silently failing the
  target.** `SloSpec::validate` existed but nothing called it, so a library caller
  with `max_error_rate: Some(-0.5)` got a threshold every possible observation
  exceeds: a healthy target "FAILED" and the summary named a breach that never
  happened. Out-of-range thresholds now surface as
  `SloBreach::InvalidThreshold`, which blames the spec rather than the target.
  (Baseline item 7.)
- **Contradictory and meaningless flags are refused rather than reinterpreted.**
  `--no-audit` together with `--audit-log` (opposite instructions about whether
  the run is on the record — the log used to win silently); `--port 0`, which the
  packet builder rewrote to port 1; `--concurrency 0`, clamped to 1 downstream.
  `--watchdog-window` and `--watchdog-breaches` now go through `parse_capped`
  like every other numeric flag.
- **One pre-traffic refusal was unaudited.** `--discover-knee` without a rate SLO
  returned a bare error while the audit log was already open, so the refusal left
  no record. It is audited like every other refusal now.

### Added

- **`not offered` in the run summary.** Attempts the generator declined to make
  because its own in-flight budget was saturated — L34's pool backpressure and
  L7's concurrency-capped ticks — were counted nowhere: no `sent`, no `error`, no
  disclosure. Deliberately kept out of `attempts()` so it cannot drag an SLO rate:
  these are our shortfall, not the target's failures. But a non-zero count says
  the binding constraint was on this side of the wire, which is the difference
  between a result and a measurement of our own box.

### Notes

- `jinrai-safety`'s manifest advertised "rate caps", which live in `jinrai-core`.
  Corrected — a reader auditing where the ceilings are enforced should not be sent
  to the one crate that has none.

## [0.35.0] — 2026-08-03

The work a TLS server does **before** it has decided to trust you.

`tls-handshake` (0.11.0) measures the crypto asymmetry: a full handshake costs
the server a signature and costs the client almost nothing. But a handshake only
starts after the ClientHello has been buffered, parsed, and had its cipher list
intersected and its extensions walked — all on bytes from an unauthenticated
peer, in code that runs before any policy the operator configured. That path had
no coverage at all.

### Added

- **`--l7-method tls-big-hello`** — one well-formed ClientHello inflated to the
  edge of the 16 KiB record limit: a 2048-entry cipher-suite list of unassigned
  code points (the server must intersect all of them against its own and come up
  empty) plus RFC 7685 `padding` to fill the record. Verified against OpenSSL:
  the hello is well-formed enough that a real TLS stack parses the whole thing
  and proceeds — which is the point. A malformed one would be rejected on the
  record header, and the run would report a finding about jinrai.
- **`--l7-method tls-sni-bomb`** — the same connection spent on the SNI alone: a
  ~12 KiB `server_name` built from legal ≤63-byte DNS labels, so it survives
  syntax validation and reaches the virtual-host lookup rather than being thrown
  out as a malformed name. (OpenSSL refuses it in
  `tls_parse_ctos_server_name` — the exact code path the primitive exists to
  reach, and the healthy outcome.)
- Both are `https`-only, rate-capped as hellos/sec and bounded by
  `--max-connections`, and neither completes a handshake: connect, write one
  record, read the first byte of the answer, drop.
- **The answer split is the result, and it is now on screen.** Three outcomes
  are counted apart because they are three verdicts on the target's parser:
  *parsed* (the server did the work), *refused with an alert* (the parser held —
  measure how cheaply), *silent* (usually a middlebox or a size guard in front of
  the TLS stack). A new `of which` row in the run summary carries breakdowns like
  this; before it, they reached the audit log and nowhere else, so an operator
  reading the screen saw a clean run with the result of the test missing from it.
  The same row now also reports WebSocket/SSE declines from 0.34.0.

### Notes

- The record is hand-rolled, std-only, as `h2_frames` is for the raw HTTP/2
  primitives. rustls is in this tree and drives every other TLS primitive, but a
  correct TLS library will not emit an incorrect-by-design hello — there is no
  API for "put 12 KiB in the SNI". No new dependency.
- **Oversized certificate chains are deliberately not covered.** The third idea
  in this family needs a server that requests client authentication, and a full
  handshake driven to the `Certificate` message, and a generated chain (a
  certificate-generation dependency) — to test a configuration most targets do
  not have. The two hello-side primitives reach the same parser without any of
  it.

## [0.34.0] — 2026-08-03

Two transports that are exhausted by using them **correctly**.

Every connection-holding primitive jinrai had until now works by being wrong on
purpose: Slowloris never terminates its headers, RUDY never delivers the body it
declared, slow-read refuses to drain the response. All three are defeated by the
same class of control — a header read timeout, a body read timeout, a minimum
data rate — and a target that passes them tells you only that those timeouts are
configured.

WebSocket and SSE are not defeated by any of them, because there is nothing to
time out. A WebSocket session that sits idle for an hour is a WebSocket session
working as designed, and an event stream that sends one comment every 30 seconds
is a healthy event stream. The connection-slot, worker and descriptor budget is
consumed exactly the same way. What jinrai now measures is whether anything
*else* stops it: a concurrent-session cap, a per-IP limit, an idle-session
reaper. If a run holds `--slow-connections` sessions for the whole `--duration`
with no errors, nothing does.

### Added

- **`--l7-method websocket`** — completes the RFC 6455 HTTP/1.1 upgrade (fresh
  16-byte `Sec-WebSocket-Key` per connection, as the RFC requires — a reused or
  malformed one is grounds for a server to reject the upgrade and would make the
  whole run look like a decline), then holds the session with a masked,
  zero-length `Ping` control frame every `--drip-ms`.
- **`--l7-method sse`** — an ordinary `Accept: text/event-stream` GET, held open
  and drained. No keep-alive traffic is needed at all: the server is the one
  obliged to keep the connection.
- Both reuse the slow modes' two knobs — `--slow-connections` as the concurrent
  ceiling, `--drip-ms` as the tick — rather than adding a second pair of flags
  for the same two numbers. `--rate` is connections opened per second, as it is
  for every other connection-holding primitive.
- **A declined transport is reported as a decline, not a failure.** A server that
  answers the upgrade with `404` and one that never answers at all are different
  findings: the first says the path in your URL is wrong, the second says the
  target is out of capacity or unreachable. The run summary names the count of
  each; a run that is all declines is not a capacity result.

### Fixed

- **A connection-holding run no longer blames the generator for its own
  ceiling.** `--slow-connections 25 --rate 50` opens 25 connections and then
  stops opening, so the summary reads `25 attempts, 10% of the 50/s cap` with
  zero failures — the precise shape the shortfall note fires on, and the one
  case where its conclusion was wrong: it told the operator that *this host*
  could not emit faster, when the host was doing exactly what it was asked. The
  ceiling is now declared for the slow modes and the two new ones, which both
  silences the false attribution and prints the bound next to the module name.
  This affects `slowloris` / `slowbody` / `slow-read` too, which had the same
  misreading since the note was introduced in 0.25.0.

### Notes

- `http(s)` URLs, not `ws(s)`: the upgrade *is* an HTTP/1.1 request, and the
  datum gate authorizes http(s) — so `https://` is how you say `wss://`. The
  safety boundary is unchanged: datum authorization, resolve-once, pinned connect
  address, kill switch, `--duration`.
- TLS for these two pins ALPN to `http/1.1`. Without it, a target offering h2
  could negotiate a protocol the upgrade cannot run over, and every connection
  would be counted as declined for a reason that was ours.
- The README roadmap's Phase 7 line had drifted — it still listed the protocol
  coverage as of 0.12.0. It now reflects what is actually implemented, and names
  what is left after Phase 8 (HTTP/3 & QUIC, IPv6 for the raw L3/L4 modes).

## [0.33.0] — 2026-07-31

The tail of the same external review. 0.32.0 took the allowlist bypass and the
skippable controls; this takes what was left, which is mostly one real defect and
a lot of *load-bearing invariants held by comments instead of by types*.

### Security

- **Ctrl-C is prompt again for L3/L4.** Retiring the connect pool `join()`ed
  every worker, and a worker blocked in `connect_timeout` cannot be interrupted —
  so aborting a run against a target that never answers waited out the full
  `--connect-timeout-ms` first. The run loop polled the kill switch every ~50ms
  and then the shutdown ignored it, which made the advertised abort latency a
  property of a timeout flag. The drain is now bounded (250ms on abort);
  handshakes still outstanding are reported as `abandoned` rather than waited
  out, and their threads are detached. `--l4-mode data` also checks the kill
  switch *before* each unit rather than after, so an abort no longer pays for one
  more blocking connect.
- **An allowlist rule that can never match is refused.** An IPv4-mapped entry
  (`--allow ::ffff:10.0.0.1/128`) parsed happily and then matched nothing ever:
  `contains` fail-closes on mapped candidates, and a plain v4 address never
  matches a v6 rule on family. The operator was left believing they had
  authorized a host. The parse error now names the spelling that works.
- **`DnsRule` can only be built by its parser.** The payload moved into a private
  inner enum. The wildcard form's invariant is that its stored suffix carries a
  leading dot — that is what makes `ends_with` align on a label boundary — and a
  hand-built rule holding `"internal"` would have matched `evilinternal`, turning
  the allowlist into a substring check.
- **`resolve_addrs` returns a type that cannot be empty.** Six engines each wrote
  `.first().expect("resolve_addrs is non-empty")`, a panic guarded only by a
  check in another function. The guarantee is now in the type and all six are
  gone.
- **Two `expect`s and an `unreachable!()` became refusals.** In `Sender::setup`
  they were reachable by adding a variant to `L4Mode`; under `panic = "abort"`
  each was a process death where a named refusal belongs.
- **A failed audit write no longer corrupts the log.** A partial `write_all`
  (ENOSPC, realistically) left half a line behind, after which every `verify`
  reported the file corrupt and `open` refused to append — one full disk
  permanently retired the trail. The record is now rolled back to the file's
  previous length, so a failure means the record did not happen.

### Fixed

- **A zero-rate profile stage is silent, not skipped.** Engines `continue`d past
  it, which shortened the run and reached every later rate early — so a ramp fine
  enough to truncate a stage to 0/s (0→5 in 10 steps wants 0.5/s first) reported
  a shape it had not run. Defined in `core` as `LoadStage::is_silent` rather than
  left to each engine.
- **`LoadProfile::stages` clamps `steps`** to `MAX_LOAD_STAGES` (10 000). The CLI
  already refused more; the library would have allocated a ~4-billion-element
  `Vec`.
- **`SlowConfig::drip` is floored at 1ms** when a run starts. The CLI refuses
  `--drip-ms 0`; this is the backstop for library callers, where zero turns a
  slowloris into an unpaced byte-flood that `--rate` does not bound.
- **A flag given twice is refused** instead of letting the last one win in
  silence — `--rate 100 --rate 5000` left an operator with a ceiling their own
  shell history disagreed with. `--allow`, `--target` and `--header` still
  repeat, because that is their interface.
- **A flag is never swallowed as another flag's value.** `--audit-log --ack-lab`
  wrote a file literally named `--ack-lab` and left the acknowledgement unset,
  surfacing later as an unrelated refusal.
- **Flags belonging to the other layer now warn** instead of being silently
  dropped (`--max-connections` under `--layer l4`, `--target` under `l7`).
- **Connect-worker stacks are 256 KiB**, up from 64 KiB. The work fits in 64 KiB;
  the margin does not, and a stack overflow is a `SIGSEGV`, not an error this
  code can return. The cost is address space, not resident memory.

### Not done

The review's remaining items are performance trade-offs — per-tick allocations in
`build_tcp_packet`, the shared `Mutex<Histogram>` on the L7 response path. This
project's optimisation history (0.24.0–0.28.0) is measured rather than guessed,
and the raw-socket path cannot be profiled without `CAP_NET_RAW`, so they are
left for a run that can measure them. The flat `Args` struct with per-mode fields
is also still flat: a per-mode config enum touches every call site in the CLI for
a readability gain, which is a poor trade against a safety-critical parser.

## [0.32.0] — 2026-07-31

A second external review, this time of the safety *baseline* rather than the
input surface. It found one real allowlist bypass — a target could redirect the
client onto a host the gate never saw — and three baseline items that were
implemented but optional, which for a dual-use tool means not implemented. The
theme of this release: the controls that existed were good, and could be skipped.

### Security

- **A target can no longer redirect jinrai off its authorized host.** The L7
  client pins the connect address for the authorized datum via `resolve_to_addrs`
  — but `reqwest` follows up to 10 redirects by default, and a redirect to
  another *host* goes through the system resolver, not the pin. A target
  answering `301 Location: http://somewhere.else/` therefore steered traffic to
  a host the gate never authorized, and carried the operator's `--header` values
  along with it. Peer-controlled, and the one bypass in the model. Redirects are
  now refused outright (`Policy::none()`); a `3xx` counts as the response it is.
- **The lab acknowledgement covers every layer.** `--ack-l34-lab` gated the raw
  socket layers only, leaving l7 — the *default* layer, the one needing no
  privileges — able to put real load on a target with nothing but a URL and an
  allowlist. It is now `--ack-lab` and applies to any run that emits traffic.
  `--ack-l34-lab` is still accepted so existing runbooks keep working.
- **A run without an audit trail is refused.** The audit machinery was already
  fail-closed once a log was open — opened before any traffic, a write failure
  aborts the run — but `--audit-log` was optional, and the command an operator
  would rather not have on record is exactly the one that omits it. Pass
  `--audit-log <PATH>`, or `--no-audit` to state that this run is untracked.
- **A kill switch that could not be installed now stops the run.** A failure to
  register the SIGINT/SIGTERM handler printed a warning and started the flood
  anyway — leaving a live run whose only advertised stop control did not exist.
- **`--dry-run`** does everything refusable — allowlist, gate, engine
  construction, preflight — then prints the plan and sends nothing. Previously
  the only way to check a command line was to run it.
- **Concurrency is bounded, not just rate.** `--rate` never bounded how many
  sockets a run holds open: at 5000/s against a target answering in 20s, the TLS
  handshake flood had ~100 000 handshakes in flight, and the fast l7 flood
  defaulted to unbounded fan-out. Both now cap in-flight work at
  `--max-connections` (default 1024, `0` = unbounded as an explicit choice).
- **The audit log takes an exclusive lock and verifies its own tail.** Two
  processes appending to one log each recovered the same `(seq, prev)` and forked
  the chain — after which `--verify-audit` reported an untampered log as
  `Tampered`. `open` also trusted the tail's stored hash, so records appended
  below an edited one chained cleanly onto the forgery. It now recomputes that
  hash and refuses a broken chain.
- **A v4 destination that yields a v6 local address refuses the run** instead of
  substituting `127.0.0.1` as the packet source. Unreachable on `AF_INET` today,
  but inventing a source address is precisely the spoofing path this crate
  promises not to have.

### Fixed

- **`--payload-size`, `--request-timeout-ms`, `--drain-timeout-ms` and
  `--connect-timeout-ms` are capped** like their siblings were in 0.31.0. The
  first is allocated per unit (a ~100 GB request was a flag away); the other
  three become `Instant::now() + duration`, which panics on overflow — and with
  `panic = "abort"`, after sockets are already open.
- **`--ramp-start` / `--spike-base` above `--rate` are refused at parse.** The
  documented promise that profiles shape traffic only *up to* the ceiling rested
  on a single `clamped_to` deep in the engine. A floor above the ceiling is a
  contradiction only the operator can resolve.
- **HPACK string lengths of 127+ are encoded properly** (RFC 7541 §5.1
  continuation). A hostname may be 253 bytes; the single-octet prefix truncated
  it into a header block the server parsed as something else — a test tool
  silently measuring the wrong thing.
- **An SLO threshold of `NaN` no longer reports `PASS`.** `observed > NaN` is
  false, so a non-finite limit silently disabled the check. An unevaluable
  threshold now counts as breached, and `SloSpec::validate` rejects it outright.
- **The CLI's module doc no longer claims "no traffic is emitted yet."** It had
  described the Phase 1 stubs since before the traffic modules existed.

## [0.31.0] — 2026-07-31

Hardening pass over the operator-input surface, from an external code review. The
safety model itself held up — no allowlist bypass, no spoofing path, no way to
forge an `AuthorizedTarget` — but extreme values of `--rate`, `--duration`,
`--concurrency` and `--ramp-steps` reached panics, unbounded allocations and a
breached rate ceiling, and several failures could report themselves as clean runs.

### Fixed

- **`--rate` is a ceiling again, and an absurd one no longer kills the process.**
  The per-unit interval came from `Duration::from_secs_f64(1.0 / rate)`, which
  rounds to *nearest*: at 3 000 000/s the exact 333.33ns became 333ns, pacing
  3 003 003/s — half a percent above the declared hard ceiling — and above
  ~2×10⁹/s it rounded all the way to zero. A zero interval is a division by zero
  in the L3/L4 batcher and a panic inside `tokio::time::interval`, so a
  fat-fingered `--rate` killed the process mid-run with the raw socket already
  open. It is now an integer ceiling division floored at 1ns: rounding can only
  ever under-deliver, which is the side a safety ceiling must err on.
- **A spike no longer stretches the run past `--duration`.** `--profile spike`
  passed the full duration as the baseline total and then added `--spike-secs` on
  top, so `--duration 30 --spike-secs 10` generated 40 seconds of traffic. The
  spike is now carved out of the window, and the L7 engine additionally clamps the
  cumulative stage deadlines to `plan.duration`, so the promise holds regardless
  of what a caller hands it.
- **The raw HTTP/2 engines can no longer be pinned open by the target.** Their
  frame writes sat outside the `select!`: on a peer that stops reading — the state
  several of these primitives exist to induce — `write_all` pends forever, past
  `--duration` and deaf to Ctrl-C, which put the *server* in charge of when a run
  ends. Writes are now raced against the kill switch and the deadline, with a
  5-second stall timeout that reports a wedged connection instead of sitting on
  it. `h2-rapid-reset`'s wait for a stream slot got the same treatment.
- **SIGTERM stops a run gracefully.** Only SIGINT was hooked, so `systemctl stop`,
  `docker stop` and a Kubernetes eviction — i.e. every way an unattended run is
  actually stopped — killed the process outright: no drain, and no `RunCompleted`
  record in the audit log.
- **Numeric flags are bounded at the front door.** `--rate`, `--duration`,
  `--concurrency`, `--slow-connections`, `--max-connections`, `--ramp-steps`,
  `--ramp-start` and `--spike-secs` are refused with a named limit instead of
  reaching a capacity-overflow abort (`--concurrency` is an allocation size),
  a ~100 GB `Vec` of ramp stages, or an `Instant` overflow panic. `--drip-ms 0`
  and `--slow-connections 0` are refused too: the first turns a slow attack into
  an unpaced write flood, the second reports a clean run that held nothing.
- **A dead route no longer reports as a completed run.** In L3/L4 a structural
  send failure (no route, an address family the primitive cannot build for) was
  bucketed as `Internal` *per packet*, producing a "completed" run with 100%
  misattributed errors — the hollow-success shape `check_targets` exists to
  prevent. The first such error now ends the run as the failure it is.

### Changed

- **`StressModule::execute` returns `Result<RunReport, ModuleError>`.** A module
  could previously only report, so every failure had to be dressed up as a run: a
  missing `CAP_NET_RAW` became "0 units sent, aborted early", indistinguishable in
  the audit log from a deliberate `--rate 0` or an operator's Ctrl-C. Failures are
  now recorded as `RunRefused` with their stage and cause, `aborted_early` means
  only what it says, and the eight near-identical `refusal_report` helpers are
  gone.

### Security

- **Refusals decided before the gate are audited.** A malformed or empty
  `--allow`, a missing `--ack-l34-lab`, a missing `--target` / `--port` / `--url`
  all returned without a record even with the log open, while authorization and
  preflight refusals were audited — an inconsistent trail on exactly the events a
  reviewer looks for.
- **Audit records are durable and private.** `flush` only moved bytes into the OS
  page cache, which a crash discards — precisely losing the records written just
  before a machine went down. Each record is now `sync_data`'d, and a newly
  created log is `0600` rather than whatever the umask allowed, since it names
  every target a run was pointed at and who pointed it.
- **The audit log stops overclaiming.** The docs said the hash chain defeats
  truncation; it does not, and cannot — a record links only backwards, so deleting
  the last *k* records leaves a chain that verifies perfectly, and reopening the
  log chains onto the truncated tail. The limitation is now documented, and
  `--verify-audit` reports the sequence range it found with an explicit note,
  instead of a bare "INTACT" that reads like proof of completeness.

### Tests

- Boundary tests for the pacing interval: no non-zero rate yields a zero interval
  (up to `u64::MAX`), no rate paces above its cap, and awkward rates that cannot
  divide a second evenly approach the ceiling only from below.
- CLI tests for every new limit, for the zero-valued flags, and for the spike
  fitting exactly inside `--duration`.
- `scripts/demo_gate.sh` now asserts *why* each case failed, not just that it
  did — cases 1 and 2 were exiting 1 for a missing `--url`, demonstrating the
  argument parser rather than the gate. `scripts/verify_criteria.sh` passes
  `--output line`, the format it has always parsed, instead of silently printing
  a table of zeros.

## [0.30.0] — 2026-07-31

### Added

- **Wall-clock start and finish times in the run summary.** The block reported
  `30.0s elapsed of 30.0s planned` and never said *when* that window was, so
  lining a run up against the target's own logs, graphs or alerts meant
  reconstructing the clock time from when the shell prompt came back. Two rows —
  `started` / `finished`, RFC 3339 UTC — now bracket the window. The finish time
  is derived from the start plus the measured elapsed time (rounded, so a 10.4 s
  run finishes at +10 s rather than inside its own window), which is why the two
  timestamps can never disagree with the `window` row above them. A caller that
  cannot read the clock omits both rows rather than claiming 1970.
- **`--l4-mode syn-ack` — unsolicited SYN-ACK flood.** The raw-TCP family had
  every single flag and every illegal combination, but not the one combination
  whose flags are *legal* and whose **state** is not: the second segment of a
  handshake, answering a SYN the target never sent. Each packet must be matched
  against connection state and either tracked or answered with an RST, which is
  the load a firewall or load balancer sees as the reflected half of a spoofed
  flood elsewhere. Same constraints as the rest of the raw family: `CAP_NET_RAW`/
  root, IPv4-only, real source address (never spoofed), and the ACK number is a
  real one rather than a bare bit.

## [0.29.0] — 2026-07-31

The summary told an operator that a saturating target had absorbed two thirds of
the offered load. It had not — two thirds of that load was never offered.

A real `--layer l4 --l4-mode tcp --rate 10000 --concurrency 512
--connect-timeout-ms 500` run reported `3183.3/s achieved (32% of the 10000/s
cap)`, `latency p50 2.7ms p90 5.7ms p99 7.7ms`, and no explanation of the
shortfall. Every one of those numbers was accurate and the reading they invited
was wrong. This release makes the reporting match the run, and removes the
ceiling that made the shortfall unavoidable.

### Fixed

- **The Little's-law note divided by the wrong number, and so stayed silent.**
  `bound by` estimates what a run *could* have offered as `concurrency /
  attempt-time`, and used `p50_micros` for the second term. But the percentiles
  cover attempts that **completed**; an attempt that times out completes nothing
  and holds its in-flight slot for the entire timeout. In the run above the
  median completion was 2.7 ms while the mean slot residency was ~132 ms — a
  factor of 40. Dividing by the median put the estimated ceiling at 190k/s, far
  above the 10k cap, so the note concluded the run had ample headroom and
  printed nothing. The true ceiling was ~3.9k/s and the cap was never reachable.
  The note now divides by mean residency and, when the shortfall is real, states
  the achieved rate as the load actually offered.

- **`--concurrency` above 512 bought nothing on `--l4-mode tcp`.** The connect
  pool clamped simultaneous handshakes at 512 whatever the operator asked for,
  so the advice the summary gave — raise `--concurrency` — could be followed to
  4096 with the achieved rate not moving. The clamp's own comment justified 512
  as "~170k attempts/s against a 3 ms target", arithmetic that assumes every
  handshake completes and is therefore wrong in exactly the case a flood is run
  to produce. The ceiling is now 4096.

- **Failed attempts held slots invisibly (L4 and L7).** Both engines measured
  how long an attempt took and then discarded that measurement on the failure
  path, so the one population that dominates the concurrency budget left no
  trace in the report.

### Added

- **`RunReport::mean_micros`** — mean residency of a resolved attempt, failures
  included. Distinct from the percentiles by design: `latency` stays "how long a
  completed attempt took", `mean_micros` answers "what did an in-flight slot
  cost", and only the second one bounds offered load.

- **`jinrai_l34::effective_parallelism`** — the in-flight ceiling that actually
  applied, so the summary quotes the number that bound the run rather than the
  `--concurrency` the pool may have clamped away.

### Changed

- **The `latency` row says what it covers.** With failures present it now reads
  `… (completed attempts only — the 8733 that failed are not in these
  percentiles)`, and a `per-slot` row appears when mean residency diverges from
  the completed-only view. A `p99 7.7ms` printed directly under `failed 8733
  (26.1%)` reads as a healthy target; it was the p99 of the survivors.

- **`--concurrency` help no longer says the reachable rate is `N /
  round-trip-time`.** It is `N / mean-attempt-time`, and once a meaningful share
  of attempts fail, lowering `--connect-timeout-ms` raises that rate far more
  than raising `N` does. The help now points at the `bound by` line to say which
  of the two applies.

## [0.28.0] — 2026-07-31

`crates/l34` split into modules. **No behaviour change** — this is code motion.

`lib.rs` had reached 2070 lines holding the mode table, the packet builders, the
pacing, the socket senders, the connect pool, the engine and every test. It is
the file that grows with each new L4 primitive, and it is also where the crate's
central safety claim lives — which was the actual motivation. The no-spoofing
guarantee is a property of a handful of functions, and those functions were
buried in the middle of two thousand lines of engine.

### Changed

- **`packet.rs` — the no-spoofing surface, now readable on its own.** Everything
  that decides what goes on the wire below the socket API: the IPv4+TCP builders,
  the options bomb, the ICMP query builder, the checksum, and `source_ipv4_for`.
  Its module doc states the guarantee and how it holds in each of the two shapes
  it takes — raw TCP crafts the IP header, so the source is an explicit argument
  whose *only* producer is `source_ipv4_for` (which asks the OS which local
  address routes to the target); ICMP crafts only the ICMP message, so the kernel
  supplies the real source and a forged one is not even expressible. A reviewer
  can now confirm the claim without reading an engine.

- **`mode.rs`** — which primitive a run drives and its configuration. Pure
  functions of the mode, no sockets, no counters: the table of eighteen
  primitives now reads as a table.

- **`pace.rs`** — turning `--rate` into a schedule the send loop can keep
  (`MIN_TICK`, `batch_for`, `interruptible_sleep`), newly worth isolating after
  the 0.26.0 batching change.

- **`lib.rs`** keeps the engine, the socket senders, the connect pool and the
  tally: **2070 → 1348 lines**, with a layout table at the top.

### Added

- Three tests that the split made natural to write:
  - `packet::the_source_address_is_the_one_supplied_and_nothing_else` — the
    builder carries the source address verbatim and never substitutes, derives or
    randomises a different one. The no-spoofing guarantee had been asserted only
    incidentally, as one line inside a SYN well-formedness test.
  - `mode::icmp_query_modes_are_l3_raw_and_carry_no_tcp_flags` — the mode table's
    own view of the ICMP modes, alongside the existing engine-level check.
  - `pace::a_tripped_kill_switch_cuts_the_sleep_short` — an abort is noticed
    without waiting out a long inter-packet sleep.

### Verification

Every moved test moved **verbatim**. l34 went 32 → 35 tests, which is exactly the
32 that existed plus the 3 above; the full suite is 206 and clippy is clean. The
release binary was re-measured on a loopback UDP flood at 20 k/s and 200 k/s and
delivers 100% of cap in both, unchanged from 0.26.0.

## [0.27.0] — 2026-07-31

The CLI gets its first tests.

Every crate underneath it was well covered — 189 tests across safety, l7, l34,
metrics and core — while `crates/cli`, 1100+ lines, had **none**. That is the
layer where an operator's intent becomes a `RunPlan`, and where `--allow`,
`--ack-l34-lab`, the SLO thresholds and the process exit codes are all read. A
parser that quietly accepts a malformed threshold, or an outcome check that
reports success for a run that tested nothing, is a safety defect no test below
this layer can catch.

### Added

- **14 tests covering the operator-facing surface**, grouped by what they
  protect:
  - *defaults* — the quiet default is the safe one (`--rate 100`, L7, and
    `--ack-l34-lab` never on by default);
  - *the allowlist* — `--allow` accumulates in order and verbatim, a flag missing
    its value is an error rather than a silent default (`--allow` swallowing the
    next flag would widen the allowlist), and a malformed `--target` IP is
    refused;
  - *values that must not be silently accepted* — the fat-finger guard on the SLO
    thresholds (`--slo-max-5xx-rate 50` meaning "50%" must not become an
    unreachable 5000% threshold that can never fail), with the `0.0`/`1.0`
    boundaries confirmed legitimate; and unknown `--l4-mode` / `--l7-method` /
    `--http-version` / `--output` values refused rather than defaulted, since
    silently running `udp` when the operator asked for `syn` produces a
    confidently wrong result;
  - *the L3/L4 pre-traffic gates* — a missing `--ack-l34-lab`, `--target` or
    `--port` refuses before any socket is opened, asserted against otherwise
    valid invocations;
  - *exit-code policy* — a run that completed nothing exits non-zero, `--rate 0`
    is a deliberate no-op rather than a failure, a watchdog abort exits non-zero
    (the target buckled), and an operator Ctrl-C does not (they stopped it on
    purpose).

### Changed

- **`parse_args` split into a testable `parse_args_from`.** The parse loop no
  longer calls `std::process::exit` for `--help`; it returns `Ok(None)`, which
  the caller treats as "nothing to run". Keeping a process exit in the middle of
  a parse function would have made the whole function untestable, and a future
  `--help` test would have killed the test runner instead of failing.

### Fixed

- **`--help` did not document `--layer l3`.** The parser has always accepted it
  (`l3` and `l4` select the same module — the ICMP modes report as L3, the rest
  as L4), and the README and cookbook both write "l3/l4", but the usage text
  listed only `<l4|l7>`. Found by the new tests; a test now pins the help text
  and the parser together.

## [0.26.0] — 2026-07-31

The L3/L4 pacer no longer lets `thread::sleep` decide the rate.

`--rate 200000` on a UDP flood delivered **28 769/s — 14% of the cap**. Not
because the target or the network pushed back (nothing failed), but because the
pacer emitted one packet per `thread::sleep`, and a sleep cannot resolve the 5 µs
interval that rate implies: every nap overshot by an order of magnitude and the
*sleep granularity*, not `--rate`, set the pace.

The same run now delivers **199 969/s — 100% of the cap**, and the ceiling has
moved from ~29 k/s to **~589 k/s**, where the limit is the cost of one send
syscall per packet: a real property of the host rather than an artefact of how
the loop was written.

| `--rate` | before | after |
|---|---|---|
| 20 000/s | 16 986/s (85%) | **19 998/s (100%)** |
| 200 000/s | 28 769/s (14%) | **199 969/s (100%)** |
| ceiling | ~29 000/s | **~589 000/s** |

### Changed

- **Below one millisecond per unit, the tick replaces the unit as the scheduling
  quantum.** The pacer emits `batch` units back-to-back and then sleeps off the
  rest of the tick, with `batch` chosen so that `batch / tick` is exactly the
  requested rate. Above one millisecond per unit nothing changes — the pacer
  still sleeps once per unit, as it always did.

  **`--rate` remains a hard ceiling.** No window of one tick or longer ever
  carries more than the cap authorises; there is a test asserting the arithmetic
  holds to within 0.1% across four decades of rate. The trade is explicit: within
  a single tick the units leave as fast as the syscalls go, so a batch is a burst
  of at most one millisecond of traffic — declared rather than accidental, and
  the shape any rate-limited generator takes once the requested rate exceeds what
  per-unit pacing can deliver.

  The deadline and the kill-switch are re-checked **inside** the batch, so a
  large `--rate` cannot buy traffic past `--duration` and Ctrl-C does not wait
  for the batch to drain. Verified: a 1 s run at `--rate 5000000` still returns
  in 1.01 s.

### Not changed, and why

The **L7 pacer was measured and left alone.** It has the same one-unit-per-tick
shape, but it paces on `tokio::time::interval`, whose timer resolves sub-
millisecond intervals far better than `thread::sleep` does: against a fast
keep-alive target the fast flood holds **100% of its cap to 20 000 req/s**, and
what breaks down past that is the sockets (54% failures), not the pacing. There
was no artefact to remove.

**Multi-threaded L3/L4 emission was considered and rejected.** With the batching
fix the ceiling is the send-syscall rate at ~589 k packets/s, far past what a lab
exercise calls for; parallelising the sender would chase diminishing returns
against that floor while adding per-thread sockets, tally merging and abort
coordination to the crate that most needs to stay auditable.

## [0.25.0] — 2026-07-31

The run summary now names **the generator** when the generator was the limit.

`--rate 200000` on a UDP flood reports `28769.9/s achieved (14% of the 200000/s
cap)` with **zero failures**. Read without help, that is the most dangerous line
the tool prints: it looks exactly like a target absorbing 86% of the offered
load. It is not. The load was never offered — a stateless flood paces itself one
unit at a time and tops out around 29k/s on this host, whatever `--rate` accepts.

0.22.0 added the mirror of this for the modes that have an in-flight ceiling
(`bound by concurrency, not the target`, from Little's law). The modes that have
no such ceiling — every stateless flood — were left with a bare percentage and
nothing to interpret it with.

### Added

- **`bound by  the generator, not the target: …` in the run summary.** Fires only
  when every other explanation is eliminated: nothing failed (so nothing was
  refused, reset or timed out), there is no concurrency ceiling that could have
  throttled dispatch, the run was not cut short, and the achieved rate is below
  90% of the cap. What remains is this host's own pacing limit, so the note
  restates the achieved rate as the **real** offered load and says explicitly not
  to credit the target with the difference:

  ```
   attempts   86335 total, 28769.5/s achieved (14% of the 200000/s cap)
   failed     0
   bound by   the generator, not the target: nothing failed and there was no
              in-flight ceiling, so 28769/s is what this host could emit — the
              shortfall against the 200000/s cap is jinrai's own limit, NOT load
              the target absorbed. Treat 28769/s as the load actually offered
  ```

  The two `bound by` notes are mutually exclusive by construction: the
  concurrency note applies only where there is an in-flight ceiling to blame,
  this one only where there is not. Where both could apply, concurrency wins —
  it is the more specific, and actionable, answer.

## [0.24.0] — 2026-07-31

`--duration` now bounds the **traffic**, not just the dispatching of it.

Measured on the bench: `--duration 3` against a slow target generated traffic
for **13.0 seconds** — a window the operator never declared, and one the audit
log recorded as three seconds. The dispatch loop did stop at the deadline, but
the run then waited out every request still in flight, and the per-request
timeout was a hard-coded 10 s, so the real window was `--duration` plus that
timeout. The same run now finishes in 4.7 s, and a healthy target's run in 3.1 s
against a 3.0 s window.

For a tool whose whole premise is that the operator's declared limits are real,
a duration that silently means "three seconds, plus up to ten more" is a safety
defect, not a performance one — which is why it is listed under **Security**
below as well.

### Security

- **The run window is now enforced on the traffic itself.** Dispatch still stops
  at the deadline; what changed is the tail. In-flight requests get a bounded
  grace period to land, and whatever is still outstanding is **cancelled**, so
  no request can outlive the run by more than that grace. An operator abort
  (Ctrl-C / watchdog) skips the grace entirely and cancels immediately, as it
  always did. The audit log's recorded duration and the traffic actually emitted
  now describe the same window.

- **Cancelled attempts are counted, never dropped.** A silently discarded
  in-flight request would understate the offered load and flatter the target, so
  every attempt cancelled at the deadline is tallied in a new `abandoned` errno
  bucket and shows up in the run summary with its own explanation. It is
  deliberately kept apart from `timeout`: the cause is the *run's* shape (the
  target was answering slower than the offered load), so the fix is a longer
  `--duration` or a lower `--rate`, not a longer per-attempt timeout.

### Added

- **`--request-timeout-ms <MS>`** (default `10000`) — how long one L7 request may
  stay unresolved before it is abandoned and counted in the `timeout` bucket.
  Previously hard-coded, with no way for an operator to say that a target which
  takes eight seconds to answer has already failed the test.

- **`--drain-timeout-ms <MS>`** (default `1000`) — how long to wait for
  still-in-flight requests once `--duration` expires, before cancelling them.
  `0` cancels at the deadline itself, the strictest reading of the flag. One
  second is long enough that a responsive target abandons nothing (there is a
  regression test asserting exactly that) and short enough that the declared
  window still means something.

### Fixed

- **The achieved-rate figure no longer charges teardown to the run.** Dropping
  the L7 engine's multi-thread runtime *blocks* until its worker threads wind
  down, and that time was being counted as part of the run window — a clean
  500/s run reported "4.0s elapsed of 3.0s planned, 75% of the cap" when it had
  in fact held 98% of the cap for its full three seconds. The runtime is now
  released in the background once every traffic task is joined or cancelled.

### Known limitation

A run that ends with tens of thousands of requests still in flight spends
measurable time cancelling them (~6.4 s wall for a 3 s run that left 24 000
outstanding). No new traffic is generated during that tail — dispatch has
stopped and the cancelled connections are closing — but it is still charged to
the reported elapsed time, which dilutes the achieved-rate percentage. The
`abandoned` count is the signal that this happened, and `--max-connections`
bounds the pile-up at its source.

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

- **A cookbook of complete, runnable commands, and a table of what `--rate`
  actually counts.** Follow-up to the above: knowing *which* technique to pick
  is only half the answer if the catalogue gives fragments (`--l7-method
  slowloris`) rather than a command that runs. The cookbook now carries one
  complete invocation per technique — nothing implied or omitted — grouped into
  L7 (no privilege) and L3/L4 (lab, `--ack-l34-lab`), with a "swap only the mode
  name" note for the families that share a shape (the nine `h2-*` methods, the
  eleven raw flag/anomaly floods, the three ICMP query floods, the three slow
  modes). Alongside it, a table of the trap that costs the most time: `--rate`
  means requests/sec, connections-opened/sec, handshakes/sec, frames/sec or
  packets/sec depending on the family, and each family reads a different
  footprint knob — `--slow-connections` on an `h2-*` method does nothing, and
  `--concurrency` is inert for every stateless flood. Every command in the
  cookbook, and all 34 documented method/mode names, were executed against the
  built binary to confirm the CLI accepts them as written.

- **The README is now one document in three parts, with each fact stated once.**
  The 101 had been bolted onto a reference manual that already carried its own
  examples, so eleven commands existed twice (POST, `--max-connections`,
  slowloris, slow-read, `h2-continuation`, both `--http-version` forms, both SLO
  forms, `udp`, `xmas`, `tcp`, `data`, `tcp-options`, `icmp`) and the
  fail-closed rule and the no-spoofing guarantee were each stated three times.
  Examples now live only in the cookbook and the reference keeps only the prose
  that explains *why* — the `auto` ALPN trap, the `TIME_WAIT`/`SO_LINGER`
  reasoning, the errno buckets, the `--concurrency / RTT` bound. The order
  follows the operator instead of the build history: **Part I — Operating**
  (install → anatomy of a run → layer → catalogue → knobs → cookbook → first
  four runs → choosing numbers → reading the result → audit log → what the tool
  will not do), **Part II — Reference** (per-flag semantics), **Part III — About
  the project** (Rust rationale, architecture, team, roadmap). `Build & test`
  became `Install` and moved to the top, since it was previously documented
  *after* the section telling operators to run things. Adds a linked table of
  contents; all 21 internal links verified to resolve.

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

[Unreleased]: https://github.com/h4b00b/jinrai/compare/v0.41.0...HEAD
[0.44.0]: https://github.com/h4b00b/jinrai/compare/v0.43.0...v0.44.0
[0.43.0]: https://github.com/h4b00b/jinrai/compare/v0.42.0...v0.43.0
[0.42.0]: https://github.com/h4b00b/jinrai/compare/v0.41.0...v0.42.0
[0.41.0]: https://github.com/h4b00b/jinrai/compare/v0.40.0...v0.41.0
[0.40.0]: https://github.com/h4b00b/jinrai/compare/v0.39.0...v0.40.0
[0.39.0]: https://github.com/h4b00b/jinrai/compare/v0.38.0...v0.39.0
[0.38.0]: https://github.com/h4b00b/jinrai/compare/v0.37.0...v0.38.0
[0.37.0]: https://github.com/h4b00b/jinrai/compare/v0.36.0...v0.37.0
[0.36.0]: https://github.com/h4b00b/jinrai/compare/v0.35.0...v0.36.0
[0.35.0]: https://github.com/h4b00b/jinrai/compare/v0.34.0...v0.35.0
[0.34.0]: https://github.com/h4b00b/jinrai/compare/v0.33.0...v0.34.0
[0.33.0]: https://github.com/h4b00b/jinrai/compare/v0.32.0...v0.33.0
[0.32.0]: https://github.com/h4b00b/jinrai/compare/v0.31.0...v0.32.0
[0.31.0]: https://github.com/h4b00b/jinrai/compare/v0.30.0...v0.31.0
[0.30.0]: https://github.com/h4b00b/jinrai/compare/v0.29.0...v0.30.0
[0.29.0]: https://github.com/h4b00b/jinrai/compare/v0.28.0...v0.29.0
[0.28.0]: https://github.com/h4b00b/jinrai/compare/v0.27.0...v0.28.0
[0.27.0]: https://github.com/h4b00b/jinrai/compare/v0.26.0...v0.27.0
[0.26.0]: https://github.com/h4b00b/jinrai/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/h4b00b/jinrai/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/h4b00b/jinrai/compare/v0.23.0...v0.24.0
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

# jinrai

Internal network **resilience / stress-testing** tool for authorized internal
infrastructure. Covers L3/L4 and L7. Built in-house and validated in-house.

> **Scope & authorization.** This tool is for testing infrastructure we own or
> are explicitly authorized to test. It is **fail-closed**: it refuses to send
> anything to an address that is not inside an operator-supplied allowlist. The
> allowlist is passed at runtime (multiple CIDR blocks), never hard-coded,
> because different campaigns target different networks.

> **Test plan in hand?** [`docs/playbook.md`](docs/playbook.md) maps a test-plan
> row to a ready command and explains **every switch in it**, one case at a time.

## Contents

**[Part I — Operating jinrai](#part-i--operating-jinrai)** · start here, it is
enough to run every test the tool has.

[Install](#install) ·
[Anatomy of a run](#anatomy-of-a-run) ·
[Which layer?](#which-layer) ·
[The catalogue](#the-catalogue) ·
[Rate, concurrency, and which knobs apply](#rate-concurrency-and-which-knobs-apply) ·
[The cookbook](#the-cookbook) ·
[Your first four runs](#your-first-four-runs) ·
[Choosing numbers safely](#choosing-numbers-safely) ·
[Reading the result](#reading-the-result) ·
[The audit log](#the-audit-log) ·
[What jinrai will not do](#what-jinrai-will-not-do)

**[Part II — Reference](#part-ii--reference)** · the semantics behind each flag,
when the cookbook is not enough.

[L7 reference](#l7-reference) ·
[L3/L4 reference](#l3l4-reference)

**[Part III — About the project](#part-iii--about-the-project)** ·
[Why Rust](#why-rust) ·
[Architecture](#architecture) ·
[Team](#team) ·
[Roadmap](#roadmap)

---

# Part I — Operating jinrai

## Install

```sh
cargo build --release     # binary at target/release/jinrai
cargo test                # unit tests, incl. the safety gate
cargo clippy
jinrai --help             # every flag, always current
```

The raw-socket modes additionally need `CAP_NET_RAW` or root on Linux; nothing
else in the tool requires privilege.

## Anatomy of a run

A jinrai run applies **one** kind of pressure to **one** authorized target and
then reports whether the target held. Every command you will ever type is the
same five decisions:

| Decision | Flag(s) | |
|---|---|---|
| **Where am I allowed to send?** | `--allow` (repeatable) | An IP/CIDR (`10.0.0.0/8`) or a DNS pattern (`*.staging.internal`). No default: with an empty allowlist the run is refused. A rule that could never match — an IPv4-mapped entry like `::ffff:10.0.0.1/128` — is refused too, rather than sitting there looking like it authorized something. |
| **Which target?** | `--url` (L7), or `--target` + `--port` (L3/L4) | Checked against the allowlist before a single byte is sent. `--target` repeats and `--port` takes a range — that pair is [carpet bombing](#random-ports-and-carpet-bombing). |
| **Which pressure?** | `--layer`, then `--l7-method` / `--l4-mode` | This is "the attack" — see [the catalogue](#the-catalogue). |
| **How hard?** | `--rate`, plus a concurrency ceiling | `--rate` is a hard safety ceiling, never exceeded by anything. Which ceiling flag applies depends on the method — see [the knob table](#rate-concurrency-and-which-knobs-apply). |
| **How long?** | `--duration`, optionally shaped by `--profile` | |

Everything else — `--slo-*`, `--watchdog` — **judges** and **bounds** the run
rather than generating traffic.

Two more flags are **mandatory on any run that emits traffic**, at every layer:

| Flag | Why it is not optional |
|---|---|
| `--ack-lab` | You state, per run, that the target is yours to hit. (Was `--ack-l34-lab`, L3/L4-only; the old spelling still works.) |
| `--audit-log <PATH>` | The run leaves a trail. `--no-audit` runs without one — allowed, but it has to be said out loud rather than happening by omission. |

Not sure about a command line? `--dry-run` does everything except send:
allowlist, gate, preflight, then prints the run it was about to start. It needs
neither of the two flags above, because it emits nothing.

The smallest useful command:

```sh
jinrai --layer l7 --allow '*.staging.internal' \
       --url https://api.staging.internal/health --rate 50 --duration 10 \
       --ack-lab --audit-log runs.jsonl
```

## Which layer?

| Layer | What it exercises | Requires | Where to run it |
|---|---|---|---|
| **L7** `--layer l7` | the service: request handlers, connection slots, TLS, HTTP/2 state machine | nothing special | staging / QA. Real requests, real responses — the only layer that yields a `PASS`/`FAIL` verdict |
| **L4** `--layer l4` | the transport: accept backlog, connection tracking, firewall state, socket buffers | the raw modes also need `CAP_NET_RAW`/root (Linux, IPv4-only) | isolated lab only |
| **L3** `--layer l3` | the host's IP/ICMP handlers | same as L4 | isolated lab only |

Rule of thumb: **L7 answers "can the service still serve?", L3/L4 answer "can
the host and the middleboxes survive the packets?"**. Only L7 reads responses,
so only L7 can tell a healthy target from one that answers `500` at full speed.
**Start at L7** — it is the layer that maps onto a real incident, and it needs
no privilege and no isolated network.

## The catalogue

Pick by the resource you want to squeeze, not by the name of the technique.
Every entry here has a complete command in [the cookbook](#the-cookbook).

### 1. Throughput capacity — "how many requests/s before it degrades?"

L7 fast methods. Realistic traffic, fully classified, safe to point at staging.

| Goal | Command shape |
|---|---|
| Read-path capacity | `--l7-method get` |
| Write-path capacity | `--l7-method post --body '{...}'` |
| Make sure you are testing the origin, not a cache/CDN | add `--cache-bust` |
| Nothing cacheable anywhere: every URI unique and non-existent | add `--random-path` |
| The same, but on endpoints that exist | add `--path-file endpoints.txt` |
| The query no cache can serve (search-field flood) | add `--search-param q` |
| A new server-side session per request (session exhaustion) | add `--session-cookie JSESSIONID` |
| **Find the breaking point automatically** | `--profile ramp --discover-knee --slo-max-5xx-rate 0.01` |
| Burst tolerance / autoscaling reaction | `--profile spike --spike-secs 30` |
| Slow degradation, leaks, GC pressure | `--profile soak --duration 3600` |
| Same load over a different protocol | `--http-version 1.1` vs `--http-version 2` |

### 2. Concurrency limits — "how many simultaneous clients before it stops accepting?"

A *different* failure than throughput: the server has capacity left but no free
slot. Cheap for the client, which is exactly the point.

| Goal | Method |
|---|---|
| Keep-alive slot / worker-pool exhaustion, controlled | `--l7-method get --max-connections 50` |
| Classic **Slowloris** — hold connections with never-finished request headers | `--l7-method slowloris` |
| **RUDY** — oversized `Content-Length`, body trickled one byte at a time | `--l7-method slowbody` |
| **Slow read** — complete request, then refuse to drain the response | `--l7-method slow-read` |
| **WebSocket sessions** — a correct upgrade, then hold the session open | `--l7-method websocket` |
| **SSE streams** — a correct `text/event-stream` GET, held open | `--l7-method sse` |
| Accept backlog / conntrack table, below HTTP | `--layer l4 --l4-mode tcp --concurrency 256` |

The last two are the awkward ones to defend against, because nothing about them
is abusive: a WebSocket or SSE endpoint is *designed* to keep the connection for
as long as the client wants it, so the request-header and body read timeouts that
retire a Slowloris connection never fire. What they measure is whether anything
else does — a concurrent-session cap, a per-IP limit, an idle-session reaper. If
a run holds `--slow-connections` sessions for the whole `--duration` with zero
errors, the answer is no. Both take `http(s)` URLs (the handshake *is* an HTTP
request, so `https://` is `wss://`), and the summary reports a server **declining**
the transport separately from a connection that never got an answer — a run that
is all declines is pointing at the path in your URL, not at the target's capacity.

### 3. Handshake cost — "is the crypto the bottleneck?"

| Goal | Method |
|---|---|
| **THC-SSL-DoS** — complete a TLS handshake, drop it, repeat (asymmetric CPU cost) | `--l7-method tls-handshake` (https only) |
| **Oversized ClientHello** — 16 KiB of well-formed hello, no handshake completed | `--l7-method tls-big-hello` (https only) |
| **SNI bomb** — a 12 KiB `server_name` of legal DNS labels | `--l7-method tls-sni-bomb` (https only) |

The last two measure the *other* half of TLS cost: the work a server does on
bytes it has not yet decided to trust, before any key exchange. Read the answer
split, not the completion count — the three outcomes mean opposite things. A
hello the target **parsed** is work it performed for you; one it **refused with
an alert** is the healthy result (measure how cheaply it refused); one answered
with **silence** usually means a middlebox or a size guard sits in front of the
TLS stack, which is worth knowing before you conclude anything about the server.

### 4. Protocol asymmetry (HTTP/2) — "one cheap frame, one expensive server reaction"

Each of these is a published CVE class: work that costs the client almost
nothing and the server a great deal. They send no application data and read no
responses, so `--slo-*` and `--watchdog` do not apply — you judge them by
whether the target survives.

| Method | What it does | CVE |
|---|---|---|
| `h2-rapid-reset` | open a stream, immediately `RST_STREAM` | CVE-2023-44487 |
| `h2-made-you-reset` | make the **server** reset the stream — evades rapid-reset mitigations | CVE-2025-8671 |
| `h2-continuation` | `HEADERS` without `END_HEADERS`, then endless `CONTINUATION` | CVE-2024-27316 |
| `h2-bomb` | HPACK header amplification with the memory pinned by a zero window | CVE-2026-49975 |
| `h2-settings` / `h2-ping` | control frames the server is obliged to ACK / PONG | CVE-2019-9515 / -9512 |
| `h2-window-update` / `h2-priority` | flow-control updates / priority-tree reshuffles | CVE-2019-9514 / -9513 |
| `h2-empty-data` | zero-length `DATA` frames without `END_STREAM` | CVE-2019-9518 |

### 5. HTTP/3 and QUIC — "does the UDP front door have the same locks?"

| Goal | Method |
|---|---|
| **QUIC handshake flood** — complete a handshake, drop it, repeat | `--l7-method quic-handshake` |
| **QUICLORIS** — hold connections on a request that never finishes | `--l7-method quicloris` |

Worth running separately from their TCP counterparts, because an HTTP/3 endpoint
is usually a *different* code path reached over a *different* protocol, and the
rate limits, connection caps and idle reapers protecting the TCP front door are
frequently absent from the UDP one. Both are `https`-only — there is no plaintext
QUIC — and both speak ALPN `h3`.

`quic-handshake` is `tls-handshake` with the asymmetry made worse: QUIC moves the
crypto *further forward*, so the server parses a ClientHello and signs with its
private key for a client that has proved nothing beyond being able to receive one
round trip. `--max-connections` caps handshakes in flight.

`quicloris` is Slowloris carried to HTTP/3: a real control stream with `SETTINGS`,
then a request stream whose `HEADERS` frame promises far more than ever arrives,
dribbled a byte per `--drip-ms`. The reason it is not just Slowloris again is that
QUIC's equivalent of a request-header read timeout is the **idle timeout** — and a
connection dribbling bytes is never idle, so the budget that retires an abandoned
QUIC connection does not fire on it. `--slow-connections` is the ceiling.

Read the answer split, as with the TLS hellos: **refused** means the peer answered
in QUIC and declined — almost always that the target speaks QUIC but not `h3`,
which is a finding about the endpoint, not about its capacity. **Errors** mean
nothing came back at all. Because a dropped QUIC Initial produces no `ECONNREFUSED`
and no `RST` — just silence — a run that reaches nothing looks exactly like a run
against a filtered path. Read it as "not reached", never as "withstood".

Neither primitive spoofs: jinrai sends from a real, OS-assigned UDP source, which
is what keeps QUIC — the protocol easiest to turn into a reflector — a direct test
here. Retry/token-replay amplification is out of scope by design.

### 6. Volume and buffers (lab) — "what happens at packet scale?"

| Goal | Mode |
|---|---|
| Raw datagram volume | `--l4-mode udp --payload-size 1400` |
| Fill application read buffers over real connections (PSH-ACK data flood) | `--l4-mode data --payload-size 4096` |
| ICMP query handlers (echo / timestamp / address-mask) | `--layer l3 --l4-mode icmp` \| `icmp-timestamp` \| `icmp-address-mask` |
| IP reassembly table (fragmented datagrams the target must hold and rebuild) | `--layer l3 --l4-mode udp-frag` \| `tcp-frag` |
| GRE decapsulation path (IP protocol 47) | `--layer l3 --l4-mode gre` |

### 7. Stateful middlebox behaviour (lab, raw sockets) — "does the firewall/IDS handle this correctly?"

These probe *handling*, not volume: how a connection tracker, IDS or TCP stack
reacts to control flags it should never see.

| Goal | Mode |
|---|---|
| Half-open state exhaustion | `syn` |
| Out-of-state segments — does the tracker create state it shouldn't? | `ack`, `fin`, `rst`, `urg`, `cwr`, `ece` |
| Unsolicited handshake response — a SYN-ACK answering a SYN nobody sent | `syn-ack` |
| Illegal flag combinations (contradictory / all-set / none-set) | `syn-fin`, `syn-rst`, `xmas`, `null` |
| Maximal 40-byte TCP option block on every SYN | `tcp-options` |
| Fragmented datagrams — can it classify what it cannot read without reassembling? | `udp-frag`, `tcp-frag` (add `--port-order random` for the fragmentation + random-ports shape) |
| Encapsulated traffic — does protocol 47 get decapsulated and re-inspected? | `gre` |
| **Several of these at once** (multi-vector) | repeat `--l4-mode` — see [multi-vector runs](#multi-vector-runs) |

## Rate, concurrency, and which knobs apply

The most expensive assumption is that `--rate` always means requests/second and
that every concurrency flag works everywhere. Neither is true: `--rate` is
reinterpreted per family, and a flag belonging to another family is inert
(jinrai warns for the ones that would otherwise change the verdict).

| Family | `--rate` counts | Bound the footprint with | Does **not** read |
|---|---|---|---|
| `get` / `post` / `head` | requests/sec | `--max-connections` (default 1024; `0` = unbounded), `--request-timeout-ms`, `--drain-timeout-ms`, `--follow-redirects` | — |

These three are not independent. A slot is held for an attempt's whole life, so
once attempts run to the timeout only `--max-connections / --request-timeout-ms`
of them can start each second — the stock 1024 over 10s is **102/s**, which is
why `--rate` defaults to 100. Ask for more than the budget carries and the
surplus is never offered: the run measures jinrai's ceiling and the summary
reports it where the target's capacity should be. Worse, it looks fine until the
target starts to struggle, because a target answering in milliseconds recycles a
slot far faster than the timeout does — so the shortfall arrives exactly when the
run was finally measuring something.

jinrai therefore refuses such a run before it sends anything, and prints the two
knobs that fix it:

```
$ jinrai --url https://host/path --rate 2000 --duration 60 ...
error: --rate 2000 cannot be offered with this in-flight budget: 1024 slots over
a 10.0s attempt timeout carry 102/s once attempts run to timeout, ...
  raise the ceiling past 2000/s:
    --request-timeout-ms 512   1024 slots turning over that fast carry 2000/s
    --max-connections 20000    2000/s at the current 10.0s timeout, one descriptor each
    --rate 102                 what this budget already delivers
  --allow-underpowered runs it as asked.
```

`--dry-run` reaches this check, so a command line can be validated without
sending anything. `--allow-underpowered` proceeds anyway, for a run where
holding a fixed slot budget against the target *is* the test.

| `slowloris` / `slowbody` / `slow-read` | **connections opened**/sec | `--slow-connections` (ceiling), `--drip-ms` (tick) | `--slo-*`, `--watchdog`, `--profile`, `--http-version` |
| `websocket` / `sse` | **connections opened**/sec | `--slow-connections` (ceiling), `--drip-ms` (Ping tick, `websocket` only) | same as above |
| `tls-handshake` | handshakes/sec | `--max-connections` (default 1024) | same as above |
| `tls-big-hello` / `tls-sni-bomb` | hellos/sec | `--max-connections` (default 1024) | same as above |
| every `h2-*` | frames/sec (cycles/sec for `h2-made-you-reset`) | *nothing* — one connection, frames paced by `--rate` | same as above |
| `quic-handshake` | handshakes/sec | `--max-connections` (in flight, default 1024) | same as above |
| `quicloris` | **connections opened**/sec | `--slow-connections` (ceiling), `--drip-ms` (dribble tick) | same as above |
| l4 `tcp` | connection attempts/sec | `--concurrency` (open sockets), `--connect-timeout-ms` | `--slo-*`, `--profile` |
| l4 `data` | writes/sec | `--concurrency`, `--payload-size` | same |
| l4 `udp` | datagrams/sec | `--payload-size` (stateless — no footprint to bound) | same |
| l4 raw floods, l3 `icmp*` | packets/sec | *nothing* — stateless | same |
| **multi-vector** (repeated `--l4-mode`) | the **total** across all vectors, split evenly between them | `--concurrency` applies per vector that holds sockets | same as the modes it runs |

Two consequences worth internalising: passing `--slow-connections 500` to an
`h2-*` method changes nothing at all, and for `--l4-mode tcp` the reachable rate
is capped at roughly `--concurrency / RTT` no matter what `--rate` says — see
[the connect flood](#the-connect-flood) for why, and note that the run summary
tells you when that is what happened.

## The cookbook

One complete, runnable command per technique. Copy, swap the allowlist and the
target, run — nothing is implied or omitted.

### L7 — no privilege required, safe to point at staging

```sh
# Every run needs the lab acknowledgement and an audit destination. Kept in one
# variable here so the commands below stay about the technique. Add --dry-run to
# any of them to validate and print the plan without sending.
REQ='--ack-lab --audit-log runs.jsonl'
# The in-flight budget. --max-connections / --request-timeout-ms is the rate still
# reachable once attempts run to the timeout, and the defaults (1024 over 10s) carry
# only 102/s — jinrai refuses a run asking for more than its budget can offer.
BUDGET='--max-connections 8192 --request-timeout-ms 1000'

# Capacity, with a verdict: fails the run (exit != 0) if the target misses the SLO
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/health --rate 200 --duration 60 \
       --slo-max-5xx-rate 0.01 --slo-max-p99-ms 250 $BUDGET

# Write path: POST with a body, cache-busted so a CDN cannot answer for the origin
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method post \
       --url https://api.staging.internal/ingest --body '{"probe":1}' \
       --cache-bust --rate 200 --duration 60 $BUDGET

# Random-path flood: every request asks for a URI that does not exist, so nothing
# is cacheable and the origin answers (and logs) all of it
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://www.staging.internal/ --random-path --rate 500 --duration 60 $BUDGET

# Valid-random flood: same idea, but drawn from endpoints that DO exist, so the
# load lands on real handlers rather than the 404 path
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/ --path-file endpoints.txt \
       --rate 500 --duration 60 $BUDGET

# Search-field flood + session exhaustion: a fresh term AND a fresh session per
# request — neither the cache nor the session store can absorb any of it
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://www.staging.internal/search --search-param q \
       --session-cookie JSESSIONID --rate 500 --duration 120 $BUDGET

# Breaking point: ramp to the ceiling, stop at the first stage that breaks the SLO
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/health --rate 5000 --duration 300 \
       --profile ramp --ramp-start 100 --ramp-steps 20 \
       --discover-knee --slo-max-5xx-rate 0.01 $BUDGET

# Burst: hold a baseline, jump to the ceiling for 30s, fall back (autoscaling test)
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/health --rate 2000 --duration 300 \
       --profile spike --spike-base 200 --spike-secs 30 $BUDGET

# Endurance: a long flat hold that surfaces leaks and slow degradation
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/health --rate 300 --duration 3600 \
       --profile soak --slo-max-p99-ms 500 --watchdog --slo-max-error-rate 0.05 $BUDGET

# Same load over a pinned protocol version (auto would negotiate h2 on https)
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/health --http-version 1.1 \
       --rate 200 --duration 60 $BUDGET

# Connection-slot exhaustion: at most 50 keep-alive connections held busy
# (the controlled form of GoldenEye/XerXes)
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/ --max-connections 50 \
       --cache-bust --rate 1000 --duration 60 --allow-underpowered

# Slowloris: 200 half-open connections, one header line each every 10s
#   swap --l7-method for slowbody (trickled POST body, RUDY)
#   or for slow-read (complete request, response drained one chunk per tick)
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method slowloris \
       --url https://api.staging.internal/ --slow-connections 200 \
       --drip-ms 10000 --rate 50 --duration 300

# WebSocket session exhaustion: 500 correctly-upgraded sessions, held for the
# whole run, kept alive with an empty Ping every 15s. Swap the method for `sse`
# to do the same with an event-stream (which needs no keep-alive at all).
# NOTE: https:// is how you say wss:// — the upgrade IS an HTTP/1.1 request.
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method websocket \
       --url https://api.staging.internal/ws --slow-connections 500 \
       --drip-ms 15000 --rate 100 --duration 300

# TLS handshake flood (THC-SSL-DoS): full handshake, immediate drop, repeat
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method tls-handshake \
       --url https://api.staging.internal/ --rate 200 --duration 60

# TLS ClientHello parser stress: 16 KiB of well-formed hello, no handshake.
# Swap for tls-sni-bomb to spend the same connection on the SNI alone.
# Read the "of which" line, not the completion count: `parsed` means the target
# did the work, `refused with an alert` is the healthy answer.
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method tls-big-hello \
       --url https://api.staging.internal/ --rate 200 --duration 60

# QUIC handshake flood: the same asymmetry as tls-handshake, over UDP and one
# step earlier — the server signs before the client has proved anything. Worth
# running even when tls-handshake was fine: the HTTP/3 listener is usually a
# different code path, and often the one without the rate limit.
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method quic-handshake \
       --url https://api.staging.internal/ --rate 200 --duration 60

# QUICLORIS: 300 HTTP/3 connections, each holding one request stream whose
# HEADERS frame never finishes, a byte every 10s. Nothing is malformed, and a
# dribbling connection is never idle — so the QUIC idle timeout does not retire
# it. If all 300 hold for the whole run with no errors, nothing else does either.
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method quicloris \
       --url https://api.staging.internal/ --slow-connections 300 \
       --drip-ms 10000 --rate 50 --duration 300

# HTTP/2 rapid reset (CVE-2023-44487). Every h2-* method takes this exact shape;
# only the method name changes:
#   h2-rapid-reset  h2-made-you-reset  h2-continuation  h2-bomb
#   h2-settings     h2-ping            h2-window-update h2-priority  h2-empty-data
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method h2-rapid-reset \
       --url https://api.staging.internal/ --rate 500 --duration 60

# Header-profile test (User-Agent, Cookie, Referer, …): --header is repeatable
jinrai $REQ --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/ --header 'User-Agent: jinrai/probe' \
       --header 'Cookie: session=x' --rate 100 --duration 30
```

### L3/L4 — isolated lab only

```sh
# As above: every run needs the acknowledgement and a trail.
REQ='--ack-lab --audit-log runs.jsonl'

# UDP datagram flood — no privilege needed
jinrai $REQ --layer l4 --l4-mode udp --allow 10.0.0.0/8 --target 10.1.2.3 --port 9 \
       --payload-size 1400 --rate 1000 --duration 30

# TCP connect flood: real handshakes held open against the accept backlog.
# --concurrency is both the local footprint AND the parallelism; no privilege needed
jinrai $REQ --layer l4 --l4-mode tcp --allow 10.0.0.0/8 --target 10.1.2.3 --port 443 \
       --rate 5000 --duration 60 \
       --concurrency 512 --connect-timeout-ms 500

# PSH-ACK data flood: real connections filled with application data
jinrai $REQ --layer l4 --l4-mode data --allow 10.0.0.0/8 --target 10.1.2.3 --port 80 \
       --payload-size 4096 --concurrency 256 --rate 500 --duration 30

# Raw SYN flood — needs CAP_NET_RAW/root, IPv4 only. Same shape for every raw
# flag flood; only --l4-mode changes:
#   syn  ack  fin  rst  urg  cwr  ece          (one flag each)
#   syn-ack                                    (unsolicited handshake response)
#   syn-fin  syn-rst  xmas  null               (illegal combinations)
#   tcp-options                                (SYN + maximal 40-byte option block)
sudo -E jinrai $REQ --layer l4 --l4-mode syn --allow 10.0.0.0/8 --target 10.1.2.3 \
       --port 80 --rate 5000 --duration 30

# ICMP query flood — portless, needs CAP_NET_RAW/root. Swap --l4-mode for
# icmp-timestamp (type 13) or icmp-address-mask (type 17)
sudo -E jinrai $REQ --layer l3 --l4-mode icmp --allow 10.0.0.0/8 --target 10.1.2.3 \
       --rate 1000 --duration 30

# IP fragmentation flood over random ports — each unit is one datagram the target
# must hold and reassemble before it can even read the port. --rate counts
# datagrams; udp-frag puts 2 packets on the wire per unit, tcp-frag 3, and the
# summary says which. Swap udp-frag for tcp-frag to fragment a SYN instead.
sudo -E jinrai $REQ --layer l3 --l4-mode udp-frag --allow 10.0.0.0/8 --target 10.1.2.3 \
       --port 20000-20999 --port-order random --payload-size 1400 \
       --rate 5000 --duration 30

# GRE flood (IP protocol 47) — packets wrapping a real IPv4/UDP datagram, so a
# target that accepts protocol 47 has to decapsulate and re-enter its IP stack
# once per packet. --port sets the encapsulated destination port.
sudo -E jinrai $REQ --layer l3 --l4-mode gre --allow 10.0.0.0/8 --target 10.1.2.3 \
       --port 4789 --rate 5000 --duration 30

# Multi-vector: repeat --l4-mode and they run at the same time, splitting the one
# --rate ceiling between them (here 10000/s each, not 30000/s each)
sudo -E jinrai $REQ --layer l4 --allow 10.0.0.0/8 \
       --target 10.1.2.3 --target 10.1.2.4 \
       --l4-mode udp --l4-mode syn --l4-mode icmp \
       --port 20000-20999 --port-order random --rate 30000 --duration 60
```

`sudo -E` preserves `$JINRAI_OPERATOR` so [the audit log](#the-audit-log) still
records who ran it.

## Your first four runs

Order matters more than the individual commands. Do these in sequence against a
new target:

0. **Prove the command line** without sending anything. `--dry-run` walks the
   whole refusable path — allowlist, gate, preflight — and prints the run it was
   about to start.
   ```sh
   jinrai --layer l7 --allow '*.staging.internal' --dry-run \
          --url https://api.staging.internal/health --rate 10 --duration 5
   ```
1. **Prove the gate and the path** with trivial load. If the allowlist or the
   URL is wrong, this refuses instead of sending — which is the whole point of
   run #1.
   ```sh
   jinrai --layer l7 --allow '*.staging.internal' --ack-lab --audit-log runs.jsonl \
          --url https://api.staging.internal/health --rate 10 --duration 5
   ```
2. **Get a verdict at steady state** — the first cookbook command. Now you know
   the target's behaviour under load you have chosen, and the run passes or
   fails on its own.
3. **Find the capacity knee** — the `--discover-knee` command. Now you know the
   load you *cannot* choose. Finding the knee is a success (exit 0).
4. **Let it stop itself** — repeat the run that mattered with `--watchdog`, so a
   target that starts failing ends the run instead of enduring it. The trail is
   already there: [`--audit-log`](#the-audit-log) is required on every run.

## Choosing numbers safely

* **`--rate` is a ceiling, not a target.** No profile ever exceeds it. Start an
  order of magnitude below the capacity you expect and ramp — `--discover-knee`
  exists so you do not have to guess twice.
* **Concurrency is your own footprint.** `--concurrency` / `--slow-connections` /
  `--max-connections` bound the sockets held open *by jinrai*, independently of
  `--duration`. Doubling the duration does not double the footprint.
* **`--duration` bounds the traffic, not just the dispatching of it.** Dispatch
  stops at the deadline; requests still in flight then get `--drain-timeout-ms`
  (default 1000) to land, and whatever is still outstanding is cancelled and
  counted in the `abandoned` bucket. So a run cannot keep generating traffic past
  its declared window while waiting for a slow target to answer.
* **`--watchdog` is the automatic brake**: it aborts the run after
  `--watchdog-breaches` consecutive breaching windows. It can only ever *stop*
  traffic, never generate it. Use it on anything long or unattended.
* **Ctrl-C is the manual brake** — it trips the same kill-switch, and no target
  can be authorized once it is tripped. It is also *prompt*: workers stop within
  ~50ms and the connect pool stops draining after 250ms, whatever
  `--connect-timeout-ms` says. Handshakes still outstanding at that point are
  reported in the `abandoned` bucket rather than waited out, so a fast exit never
  costs you the accounting. jinrai refuses to start at all if it could not
  install the signal handler.
* **If the summary says the run fell short of the rate cap, believe it.** A test
  that never produced the load it promised is not evidence that the target
  coped.

## Reading the result

Every run ends with a summary block that states the offered load, what came back,
and what it means. `--output line` switches to the single machine-friendly line
instead (stable for scripts and log scraping):

```
==== run summary =========================================================
 target     https://api.staging.internal/health
 module     L7 / l7-http-get  (HTTP/1.1 forced)
 window     30.0s elapsed of 30.0s planned, rate cap 200/s
 started    2026-07-10T09:14:02Z
 finished   2026-07-10T09:14:32Z
 attempts   6000 total, 199.4/s achieved (100% of the 200/s cap)
 completed  5994 (99.9%)
   status   2xx 5900 (98.4%)   3xx 0 (0.0%)   4xx 40 (0.7%)   5xx 54 (0.9%)
   of which 200 x5900   503 x54   429 x37   400 x3
   protocol HTTP/1.1 5994
 failed     6 (0.1%), of which 6 timed out
            6 x timeout — our own attempt timeout expired first
 latency    p50 12.4ms   p90 45.1ms   p99 210.0ms   max 1.20s
 outcome    ran to completion
 SLO        FAIL (5xx-rate 0.9% > 0.5%)
==========================================================================
```

On a terminal the block is coloured, in three senses only: **green** = the run
did what it set out to do (`completed`, `failed 0`, `2xx`, `SLO: PASS`, `ran to
completion`), **yellow** = a caveat about *our* side (`bound by`, `not sent`,
a local errno ceiling, an operator abort, `4xx`), **red** = failure and the
target's own errors (`failed`, `5xx`, a remote errno, `SLO: FAIL`, a watchdog
abort, the hollow-run `WARNING`). `--color auto|always|never` controls it;
`auto` paints only when stdout is a terminal and `NO_COLOR` is unset, so a
redirected report is exactly the plain block above.

Six things the block is there to make unmissable:

* **Which status codes, not just which classes** — `4xx 40` is three different
  findings depending on whether those were `400`s (the request *jinrai* sent was
  malformed, so the run measured nothing), `401`/`403`s (the target behaving
  normally) or `429`s (the rate limiter engaged — usually the result the run went
  looking for). The `of which` row names them, ranked by count, and the audit log
  records them under `status_codes` so the question is still answerable months
  later. An all-`2xx` run gets no row: it would only repeat the class.

* **When the run happened** — `started` / `finished` (RFC 3339 UTC) bracket the
  window, so the block can be lined up against the target's own logs, graphs and
  alerts without reconstructing the clock time from `elapsed`.
* **Offered vs. achieved load** — `attempts … achieved (…% of the cap)` says
  whether the tool actually produced the load that was asked for, so a result is
  never read as "the target coped" when the generator never reached the rate.
* **Why it fell short, when it did** — a low percentage with **zero failures** is
  the single most misreadable line the tool can print: it looks exactly like a
  target absorbing the difference. So when the run did not reach its cap, a
  `bound by` line names the constraint rather than leaving the percentage to be
  guessed at. See [when the run falls short of its cap](#when-the-run-falls-short-of-its-cap).
* **Whose failure it was** — L7 failures are bucketed like the L3/L4 ones:
  `ECONNREFUSED` (the target refused), `timeout` (nobody answered),
  `protocol` (the exchange failed above the socket — typically a forced
  `--http-version` the target does not speak), `EMFILE`/`EADDRNOTAVAIL` (a local
  ceiling on the *testing* host, saying nothing about the target).
* **A run that tested nothing** — 0 completions with only failures prints an
  explicit warning **and exits non-zero**, so "6000 attempts, 0 responses" can no
  longer be mistaken for a successful test in a pipeline.

### When the run falls short of its cap

`--rate` is a ceiling, and a run reaching only part of it is normal. What matters
is *why*, because two of the three reasons say nothing at all about the target:

```
 attempts   86335 total, 28769.5/s achieved (14% of the 200000/s cap)
 failed     0
 bound by   the generator, not the target: nothing failed and there was no
            in-flight ceiling, so 28769/s is what this host could emit — the
            shortfall against the 200000/s cap is jinrai's own limit, NOT load
            the target absorbed. Treat 28769/s as the load actually offered
```

| `bound by` says | what it means | what to do |
| --- | --- | --- |
| `concurrency, not the target` | the in-flight ceiling made the cap unreachable: `--concurrency / RTT` lands below `--rate` (Little's law) | shorten `--request-timeout-ms` before raising `--max-connections` — a failing attempt holds its slot for the whole timeout, so the timeout usually buys more offered load than slots do. For `get`/`post`/`head` this is now refused up front (see below), so it should only appear on an `--allow-underpowered` run |
| `the generator, not the target` | this host could not emit any faster — nothing failed and no ceiling applied | treat the achieved rate as the real offered load; run from more hosts if you need more |
| *(nothing printed)* | the run had the headroom and still fell short, or it got within 90% of the cap | **this one is about the target** — read it as a finding |

The generator note is deliberately narrow: it appears only when nothing failed,
no in-flight ceiling applied, and the run ran to completion — with any failure on
the board the errno breakdown is the story instead.

**Where the ceiling actually is.** On a modern host the stateless floods sustain
roughly **half a million packets/second**, bounded by the cost of one send
syscall per packet; the fast L7 flood holds its cap to around **20 000
requests/second** before the sockets, not the pacer, become the limit. Both are
well beyond what a lab test normally needs, so if a run reports `bound by the
generator` at a rate below those figures, look for a local cause first — a busy
testing host, a tiny `--payload-size` inflating the syscall count, or a `--rate`
set higher than the exercise actually calls for.

## The audit log

An accountable, hash-chained trail of every run — who authorized what, against
which allowlist, and with what outcome. **Required**: a run with neither
`--audit-log` nor an explicit `--no-audit` is refused, because a trail that can
be skipped by omission is one that goes missing exactly when it matters. The log
is opened before any traffic and a write failure aborts the run, so traffic can
never outrun its own record. Only one jinrai process may write to a given log at
a time — concurrent writers would fork the hash chain.

```sh
export JINRAI_OPERATOR="you@example.com"          # else falls back to the OS user
jinrai --layer l4 --l4-mode udp --allow 10.0.0.0/8 --target 10.1.2.3 \
       --port 9 --ack-lab --rate 1000 --duration 10 \
       --audit-log runs.jsonl

jinrai --verify-audit runs.jsonl                 # 0 = chain intact, non-zero = tampered
```

`--verify-audit` verifies **and prints** the log, one readable line per record:

```
audit log runs.jsonl
hash chain: INTACT (2 record(s))

  #0    2026-07-30T15:00:17Z  you@example.com   AUTHORIZED L7/l7-http-get at up to 60/s for 3s -> api.staging.internal [allowed by: *.staging.internal]
  #1    2026-07-30T15:00:20Z  you@example.com   COMPLETED L7 l7-http-get https://api.staging.internal/ (HTTP/1.1 forced) — 180 attempts: 180 completed, 0 failed; status 2xx=180 3xx=0 4xx=0 5xx=0; proto HTTP/1.1=180; p99 45247us; SLO PASS
```

The log is append-only JSONL with a SHA-256 hash chain: editing, deleting, or
reordering any record is detectable. The log is opened before any traffic and a
write failure aborts the run, so traffic never outruns its own record. Each record
carries both the structured fields (`attempts`, `status`, `errno`,
`http_versions`, `latency_us`, `slo` — greppable / `jq`-able) and the
human-readable `summary` line printed above; the summary is inside the hashed
body, so it cannot be edited to disagree with the numbers beside it.

## What jinrai will not do

There is **no source-IP spoofing** anywhere: every crafted packet carries the
host's real, OS-routed source address. There is no reflection or amplification
through third parties, and the ICMP modes send only *query* messages the target
answers itself — never forged errors, redirects or router messages. A target
outside every `--allow` rule aborts the entire run. Those techniques exist to
hide the sender or to borrow someone else's bandwidth; a test of your own
infrastructure needs neither.

This is the line the QUIC primitives sit closest to, so it is worth stating
twice: `quic-handshake` and `quicloris` send from a real, OS-assigned UDP source
on an ordinary client socket. There is no source-address option in that code
path, which is the whole difference between a QUIC load test and a QUIC
reflector — every amplification variant needs a spoofed Initial. QUIC Retry /
token-replay amplification and reflection via the certificate exchange are out of
scope by design, not merely unimplemented.

---

# Part II — Reference

Everything below explains *why* a flag behaves the way it does. For the commands
themselves, [the cookbook](#the-cookbook) is complete; `jinrai --help` is always
current.

## L7 reference

The `--url` host is validated as a *datum* against its own rule type — an
IP-literal host against the CIDR rules, a DNS-name host against the DNS rules —
and only then resolved once and pinned. A name is never resolved-then-IP-checked.

**Redirects are not followed off the authorized origin.** Pinning the connect
address is only worth something if the client cannot be talked into connecting
elsewhere, and a `3xx` with a `Location:` on another host is exactly that: the
*target* choosing where your traffic and your `--header` values go next. Such a
redirect is counted as the response it is (`3xx` in the summary) and the run
stays on the host the gate authorized — at every setting of
[`--follow-redirects`](#what-the-client-looks-like-user-agent-and-redirects),
which relaxes how far the client walks on the approved origin, never which
origin it walks on.

### The L7 methods

`--l7-method` selects the request primitive (default `get`). For what each one
counts as a unit of `--rate`, see
[the knob table](#rate-concurrency-and-which-knobs-apply).

| Method | Kind | Mechanism |
|---|---|---|
| `get` / `post` / `head` | fast, constant-rate | `--body` sets the POST body; `--cache-bust` appends a unique `_cb=<n>` query per request (query only — never the host); `--max-connections <N>` caps concurrent connections (and must be able to carry `--rate` — see [the knob table](#rate-concurrency-and-which-knobs-apply), or `--allow-underpowered` to waive it); `--http-version <auto\|1.1\|2>` pins the protocol version |
| `slowloris` | slow connection | partial request headers, never terminated |
| `slowbody` | slow connection | oversized `Content-Length`, body trickled a byte at a time (RUDY) |
| `slow-read` | slow connection | send a *complete* request, then drain the response one small chunk per tick with a shrunken receive window (`SO_RCVBUF`) so the server cannot flush it — the read-side mirror of `slowbody` |
| `tls-handshake` | TLS | full TLS handshake then drop, repeated concurrently (THC-SSL-DoS); https-only |
| `h2-rapid-reset` | HTTP/2 | open a stream, immediately `RST_STREAM` (CVE-2023-44487) |
| `h2-continuation` | HTTP/2 | HEADERS without `END_HEADERS` + endless `CONTINUATION` frames (CVE-2024-27316) |
| `h2-settings` | HTTP/2 | flood empty `SETTINGS` frames the server must ACK (CVE-2019-9515) |
| `h2-ping` | HTTP/2 | flood `PING` frames the server must answer with a PONG (CVE-2019-9512) |
| `h2-window-update` | HTTP/2 | flood connection-level `WINDOW_UPDATE` frames the server must process (CVE-2019-9514) |
| `h2-priority` | HTTP/2 | flood `PRIORITY` frames that reshuffle the server's priority tree (CVE-2019-9513, "Resource Loop") |
| `h2-made-you-reset` | HTTP/2 | complete request then a zero-increment `WINDOW_UPDATE` so the **server** resets the stream (CVE-2025-8671, "MadeYouReset") — evades Rapid-Reset mitigations |
| `h2-empty-data` | HTTP/2 | open a stream, then flood zero-length `DATA` frames without `END_STREAM` (CVE-2019-9518) |
| `h2-bomb` | HTTP/2 | HPACK 1-byte-reference header amplification + `INITIAL_WINDOW_SIZE=0` so the amplified memory stays pinned (CVE-2026-49975, "HTTP/2 Bomb") |
| `websocket` | long-lived transport | complete the RFC 6455 upgrade, then hold the session open with a masked empty `Ping` every `--drip-ms`. Nothing is slow or malformed, so no header/body read timeout applies |
| `sse` | long-lived transport | a normal `Accept: text/event-stream` GET, held open and drained — the server keeps it open by design |
| `tls-big-hello` | TLS parser | one well-formed ClientHello inflated to the 16 KiB record ceiling: a 2048-entry cipher-suite list the server must intersect against its own, padded out with the RFC 7685 `padding` extension. No handshake is completed; https-only |
| `tls-sni-bomb` | TLS parser | the same connection budget spent on the SNI alone: a ~12 KiB `server_name` built from legal ≤63-byte DNS labels, so it survives syntax validation and reaches the virtual-host lookup (and whatever logs the name on rejection); https-only |
| `quic-handshake` | QUIC | complete a full QUIC handshake, drop it, repeat concurrently — the TLS-handshake asymmetry moved forward, since the server parses a ClientHello and signs for a client that has proved only that it can receive one round trip; https-only, ALPN `h3` |
| `quicloris` | QUIC | hold HTTP/3 connections, each carrying a proper control stream with `SETTINGS` and one request stream whose `HEADERS` frame promises 4 KiB and delivers a byte per `--drip-ms`. A dribbling connection is never idle, so QUIC's idle timeout — the budget that retires an abandoned connection — never fires; https-only, ALPN `h3` |

The slow modes and the long-lived transports support https targets (the handshake
accepts any server certificate); `websocket` and `sse` pin ALPN to `http/1.1`, so
a target that also offers h2 cannot negotiate a protocol the upgrade could not run
over. All the `h2-*` primitives negotiate h2 via ALPN for `https` and
prior-knowledge h2c for `http`.

### Request shaping — when every request must differ

The fast flood sends one identical request N times. That measures a single
endpoint's ceiling, and it is the wrong shape for four floods that are asked for
by name. All four are the same primitive — vary the request per unit — and all
four apply to `get`/`post`/`head` only:

| flag | flood | what the target has to do |
| --- | --- | --- |
| `--cache-bust` | upstream jamming | a unique `_cb=<n>` query, so a CDN/cache cannot serve a stored response and every request reaches the origin |
| `--random-path` | random-path flood | a fresh random path segment per request, so every URI is one that does not exist: nothing is cacheable, and the origin generates (and usually logs) a 404 for all of it |
| `--path-file <PATH>` | valid-random flood | draw the path from a list of endpoints that *do* exist, so the load lands on real handlers instead of the 404 path |
| `--search-param <NAME>` | search-field flood | a fresh random term as `NAME=<term>` — the one query a cache can never serve and a backend can rarely index its way out of. Query for `get`/`head`, form-encoded body for `post` (where it replaces `--body`) |
| `--session-cookie <NAME>` | session exhaustion | a distinct, unrecognised `NAME=<value>` cookie per request, so the target allocates or looks up session state for each one rather than reusing a single session for the whole run |

They compose. Session exhaustion against a search endpoint, with nothing
cacheable anywhere in it:

```bash
jinrai $REQ --url https://staging.internal/search --allow '*.staging.internal' \
       --search-param q --session-cookie JSESSIONID --cache-bust \
       --max-connections 4096 --request-timeout-ms 4000 \
       --rate 500 --duration 120 --slo-max-p99-ms 2000
```

A path list is one path per line; `#` comments and blank lines are skipped:

```
# checkout flow
/api/cart
/api/cart/items?limit=50
/api/checkout/summary
```

**Only the path, query, body and cookie are ever touched — never the host.** The
authorization and the pinned DNS resolution are properties of the origin, so a
variation that could move the origin would void both. For generated paths that
holds by construction. For a `--path-file` it does not, so every entry is joined
against the authorized URL and checked to land on the same origin **before the
run starts**; an entry that would move it **refuses the run** rather than being
skipped at request time. The syntax rule (`/` start, no `//`) is the first gate,
the joined-origin check is the one that does not depend on out-guessing URL
normalisation.

The run summary and `--dry-run` both name what varied, so a run with a 100% 4xx
rate reads as the random-path flood it was rather than a target problem.

### Timeouts and the end of the run

Two flags bound the fast `get`/`post`/`head` flood in time, and they answer
different questions:

| flag | default | bounds |
| --- | --- | --- |
| `--request-timeout-ms` | 10000 | how long **one request** may stay unresolved before it is given up on and counted in the `timeout` bucket |
| `--drain-timeout-ms` | 1000 | how long the **run** waits for requests still in flight once `--duration` expires, before cancelling them |

The second one exists because `--duration` has to bound the traffic, not merely
the dispatching of it. Dispatch stops at the deadline either way — but requests
already on the wire have not resolved, and waiting all of them out makes the
real window `--duration + --request-timeout-ms`. With the defaults that is a
three-second run that keeps generating traffic for thirteen seconds: a window the
operator never declared, and one the audit log records as three seconds.

So the tail is bounded. Whatever is still outstanding after the grace period is
cancelled and counted in the **`abandoned`** bucket — never silently dropped,
which would understate the offered load and flatter the target:

```
 failed     12172 (86.1%)
            12172 x abandoned — still in flight when the run's window closed
```

A non-zero `abandoned` count means the target was answering more slowly than the
load being offered. The fix is a longer `--duration` or a lower `--rate` — not a
longer `--request-timeout-ms`, which is why the bucket is kept separate from
`timeout`. `--max-connections` prevents the pile-up at its source by capping how
many requests can be in flight at once. An operator Ctrl-C or a watchdog abort
skips the grace entirely and cancels immediately: an abort must be prompt.

### What the client looks like: `User-Agent`, body type, redirects

Three properties of the request decide whether a run measures the target or the
appliance in front of it. All three have bitten the same way: the summary reports
a status class you cannot reproduce in a browser against the same URL, and
nothing in the run says why.

**Every request carries `User-Agent: jinrai/<version>`.** Sending no
`User-Agent` at all is not the neutral choice it looks like — WAFs, CDNs and bot
filters answer a headerless request differently from the same request carrying
*any* UA, typically with a challenge or a redirect. Identifying the tool is also
the honest default for a load generator pointed at authorized infrastructure.
`--header "User-Agent: ..."` replaces it when the point of the test is a
specific client profile; the default is a default, not a policy.

**`--body` is sent verbatim, with no `Content-Type` of its own.** Guessing one
from the bytes would put a header on the wire you never wrote, so jinrai does
not — but a target that cannot tell what the body *is* rejects it (`415`/`400`)
or ignores it, and either way the parsing, validation and persistence cost you
meant to measure is never paid. The `4xx` that comes back then reads as a finding
about the target instead of a broken request. jinrai warns when `--body` arrives
without the header; pair them:

```sh
--body '{"q":"load"}' --header 'Content-Type: application/json'
```

**A redirect is counted, not followed — unless you ask for it.**

| `--follow-redirects` | what a status class in the summary means |
| --- | --- |
| `0` (default) | the status of the **first** response. A target that answers `302` to a login page reports `3xx 100%`, even though a browser would end on the `404` two hops later |
| `N > 0` | the status at the **end** of the chain, for up to `N` same-origin hops |

Same-origin is the whole safety story: the hop is taken only when the
`Location:` still names the host, port and scheme the gate approved — the origin
the DNS pin already covers and the `--header` values already belong to. Anything
else stops the chain and reports the `3xx`, at every value of `N`. The peer
never chooses where the client connects.

The cost is real and belongs to you, which is why it is opt-in: **a followed hop
is a second request `--rate` never counted.** With `N` hops available a run can
put up to `(1 + N) x --rate` requests/sec on the target. The rate cap still
bounds what jinrai *dispatches*; it no longer bounds what the target receives.
The summary says so — `following up to 3 same-origin redirects` in the module
line — because `attempts` otherwise quietly stops meaning "requests the target
saw". Keep `N` at the length of the chain you actually expect (usually `1`), and
prefer pointing `--url` at the final URL when you know it.

### When the summary raises a question it cannot answer (`--debug`)

The end-of-run block is the report, and it is deliberately a report: aggregated,
bounded, the same shape every time. `--debug` is what you turn on when it left
you with a question — narration on **stderr**, so `--output line` on stdout stays
exactly as scriptable as it was.

Three things, in the three places a question actually gets asked.

**Before — the request as composed.** "What am I actually sending" had no answer
short of a packet capture. The header map with jinrai's own defaults merged in,
and the single pinned resolution the whole run is bound to, exist only inside the
engine, so this is where they can be shown:

```
---- debug: the request as composed ----
  method     POST
  url        https://api.staging.internal/web/client/login
  resolved   10.0.0.10:443 (pinned for the whole run)
  varying    cache-bust (the url above is the base)
  header     user-agent: jinrai/0.44.0
  header     content-type: application/json
  body       12 bytes, type: application/json
  policies   http negotiated (ALPN for https), redirects counted, never followed,
             request timeout 10s, in flight 1024
----------------------------------------
```

A `body ... type: NONE — the target cannot tell what this is` here is the whole
diagnosis of a POST flood that reported 4xx and tested nothing.

**During — one line a second.** A sixty-second run printed nothing at all until
it was over, so neither "is it doing anything" nor "when did it start failing"
could be answered from outside. The rate in brackets is the **last second**, not
the cumulative average, because that is what shows a target degrading mid-run:

```
  debug   1.0s  attempts 100 (100/s)  2xx 86 3xx 0 4xx 14 5xx 0  failed 0
  debug   2.0s  attempts 200 (100/s)  2xx 172 3xx 0 4xx 28 5xx 0  failed 0
```

**After — the sentence behind each errno bucket.** `4 x internal` names a
category; the text underneath names the cause, and it was being discarded at
classification time:

```
   debug    distinct failure messages, most frequent first:
            300 x  error sending request for url (<url>): client error (Connect):
            tcp connect error: Connection refused (os error 111)
```

The URL is replaced with a placeholder because it varies per request — with
`--cache-bust` or `--random-path` every message would otherwise be unique and the
sample would degenerate into a list of URLs. The sample is capped at 16 distinct
messages, with the overflow counted rather than dropped: the text is chosen by
the thing being tested, so it is not given an unbounded map. For the same reason
it never reaches the audit log, which stays a bounded, hash-chained record.

What `--debug` deliberately is **not** is per-request logging. At the rates this
engine dispatches, a line per request is not a log anyone reads — it is a second
workload competing with the one under test, and it would change the measurement
it exists to explain. Everything above is once, once a second, or aggregated.

It applies to the fast `get`/`post`/`head` flood; the other methods build their
own frames and report through the summary alone, and say so rather than leaving
you waiting for output that is not coming.

### HTTP/1.1 vs HTTP/2 (`--http-version`)

For the fast `get`/`post`/`head` methods the protocol version is the operator's
choice, not the server's. The default (`auto`) negotiates — plain HTTP/1.1 for an
`http://` URL, but ALPN for `https://`, which means **an https target that offers
h2 is tested over HTTP/2**. That is a different test (multiplexed streams instead
of one request per connection, HPACK instead of plain headers, different
server-side limits), so it has to be selectable.

Forcing `2` deliberately does **not** fall back: a target that cannot do h2 fails
every request and the run says so (`protocol` failure bucket, non-zero exit)
rather than silently downgrading to HTTP/1.1 and reporting a clean pass. Whatever
is selected, the run summary reports the version the responses *actually* arrived
on — the only way to notice that an "HTTP/1.1" run was negotiated up to h2. The
slow modes are HTTP/1.1 by construction and the `h2-*` methods are HTTP/2 by
construction, so the flag does not apply to them (it warns and is ignored).

### SLO verdict & health-watchdog

Fast L7 methods only. Every response is classified by status class, so the tool
can tell a healthy target from one that is answering but failing. Declare an SLO
(`--slo-max-error-rate`, `--slo-max-5xx-rate`, `--slo-max-4xx-rate`,
`--slo-max-p99-ms`) and the run prints a `PASS`/`FAIL` verdict and exits non-zero
when the target misses it — a `500`/`429` flood no longer reports a hollow
"success".

`--watchdog` auto-aborts (kill-switch) once a *rate* SLO is breached for
`--watchdog-breaches` consecutive `--watchdog-window`s. The watchdog can only
ever stop traffic, never generate it, and it is inert without at least one
`--slo-max-*-rate` to watch.

## L3/L4 reference

Requires raw target IPs matching a CIDR `--allow` and a `--port` (a single port,
a list, or a range — except for the ICMP modes, which are portless), on top of
the `--ack-lab` acknowledgement every layer needs. `udp`/`tcp`/`data` need
no privilege, and `tcp`/`data` work over IPv4 **and** IPv6; the raw-socket modes
(`syn`/`ack`/`fin`/`rst`/`urg`/`cwr`/`ece`/`syn-ack`/`syn-fin`/`syn-rst`/`xmas`/
`null`/`tcp-options`/`udp-frag`/`tcp-frag`/`gre`/`icmp`/`icmp-timestamp`/
`icmp-address-mask`) need `CAP_NET_RAW`/root and are IPv4-only.

### Random ports and carpet bombing

`--port` takes a **set**, not just a number: a single port (`443`), a comma list
(`80,443,8080`), an inclusive range (`1000-2000`), or a mix (`80,8000-8100`).
Port 0 is refused. `--port-order` decides how a run walks it:

| order | behaviour |
| --- | --- |
| `sequential` (default) | walk the set in the order written, advancing once per pass over the targets, so the run enumerates the whole target × port cross-product. Deterministic; for a single port it is exactly what earlier releases did |
| `random` | draw a port per packet — consecutive packets are unrelated, so a rule keyed on one port sees a trickle rather than the run |

This is what a test plan means by a **random-port flood**: most of the range has
no listener, so the target has to generate a refusal per packet (RST, or an ICMP
port-unreachable) and track a flow that goes nowhere, and a per-port rule no
longer sees the whole run.

Combine it with a repeated `--target` and it is **carpet bombing** — load spread
across several destination addresses *and* several ports at once, so no single
address/port pair looks like an attack on its own:

```bash
# UDP carpet bombing: 3 targets, 1000 ports, drawn at random per packet
jinrai $REQ --layer l4 --l4-mode udp --allow 10.0.0.0/8 \
       --target 10.1.2.3 --target 10.1.2.4 --target 10.1.2.5 \
       --port 20000-20999 --port-order random --rate 20000 --duration 60

# TCP carpet bombing: same shape, SYNs instead of datagrams (needs CAP_NET_RAW)
sudo -E jinrai $REQ --layer l4 --l4-mode syn --allow 10.0.0.0/8 \
       --target 10.1.2.3 --target 10.1.2.4 \
       --port 1-65535 --port-order random --rate 50000 --duration 60
```

Only the **destination** port varies. The source address is never spoofed and the
source port stays deterministic — source-port randomisation is the neighbouring
move that makes flows unattributable, and it is deliberately absent for the same
reason source-IP spoofing is.

### Multi-vector runs

`--l4-mode` is repeatable. Give it more than once and the primitives run
**concurrently** against the same targets, in one run:

```bash
# UDP + TCP + ICMP at once, over a random port range, across two targets
sudo -E jinrai $REQ --layer l4 --allow 10.0.0.0/8 \
       --target 10.1.2.3 --target 10.1.2.4 \
       --l4-mode udp --l4-mode syn --l4-mode icmp \
       --port 20000-20999 --port-order random --rate 30000 --duration 60
```

Each vector gets its own thread, its own socket state and its own send loop, so
a `data` write blocking on a full buffer cannot set the pace for the packet
floods next to it. They share everything that bounds the run: one `--duration`,
one kill-switch (Ctrl-C and the watchdog stop all of them), one audit record, one
summary.

**They also share `--rate`, and that is the point.** The ceiling is split evenly
between the vectors — three vectors at `--rate 6000` emit 2000/s *each*, not
6000/s each. A per-vector ceiling would make `--rate` mean `--rate` × the vector
count, so the number the operator typed, acknowledged and had written to the
audit log would be a fraction of the traffic actually sent, and a safety ceiling
that multiplies behind your back is not a ceiling. A `--rate` too small to split
(fewer units/s than vectors) is refused rather than silently rounding a vector to
zero.

The summary reports the total and a per-vector breakdown, because one total
cannot tell "both vectors landed" from "one did all the work":

```
 attempts   2000 total, 993.7/s achieved (99% of the 1000/s cap)
 completed  1000 (50.0%)
   of which udp-flood 1000 sent / 0 failed at 500/s; tcp-connect-flood 0
            sent / 1000 failed at 500/s
```

Mixing ICMP with a port mode is allowed; `--port` is still required, for the
vectors that address one. A run whose vectors are *all* ICMP reports as L3, a
mixed run as L4 — calling a run that floods a port "L3" because one vector is
ICMP would understate it. Preflight checks **every** vector, so a missing
`CAP_NET_RAW` or an unreachable IPv6 target refuses the whole run before any
traffic rather than surfacing as one vector failing every packet.

### The flag and anomaly floods

The raw-TCP flag floods set control flags directly: `syn`/`ack`/`fin`/`rst`/`urg`/
`cwr`/`ece` each set exactly one (the last three send an otherwise-empty segment
carrying only the urgent or an ECN congestion bit). `syn-ack` is the odd one out:
its flags are perfectly legal — it is the *second* segment of a handshake — but it
answers a SYN the target never sent, so every packet must be matched against
connection state or answered with an RST. The **anomaly floods**
set flag fields that match no RFC-legal state — `syn-fin` and `syn-rst` set
mutually-contradictory combinations, `xmas` sets `FIN+PSH+URG` at once, and `null`
sets none — to probe how a stateful firewall / IDS / connection-tracker / TCP
stack handles them.

The `tcp-options` mode is a **TCP-options bomb**: a raw SYN flood whose every
packet carries the full 40-byte maximum of TCP options (MSS + SACK-permitted +
timestamp + window scale, NOP-padded to the limit). Each SYN forces the target's
TCP stack to walk a maximal option block and allocate SACK/timestamp state,
amplifying the per-SYN cost over a bare SYN. Same raw-socket / real-source /
IPv4-only constraints as the flag floods.

### Fragmentation floods (`udp-frag`, `tcp-frag`)

These cut one datagram into IPv4 fragments, so the target has to **hold the
pieces and rebuild them** before it can act on any of it. The cut is deliberate,
not an MTU accident: the datagram is split on 8-byte boundaries *inside its
transport header*, so

* `udp-frag` puts the 8-byte UDP header in fragment 0 and the payload in
  fragment 1 — the destination port is unreadable until both have arrived;
* `tcp-frag` fragments a SYN, whose 20-byte header cuts into 8 + 8 + 4 — the
  ports are in fragment 0 and the **control flags** are in fragment 1, so nothing
  on the path can tell it is a SYN without reassembling first.

The load is the reassembly table: one entry per unit, held until the last
fragment lands or the target's fragment timer expires. Each unit carries its own
IP identification, so entries accumulate instead of overwriting one another.

**`--rate` counts datagrams, not packets.** One `udp-frag` unit is 2 packets on
the wire and one `tcp-frag` unit is 3, so `--rate 5000` on `tcp-frag` is 15 000
pps. The run summary states the multiplier rather than leaving it implicit.

Combine with `--port-order random` over a range for the fragmentation +
random-ports shape. Same raw-socket / real-source / IPv4-only constraints as the
flag floods; the source address is the host's real one on **every** fragment.

### The GRE flood (`gre`)

`gre` sends IP protocol 47 packets: an outer IPv4 header, the 4-byte version-0
GRE header (RFC 2784, no checksum/key/sequence), and an encapsulated IPv4/UDP
datagram. A target that accepts protocol 47 — a router, a firewall, a tunnel
endpoint — has to recognise it, strip the outer header and hand the inner packet
back to its IP stack, so each unit costs roughly two packets' worth of processing
for one packet of bandwidth. `--port` sets the *encapsulated* destination port.

The encapsulated packet is addressed **from the same real source** to the same
target. A GRE payload is the one place a source address could be written where no
kernel would validate it, and the builder deliberately has no argument with which
to write a different one — the no-spoofing guarantee does not stop at the tunnel
header.

### The connect flood

The `tcp` mode is a **full-handshake connect flood**: it completes real TCP
handshakes and holds them open to pressure the target's connection table and
accept backlog. `--concurrency <N>` caps how many connections are held open at
once (default 256); once `N` are open, admitting a new attempt closes the oldest.
The three knobs are orthogonal, and this is the property that keeps a long run
safe to leave running:

| flag | meaning |
| --- | --- |
| `--rate` | offered load — connection attempts per second |
| `--concurrency` | maximum **simultaneously open sockets** — the local footprint |
| `--duration` | wall-clock run length, and nothing else |

Because the footprint is bounded by `--concurrency` rather than by
`rate × duration`, doubling `--duration` does not change the peak descriptor
count.

For `tcp`, that socket count includes connections still **mid-handshake**, so
`--concurrency` is also how many handshakes run in parallel — and therefore what
determines the rate the run can actually offer:

```
reachable rate ≈ --concurrency / round-trip-time
```

This matters because a connect flood is otherwise bounded by *one handshake per
RTT*: 256 sockets against a 3 ms target reaches ~85k attempts/s, but a single
handshake at a time reaches ~330/s no matter what `--rate` says. When a run falls
short of its cap for this reason the summary names it rather than leaving the
percentage to be misread as absorbed load:

```
 attempts   37877 total, 12621.1/s achieved (13% of the 100000/s cap)
 bound by   concurrency, not the target: 1 in flight at a 20us median
            attempt tops out near 50000/s, below the 100000/s cap — raise
            --concurrency to offer more load
```

Evicted connections are closed **abortively** (`SO_LINGER 0`, i.e. RST rather
than FIN) so the local ephemeral port is reusable immediately. A graceful close
parks each port in `TIME_WAIT` for 60 s, which at any sustained rate above a few
hundred per second exhausts the default ~28k-port range mid-run and turns the
test into a local `EADDRNOTAVAIL` failure. Steady-state pressure on the target is
unaffected: it comes from the `--concurrency` connections held established, not
from the ones already closed.

`--connect-timeout-ms` (default 500) bounds a single attempt; an attempt that
outlives it is abandoned and counted in the `timeout` bucket.

### Failure buckets and local limits

Handshake latency (attempt initiation → resolution) is reported as
`latency_us(p50=… p90=… p99=… max=…)`, and failures are broken out **per
errno** rather than as one flat count:

```
[L4 tcp-connect-flood -> port 443 (1 target)] sent=1021 errors=1964 \
  aborted_early=false errno(EMFILE=1964) latency_us(p50=28 p90=39 p99=75 max=14855)
```

That distinction is the point: `EMFILE` / `ENFILE` / `ENOBUFS` /
`EADDRNOTAVAIL` are *local* limits on the machine running jinrai and say nothing
about the target, whereas `ECONNREFUSED` / `ETIMEDOUT` / `ECONNRESET` are the
target actually rejecting traffic. A single `errors=<n>` cannot tell them apart,
and each has a different fix. At startup jinrai also raises its own
`RLIMIT_NOFILE` soft limit to the hard limit and logs the resulting ceiling
(`fd ceiling: …`), because a shell's `ulimit -n` is shell-local and absent under
systemd or cron. That is headroom, not a substitute for `--concurrency`.

### The data flood and the ICMP floods

The `data` mode is a **PSH-ACK data flood**: it opens a bounded pool of real OS
connections (also capped by `--concurrency`) and writes `--payload-size` bytes
into each, filling the target's application buffers rather than just its accept
backlog. No privilege needed.

The `icmp` modes are **L3 ICMPv4 query floods** — each sends a request message the
target host answers directly (never a forged error/redirect/router message):
`icmp` sends echo requests (type 8, the classic ping flood), `icmp-timestamp`
sends timestamp requests (type 13), and `icmp-address-mask` sends address-mask
requests (type 17), exercising the target's different ICMP handlers. They are
portless; the kernel supplies the IP header, so the source is always the host's
real address.

---

# Part III — About the project

## Why Rust

Chosen for raw-packet throughput (L3/L4) *and* high-concurrency async load (L7)
in one toolchain, with memory safety and deterministic, GC-free behaviour that
makes the tool easier to validate/certify. See the conversation log / `docs/` for
the full rationale vs Go.

## Architecture

```
jinrai/  (Cargo workspace)
├── crates/core     # engine vocabulary + StressModule contract
├── crates/safety   # ⚠ THE GATE: allowlist, kill-switch, authorization (std-only, zero deps)
├── crates/l34      # L3/L4 packet generation — lab/isolated nets only  (UDP / TCP-connect / SYN / flag & anomaly floods / data / ICMP)
│   ├── mode.rs     #   which primitive, and its config — pure data, no sockets
│   ├── packet.rs   #   ⚠ THE NO-SPOOFING SURFACE: every byte built below the socket API
│   ├── pace.rs     #   turning --rate into a schedule the send loop can keep
│   └── lib.rs      #   the engine: authorization, send loop, socket senders, tally
├── crates/l7       # L7 HTTP load: GET/POST/HEAD + Slowloris/slow-body  (tokio + reqwest/rustls)
├── crates/metrics  # reporting + tamper-evident audit log             (SHA-256 hash chain)
└── crates/cli      # `jinrai` binary — orchestration + operator gate
```

### The safety invariant (enforced by the compiler)

Traffic modules operate only on `AuthorizedTarget`, which has **no public
constructor** — the sole way to obtain one is `Authorization::authorize`, which
checks the allowlist. "Fire at a target that was never authorized" is therefore
not an expressible program state; it fails to compile.

## Team

| Role | Owns |
|---|---|
| Architect | core traits, the type-state that makes bypassing `safety` impossible |
| Safety/Compliance Engineer | `safety` (allowlist, authz, kill-switch, audit) — gates everyone |
| L3/L4 Engineer | `l34`, packet crafting, lab-isolated throughput |
| L7 Engineer | `l7`, async HTTP engine, load scenarios |
| Metrics/Reporting Engineer | `metrics`, percentiles, signed audit log |
| QA/Test Engineer | tests + adversarial checks that the gate can't be bypassed |

## Roadmap

- **Phase 0** — scaffolding ✅
- **Phase 1** — `safety` + `core` (the non-negotiable foundation) ✅
- **Phase 2** — `l7` async engine ✅
- **Phase 3** — `l34` in isolated-lab mode ✅
- **Phase 4** — metrics, reporting, tamper-evident audit log ✅
- **Phase 5** — response classification, SLO verdict + inline health-watchdog ✅
- **Phase 6** — load profiles (ramp / spike / soak) + breaking-point discovery ✅
- **Phase 7** — protocol coverage ✅: TCP-flag floods (ACK/FIN/RST, URG/CWR/ECE, SYN-ACK, SYN+FIN/SYN+RST, Xmas/NULL), TCP options bomb, TCP data/PSH-ACK flood, ICMP/L3 query floods (echo/timestamp/address-mask), the HTTP/1.1 slow family (Slowloris/RUDY/slow-read) and keep-alive exhaustion, WebSocket/SSE session exhaustion, TLS slow modes + handshake flood + ClientHello/SNI parser stress, and the HTTP/2 family (rapid-reset, MadeYouReset, CONTINUATION, SETTINGS/PING, WINDOW_UPDATE/PRIORITY, empty-DATA, HPACK bomb)
- **Phase 7b** — HTTP/3 & QUIC ✅: handshake flood + QUICLORIS
- **Phase 8** *(next)* — declarative scenario files + multi-source orchestration

Still open beyond Phase 8: IPv6 for the raw L3/L4 primitives (`tcp-connect` and
`data` already do IPv6; the raw modes are IPv4-only).

See [CHANGELOG.md](CHANGELOG.md) for the detailed history.

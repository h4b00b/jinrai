# jinrai

Internal network **resilience / stress-testing** tool for authorized internal infrastructure.
Covers L3/L4 and L7. Built in-house and validated in-house.

> **Scope & authorization.** This tool is for testing infrastructure we own or
> are explicitly authorized to test. It is **fail-closed**: it refuses to send
> anything to an address that is not inside an operator-supplied allowlist. The
> allowlist is passed at runtime (multiple CIDR blocks), never hard-coded,
> because different campaigns target different networks.

---

# jinrai 101 — what you can launch, and how to choose

*New here? Read this section and nothing else. It is the map; everything from
[Usage](#usage) onward is the reference manual.*

## One run = one pressure, on one authorized target, for a bounded time

A jinrai run applies **one** kind of pressure to **one** authorized target and
then reports whether the target held. Every command you will ever type is the
same five decisions:

| Decision | Flag(s) | |
|---|---|---|
| **Where am I allowed to send?** | `--allow` (repeatable) | An IP/CIDR (`10.0.0.0/8`) or a DNS pattern (`*.staging.internal`). No default: with an empty allowlist the run is refused. |
| **Which target?** | `--url` (L7), or `--target` + `--port` (L3/L4) | Checked against the allowlist before a single byte is sent. |
| **Which pressure?** | `--layer`, then `--l7-method` / `--l4-mode` | This is "the attack" — the catalogue is below. |
| **How hard?** | `--rate`, plus a concurrency ceiling (`--max-connections`, `--slow-connections`, `--concurrency`) | `--rate` is a hard safety ceiling, never exceeded by anything. |
| **How long?** | `--duration`, optionally shaped by `--profile` | |

Everything else — `--slo-*`, `--watchdog`, `--audit-log` — is about **judging**
and **bounding** the run, not about generating traffic. The smallest useful
command is:

```sh
jinrai --layer l7 --allow '*.staging.internal' \
       --url https://api.staging.internal/health --rate 50 --duration 10
```

## Which layer?

| Layer | What it exercises | Requires | Where to run it |
|---|---|---|---|
| **L7** `--layer l7` | the service: request handlers, connection slots, TLS, HTTP/2 state machine | nothing special | staging / QA. Real requests, real responses — the only layer that yields a `PASS`/`FAIL` verdict |
| **L4** `--layer l4` | the transport: accept backlog, connection tracking, firewall state, socket buffers | `--ack-l34-lab`; the raw modes also need `CAP_NET_RAW`/root (Linux, IPv4-only) | isolated lab only |
| **L3** `--layer l3` | the host's IP/ICMP handlers | same as L4 | isolated lab only |

Rule of thumb: **L7 answers "can the service still serve?", L3/L4 answer "can
the host and the middleboxes survive the packets?"**. Only L7 reads responses,
so only L7 can tell a healthy target from one that answers `500` at full speed.
**Start at L7** — it is the layer that maps onto a real incident, and it needs
no privilege and no isolated network.

## The catalogue — pick by the resource you want to squeeze

### 1. Throughput capacity — "how many requests/s before it degrades?"

L7 fast methods. Realistic traffic, fully classified, safe to point at staging.

| Goal | Command shape |
|---|---|
| Read-path capacity | `--l7-method get` |
| Write-path capacity | `--l7-method post --body '{...}'` |
| Make sure you are testing the origin, not a cache/CDN | add `--cache-bust` |
| **Find the breaking point automatically** | `--profile ramp --discover-knee --slo-max-5xx-rate 0.01` |
| Burst tolerance / autoscaling reaction | `--profile spike --spike-secs 30` |
| Slow degradation, leaks, GC pressure | `--profile soak --duration 3600` |
| Same load over a different protocol | `--http-version 1.1` vs `--http-version 2` |

### 2. Concurrency limits — "how many simultaneous clients before it stops accepting?"

This is a *different* failure than throughput: the server has capacity left but
no free slot. Cheap for the client, which is exactly the point.

| Goal | Method |
|---|---|
| Keep-alive slot / worker-pool exhaustion, controlled | `--l7-method get --max-connections 50` |
| Classic **Slowloris** — hold connections with never-finished request headers | `--l7-method slowloris` |
| **RUDY** — oversized `Content-Length`, body trickled one byte at a time | `--l7-method slowbody` |
| **Slow read** — complete request, then refuse to drain the response | `--l7-method slow-read` |
| Accept backlog / conntrack table, below HTTP | `--layer l4 --l4-mode tcp --concurrency 256` |

For all slow modes `--slow-connections` is the ceiling of held connections and
`--drip-ms` the tick interval; `--rate` becomes *connections opened per second*.

### 3. Handshake cost — "is the crypto the bottleneck?"

| Goal | Method |
|---|---|
| **THC-SSL-DoS** — complete a TLS handshake, drop it, repeat (asymmetric CPU cost) | `--l7-method tls-handshake` (https only) |

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

### 5. Volume and buffers (lab) — "what happens at packet scale?"

| Goal | Mode |
|---|---|
| Raw datagram volume | `--l4-mode udp --payload-size 1400` |
| Fill application read buffers over real connections (PSH-ACK data flood) | `--l4-mode data --payload-size 4096` |
| ICMP query handlers (echo / timestamp / address-mask) | `--layer l3 --l4-mode icmp` \| `icmp-timestamp` \| `icmp-address-mask` |

### 6. Stateful middlebox behaviour (lab, raw sockets) — "does the firewall/IDS handle this correctly?"

These probe *handling*, not volume: how a connection tracker, IDS or TCP stack
reacts to control flags it should never see.

| Goal | Mode |
|---|---|
| Half-open state exhaustion | `syn` |
| Out-of-state segments — does the tracker create state it shouldn't? | `ack`, `fin`, `rst`, `urg`, `cwr`, `ece` |
| Illegal flag combinations (contradictory / all-set / none-set) | `syn-fin`, `syn-rst`, `xmas`, `null` |
| Maximal 40-byte TCP option block on every SYN | `tcp-options` |

## What `--rate` counts, and which knobs each family actually reads

The single most common mistake is assuming `--rate` always means
requests/second and that every concurrency flag applies everywhere. Neither is
true — `--rate` is reinterpreted per family, and a flag belonging to another
family is silently inert (jinrai warns for the ones that would change the
verdict):

| Family | `--rate` counts | Bound the footprint with | Does **not** read |
|---|---|---|---|
| `get` / `post` / `head` | requests/sec | `--max-connections` (0 = unbounded) | — |
| `slowloris` / `slowbody` / `slow-read` | **connections opened**/sec | `--slow-connections` (ceiling), `--drip-ms` (tick) | `--slo-*`, `--watchdog`, `--profile`, `--http-version` |
| `tls-handshake` | handshakes/sec | *nothing* — concurrency follows the rate | same as above |
| every `h2-*` | frames/sec (cycles/sec for `h2-made-you-reset`) | *nothing* — one connection, frames paced by `--rate` | same as above |
| l4 `tcp` | connection attempts/sec | `--concurrency` (open sockets), `--connect-timeout-ms` | `--slo-*`, `--profile` |
| l4 `data` | writes/sec | `--concurrency`, `--payload-size` | same |
| l4 `udp` | datagrams/sec | `--payload-size` (stateless — no footprint to bound) | same |
| l4 raw floods, l3 `icmp*` | packets/sec | *nothing* — stateless | same |

Two consequences worth internalising: passing `--slow-connections 500` to an
`h2-*` method changes nothing at all, and for `--l4-mode tcp` the reachable rate
is capped at roughly `--concurrency / RTT` no matter what `--rate` says (the run
summary tells you when that is what happened).

## The cookbook — one complete, runnable command per technique

Copy, swap the allowlist and the target, run. Every command below is complete:
nothing is implied or omitted.

### L7 — no privilege required, safe to point at staging

```sh
# Capacity, with a verdict: fails the run (exit != 0) if the target misses the SLO
jinrai --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/health --rate 200 --duration 60 \
       --slo-max-5xx-rate 0.01 --slo-max-p99-ms 250

# Write path: POST with a body, cache-busted so a CDN cannot answer for the origin
jinrai --layer l7 --allow '*.staging.internal' --l7-method post \
       --url https://api.staging.internal/ingest --body '{"probe":1}' \
       --cache-bust --rate 200 --duration 60

# Breaking point: ramp to the ceiling, stop at the first stage that breaks the SLO
jinrai --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/health --rate 5000 --duration 300 \
       --profile ramp --ramp-start 100 --ramp-steps 20 \
       --discover-knee --slo-max-5xx-rate 0.01

# Burst: hold a baseline, jump to the ceiling for 30s, fall back (autoscaling test)
jinrai --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/health --rate 2000 --duration 300 \
       --profile spike --spike-base 200 --spike-secs 30

# Endurance: a long flat hold that surfaces leaks and slow degradation
jinrai --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/health --rate 300 --duration 3600 \
       --profile soak --slo-max-p99-ms 500 --watchdog --slo-max-error-rate 0.05

# Same load over a pinned protocol version (auto would negotiate h2 on https)
jinrai --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/health --http-version 1.1 \
       --rate 200 --duration 60

# Connection-slot exhaustion: at most 50 keep-alive connections held busy
jinrai --layer l7 --allow '*.staging.internal' --l7-method get \
       --url https://api.staging.internal/ --max-connections 50 \
       --cache-bust --rate 1000 --duration 60

# Slowloris: 200 half-open connections, one header line each every 10s
#   swap --l7-method for slowbody (trickled POST body, RUDY)
#   or for slow-read (complete request, response drained one chunk per tick)
jinrai --layer l7 --allow '*.staging.internal' --l7-method slowloris \
       --url https://api.staging.internal/ --slow-connections 200 \
       --drip-ms 10000 --rate 50 --duration 300

# TLS handshake flood (THC-SSL-DoS): full handshake, immediate drop, repeat
jinrai --layer l7 --allow '*.staging.internal' --l7-method tls-handshake \
       --url https://api.staging.internal/ --rate 200 --duration 60

# HTTP/2 rapid reset (CVE-2023-44487). Every h2-* method takes this exact shape;
# only the method name changes:
#   h2-rapid-reset  h2-made-you-reset  h2-continuation  h2-bomb
#   h2-settings     h2-ping            h2-window-update h2-priority  h2-empty-data
jinrai --layer l7 --allow '*.staging.internal' --l7-method h2-rapid-reset \
       --url https://api.staging.internal/ --rate 500 --duration 60
```

### L3/L4 — isolated lab only (`--ack-l34-lab` is mandatory)

```sh
# UDP datagram flood — no privilege needed
jinrai --layer l4 --l4-mode udp --allow 10.0.0.0/8 --target 10.1.2.3 --port 9 \
       --ack-l34-lab --payload-size 1400 --rate 1000 --duration 30

# TCP connect flood: real handshakes held open against the accept backlog.
# --concurrency is both the local footprint AND the parallelism: no privilege needed
jinrai --layer l4 --l4-mode tcp --allow 10.0.0.0/8 --target 10.1.2.3 --port 443 \
       --ack-l34-lab --rate 5000 --duration 60 \
       --concurrency 512 --connect-timeout-ms 500

# PSH-ACK data flood: real connections filled with application data
jinrai --layer l4 --l4-mode data --allow 10.0.0.0/8 --target 10.1.2.3 --port 80 \
       --ack-l34-lab --payload-size 4096 --concurrency 256 --rate 500 --duration 30

# Raw SYN flood — needs CAP_NET_RAW/root, IPv4 only. Same shape for every raw
# flag flood; only --l4-mode changes:
#   syn  ack  fin  rst  urg  cwr  ece          (one flag each)
#   syn-fin  syn-rst  xmas  null               (illegal combinations)
#   tcp-options                                (SYN + maximal 40-byte option block)
sudo -E jinrai --layer l4 --l4-mode syn --allow 10.0.0.0/8 --target 10.1.2.3 \
       --port 80 --ack-l34-lab --rate 5000 --duration 30

# ICMP query flood — portless, needs CAP_NET_RAW/root. Swap --l4-mode for
# icmp-timestamp (type 13) or icmp-address-mask (type 17)
sudo -E jinrai --layer l3 --l4-mode icmp --allow 10.0.0.0/8 --target 10.1.2.3 \
       --ack-l34-lab --rate 1000 --duration 30
```

`sudo -E` preserves `$JINRAI_OPERATOR` so the audit log still records who ran it.

## Your first four runs, in order

```sh
# 1. Prove the gate and the path. Trivial load — if the allowlist or the URL is
#    wrong, this refuses instead of sending, which is the point of run #1.
jinrai --layer l7 --allow '*.staging.internal' \
       --url https://api.staging.internal/health --rate 10 --duration 5

# 2. Steady state with an actual verdict (exits non-zero if the SLO is missed).
jinrai --layer l7 --allow '*.staging.internal' \
       --url https://api.staging.internal/health --rate 200 --duration 60 \
       --slo-max-5xx-rate 0.01 --slo-max-p99-ms 250

# 3. Find the capacity knee: ramp until the SLO breaks, then stop and report it.
jinrai --layer l7 --allow '*.staging.internal' \
       --url https://api.staging.internal/health --rate 5000 --duration 300 \
       --profile ramp --discover-knee --slo-max-5xx-rate 0.01

# 4. The same, on the record: hash-chained audit trail, plus an automatic abort.
export JINRAI_OPERATOR="you@example.com"
jinrai --layer l7 --allow '*.staging.internal' \
       --url https://api.staging.internal/ --rate 1000 --duration 300 \
       --slo-max-error-rate 0.05 --watchdog --audit-log runs.jsonl
jinrai --verify-audit runs.jsonl
```

## Choosing numbers without breaking something you meant to keep

* **`--rate` is a ceiling, not a target.** No profile ever exceeds it. Start an
  order of magnitude below the capacity you expect and ramp — `--discover-knee`
  exists so you do not have to guess twice.
* **Concurrency is your own footprint.** `--concurrency` / `--slow-connections` /
  `--max-connections` bound the sockets held open *by jinrai*, independently of
  `--duration`. Doubling the duration does not double the footprint.
* **`--watchdog` is the automatic brake**: it aborts the run after
  `--watchdog-breaches` consecutive breaching windows. It can only ever *stop*
  traffic, never generate it. Use it on anything long or unattended.
* **Ctrl-C is the manual brake** — it trips the same kill-switch, and no target
  can be authorized once it is tripped.
* **If the summary says the run fell short of the rate cap, believe it.** A test
  that never produced the load it promised is not evidence that the target
  coped; see [Reading the result](#reading-the-result---output).

## What jinrai deliberately will not do

There is **no source-IP spoofing** anywhere: every crafted packet carries the
host's real, OS-routed source address. There is no reflection or amplification
through third parties, and the ICMP modes send only *query* messages the target
answers itself — never forged errors, redirects or router messages. A target
outside every `--allow` rule aborts the entire run. Those techniques exist to
hide the sender or to borrow someone else's bandwidth; a test of your own
infrastructure needs neither.

---

## Language

**Rust** — chosen for raw-packet throughput (L3/L4) *and* high-concurrency
async load (L7) in one toolchain, with memory safety and deterministic,
GC-free behaviour that makes the tool easier to validate/certify. See the
conversation log / `docs/` for the full rationale vs Go.

## Architecture

```
jinrai/  (Cargo workspace)
├── crates/core     # engine vocabulary + StressModule contract
├── crates/safety   # ⚠ THE GATE: allowlist, kill-switch, authorization (std-only, zero deps)
├── crates/l34      # L3/L4 packet generation — lab/isolated nets only  (UDP / TCP-connect / SYN / flag & anomaly floods / data / ICMP)
├── crates/l7       # L7 HTTP load: GET/POST/HEAD + Slowloris/slow-body  (tokio + reqwest/rustls)
├── crates/metrics  # reporting + tamper-evident audit log             (SHA-256 hash chain)
└── crates/cli      # `jinrai` binary — orchestration + operator gate
```

### The safety invariant (enforced by the compiler)

Traffic modules operate only on `AuthorizedTarget`, which has **no public
constructor** — the sole way to obtain one is `Authorization::authorize`, which
checks the allowlist. "Fire at a target that was never authorized" is therefore
not an expressible program state; it fails to compile.

## Team (agent roles)

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
- **Phase 7** — protocol coverage: TCP-flag floods (ACK/FIN/RST) ✅, TCP anomaly floods (Xmas/NULL) ✅, TCP data/PSH-ACK flood ✅, TLS slow modes ✅, TLS handshake flood ✅, ICMP/L3 ✅, HTTP/2 rapid-reset ✅, HTTP/2 CONTINUATION flood ✅, HTTP/2 SETTINGS/PING floods ✅
- **Phase 8** *(next)* — declarative scenario files + multi-source orchestration

See [CHANGELOG.md](CHANGELOG.md) for the detailed history.

## Build & test

```sh
cargo build
cargo test          # unit tests, incl. the safety gate
cargo clippy
```

## Usage

Every run needs at least one `--allow` rule; an empty allowlist authorizes
nothing and the run is refused (fail-closed). `--allow` takes either an IP/CIDR
or a DNS pattern (`api.staging.internal`, `*.staging.internal`).

### L7 — HTTP/API load

Constant-rate by default. The `--url` host is validated as a
*datum* against its own rule type (an IP-literal host against the CIDR rules, a
DNS-name host against the DNS rules) and only then resolved once and pinned:

```sh
jinrai --layer l7 --allow '*.staging.internal' \
       --url https://api.staging.internal/health --rate 200 --duration 30
```

`--l7-method` selects the request primitive (default `get`):

| Method | Kind | Notes |
|---|---|---|
| `get` / `post` / `head` | fast, constant-rate | `--body` sets the POST body; `--cache-bust` appends a unique `_cb=<n>` query per request (query only — never the host); `--max-connections <N>` caps concurrent connections (see below); `--http-version <auto\|1.1\|2>` pins the protocol version (see below) |
| `slowloris` | slow connection | partial request headers, never terminated |
| `slowbody` | slow connection | oversized `Content-Length`, body trickled a byte at a time (RUDY) |
| `slow-read` | slow connection | send a *complete* request, then drain the response one small chunk per tick with a shrunken receive window (`SO_RCVBUF`) so the server cannot flush it — the read-side mirror of `slowbody` |
| `h2-rapid-reset` | HTTP/2 | open a stream, immediately `RST_STREAM` (CVE-2023-44487); rate cap = resets/sec |
| `h2-continuation` | HTTP/2 | HEADERS without `END_HEADERS` + endless `CONTINUATION` frames (CVE-2024-27316); rate cap = frames/sec |
| `tls-handshake` | TLS | full TLS handshake then drop, repeated concurrently (THC-SSL-DoS); https-only; rate cap = handshakes/sec |
| `h2-settings` | HTTP/2 | flood empty `SETTINGS` frames the server must ACK (CVE-2019-9515); rate cap = frames/sec |
| `h2-ping` | HTTP/2 | flood `PING` frames the server must answer with a PONG (CVE-2019-9512); rate cap = frames/sec |
| `h2-window-update` | HTTP/2 | flood connection-level `WINDOW_UPDATE` frames the server must process (CVE-2019-9514); rate cap = frames/sec |
| `h2-priority` | HTTP/2 | flood `PRIORITY` frames that reshuffle the server's priority tree (CVE-2019-9513, "Resource Loop"); rate cap = frames/sec |
| `h2-made-you-reset` | HTTP/2 | complete request then a zero-increment `WINDOW_UPDATE` so the **server** resets the stream (CVE-2025-8671, "MadeYouReset") — evades Rapid-Reset mitigations; rate cap = reset cycles/sec |
| `h2-empty-data` | HTTP/2 | open a stream, then flood zero-length `DATA` frames without `END_STREAM` (CVE-2019-9518); rate cap = frames/sec |
| `h2-bomb` | HTTP/2 | HPACK 1-byte-reference header amplification + `INITIAL_WINDOW_SIZE=0` so the amplified memory stays pinned (CVE-2026-49975, "HTTP/2 Bomb"); rate cap = bomb frames/sec |

**HTTP/1.1 vs HTTP/2 (`--http-version`).** For the fast `get`/`post`/`head`
methods the protocol version is the operator's choice, not the server's. The
default (`auto`) negotiates — plain HTTP/1.1 for an `http://` URL, but ALPN for
`https://`, which means **an https target that offers h2 is tested over HTTP/2**.
That is a different test (multiplexed streams instead of one request per
connection, HPACK instead of plain headers, different server-side limits), so it
has to be selectable:

```sh
# force HTTP/1.1 — never negotiate h2, even if the server offers it
jinrai --layer l7 --allow '*.staging.internal' --http-version 1.1 \
       --url https://api.staging.internal/health --rate 200 --duration 30

# force HTTP/2 (ALPN h2 only for https, prior-knowledge h2c for http)
jinrai --layer l7 --allow '*.staging.internal' --http-version 2 \
       --url https://api.staging.internal/health --rate 200 --duration 30
```

Forcing `2` deliberately does **not** fall back: a target that cannot do h2 fails
every request and the run says so (`protocol` failure bucket, non-zero exit)
rather than silently downgrading to HTTP/1.1 and reporting a clean pass. Whatever
is selected, the run summary reports the version the responses *actually* arrived
on — the only way to notice that an "HTTP/1.1" run was negotiated up to h2. The
slow modes are HTTP/1.1 by construction and the `h2-*` methods are HTTP/2 by
construction, so the flag does not apply to them (it warns and is ignored).

For slow modes the rate cap means *connections opened per second*; `--slow-connections`
is the concurrent ceiling and `--drip-ms` the per-tick interval (the keep-alive write
interval for `slowloris`/`slowbody`, or the read interval draining one chunk for
`slow-read`). Header-profile tests (`User-Agent`, `Cookie`, `Referer`, …) use the
repeatable `--header` flag.

```sh
# POST flood with a body and cache-busting
jinrai --layer l7 --allow '*.staging.internal' --l7-method post \
       --url http://api.staging.internal/ingest --body '{"probe":1}' \
       --cache-bust --rate 200 --duration 30

# Keep-alive connection exhaustion: hold at most 50 concurrent connections busy
# (controlled form of GoldenEye/XerXes) to probe the connection-slot / worker limit
jinrai --layer l7 --allow '*.staging.internal' --l7-method get \
       --url http://api.staging.internal/ --max-connections 50 \
       --cache-bust --rate 1000 --duration 60

# Slowloris: hold 200 half-open connections, one header line every 10s
jinrai --layer l7 --allow '*.staging.internal' --l7-method slowloris \
       --url http://api.staging.internal/ --slow-connections 200 \
       --drip-ms 10000 --rate 50 --duration 60

# Slow-read: hold 200 connections, draining the response one chunk every 10s
jinrai --layer l7 --allow '*.staging.internal' --l7-method slow-read \
       --url http://api.staging.internal/large-resource --slow-connections 200 \
       --drip-ms 10000 --rate 50 --duration 60
```

All the `h2-*` primitives negotiate h2 via ALPN for `https` and prior-knowledge
h2c for `http`; the rate cap is reinterpreted per primitive (resets/sec,
frames/sec, cycles/sec). They send no application data and read no response, so
`--slo-*` / `--watchdog` don't apply.

```sh
# HTTP/2 CONTINUATION flood: HEADERS without END_HEADERS, then endless
# (non-flow-controlled) CONTINUATION frames the server must buffer forever
jinrai --layer l7 --allow '*.staging.internal' --l7-method h2-continuation \
       --url https://api.staging.internal/ --rate 200 --duration 30
```

**SLO verdict & health-watchdog (l7 fast methods).** Every response is classified
by status class, so the tool can tell a healthy target from one that is answering
but failing. Declare an SLO and the run prints a `PASS`/`FAIL` verdict and exits
non-zero when the target misses it — a `500`/`429` flood no longer reports a
hollow "success":

```sh
jinrai --layer l7 --allow '*.staging.internal' \
       --url https://api.staging.internal/health --rate 500 --duration 60 \
       --slo-max-5xx-rate 0.01 --slo-max-p99-ms 250
```

Add `--watchdog` to auto-abort (kill-switch) once a *rate* SLO is breached for
`--watchdog-breaches` consecutive `--watchdog-window`s — the watchdog can only
ever stop traffic, never generate it:

```sh
jinrai --layer l7 --allow '*.staging.internal' \
       --url https://api.staging.internal/ --rate 1000 --duration 300 \
       --slo-max-error-rate 0.05 --slo-max-5xx-rate 0.02 \
       --watchdog --watchdog-window 5 --watchdog-breaches 3
```

### L3/L4 — isolated-lab only

Requires raw target IPs matching a CIDR `--allow`,
an explicit `--ack-l34-lab` acknowledgement, and a `--port`. `udp`/`tcp`/`data`
need no privilege (and `tcp`/`data` work over IPv4 **and** IPv6); the raw-socket
modes (`syn`/`ack`/`fin`/`rst`/`urg`/`cwr`/`ece`/`syn-fin`/`syn-rst`/`xmas`/`null`/
`tcp-options`/`icmp`/`icmp-timestamp`/`icmp-address-mask`) need `CAP_NET_RAW`/root
and are IPv4-only:

```sh
jinrai --layer l4 --l4-mode udp --allow 10.0.0.0/8 \
       --target 10.1.2.3 --port 9 --ack-l34-lab --rate 1000 --duration 10
```

The raw-TCP flag floods set control flags directly: `syn`/`ack`/`fin`/`rst`/`urg`/
`cwr`/`ece` each set exactly one (the last three send an otherwise-empty segment
carrying only the urgent or an ECN congestion bit), while the **anomaly floods**
set flag fields that match no RFC-legal state — `syn-fin` and `syn-rst` set
mutually-contradictory combinations, `xmas` sets `FIN+PSH+URG` at once, and `null`
sets none — to probe how a stateful firewall / IDS / connection-tracker / TCP
stack handles them:

```sh
# Xmas flood against a lab host (raw socket; needs CAP_NET_RAW/root)
jinrai --layer l4 --l4-mode xmas --allow 10.0.0.0/8 \
       --target 10.1.2.3 --port 80 --ack-l34-lab --rate 1000 --duration 10
```

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
outlives it is abandoned and counted in the `timeout` bucket:

```sh
jinrai --layer l4 --l4-mode tcp --allow 10.0.0.0/8 \
       --target 10.1.2.3 --port 443 --ack-l34-lab \
       --rate 200 --duration 60 --concurrency 256
```

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

The `data` mode is a **PSH-ACK data flood**: it opens a bounded pool of real OS
connections (also capped by `--concurrency`) and writes `--payload-size` bytes
into each, filling the target's application buffers rather than just its accept
backlog. No privilege needed:

```sh
jinrai --layer l4 --l4-mode data --allow 10.0.0.0/8 \
       --target 10.1.2.3 --port 80 --ack-l34-lab \
       --payload-size 4096 --rate 500 --duration 30
```

The `tcp-options` mode is a **TCP-options bomb**: a raw SYN flood whose every
packet carries the full 40-byte maximum of TCP options (MSS + SACK-permitted +
timestamp + window scale, NOP-padded to the limit). Each SYN forces the target's
TCP stack to walk a maximal option block and allocate SACK/timestamp state,
amplifying the per-SYN cost over a bare SYN. Same raw-socket / real-source /
IPv4-only constraints as the flag floods:

```sh
jinrai --layer l4 --l4-mode tcp-options --allow 10.0.0.0/8 \
       --target 10.1.2.3 --port 80 --ack-l34-lab --rate 1000 --duration 10
```

The `icmp` modes are **L3 ICMPv4 query floods** — each sends a request message the
target host answers directly (never a forged error/redirect/router message):
`icmp` sends echo requests (type 8, the classic ping flood), `icmp-timestamp`
sends timestamp requests (type 13), and `icmp-address-mask` sends address-mask
requests (type 17), exercising the target's different ICMP handlers. They are
portless; the kernel supplies the IP header, so the source is always the host's
real address (no spoofing):

```sh
jinrai --layer l3 --l4-mode icmp-timestamp --allow 10.0.0.0/8 \
       --target 10.1.2.3 --ack-l34-lab --rate 1000 --duration 10
```

A target outside every `--allow` block aborts the whole run. There is **no
source-IP spoofing** anywhere: every crafted packet carries the host's real
OS-routed source address.

### Reading the result (`--output`)

Every run ends with a summary block that states the offered load, what came back,
and what it means. `--output line` switches to the single machine-friendly line
instead (stable for scripts and log scraping):

```
==== run summary =========================================================
 target     https://api.staging.internal/health
 module     L7 / l7-http-get  (HTTP/1.1 forced)
 window     30.0s elapsed of 30.0s planned, rate cap 200/s
 attempts   6000 total, 199.4/s achieved (100% of the 200/s cap)
 completed  5994 (99.9%)
   status   2xx 5900 (98.4%)   3xx 0 (0.0%)   4xx 40 (0.7%)   5xx 54 (0.9%)
   protocol HTTP/1.1 5994
 failed     6 (0.1%), of which 6 timed out
            6 x timeout — our own attempt timeout expired first
 latency    p50 12.4ms   p90 45.1ms   p99 210.0ms   max 1.20s
 outcome    ran to completion
 SLO        FAIL (5xx-rate 0.9% > 0.5%)
==========================================================================
```

Three things the block is there to make unmissable:

* **Offered vs. achieved load** — `attempts … achieved (…% of the cap)` says
  whether the tool actually produced the load that was asked for, so a result is
  never read as "the target coped" when the generator never reached the rate.
* **Whose failure it was** — L7 failures are bucketed like the L3/L4 ones:
  `ECONNREFUSED` (the target refused), `timeout` (nobody answered),
  `protocol` (the exchange failed above the socket — typically a forced
  `--http-version` the target does not speak), `EMFILE`/`EADDRNOTAVAIL` (a local
  ceiling on the *testing* host, saying nothing about the target).
* **A run that tested nothing** — 0 completions with only failures prints an
  explicit warning **and exits non-zero**, so "6000 attempts, 0 responses" can no
  longer be mistaken for a successful test in a pipeline.

### Audit log (tamper-evident)

Record an accountable, hash-chained trail of every run — who authorized what,
against which allowlist, and with what outcome:

```sh
export JINRAI_OPERATOR="you@example.com"          # else falls back to the OS user
jinrai --layer l4 --l4-mode udp --allow 10.0.0.0/8 --target 10.1.2.3 \
       --port 9 --ack-l34-lab --rate 1000 --duration 10 \
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

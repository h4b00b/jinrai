# jinrai

Internal network **resilience / stress-testing** tool for authorized internal infrastructure.
Covers L3/L4 and L7. Built in-house and validated in-house.

> **Scope & authorization.** This tool is for testing infrastructure we own or
> are explicitly authorized to test. It is **fail-closed**: it refuses to send
> anything to an address that is not inside an operator-supplied allowlist. The
> allowlist is passed at runtime (multiple CIDR blocks), never hard-coded,
> because different campaigns target different networks.

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

**L7 — HTTP/API constant-rate load.** The `--url` host is validated as a
*datum* against its own rule type (an IP-literal host against the CIDR rules, a
DNS-name host against the DNS rules) and only then resolved once and pinned:

```sh
jinrai --layer l7 --allow '*.staging.internal' \
       --url https://api.staging.internal/health --rate 200 --duration 30
```

`--l7-method` selects the request primitive (default `get`):

| Method | Kind | Notes |
|---|---|---|
| `get` / `post` / `head` | fast, constant-rate | `--body` sets the POST body; `--cache-bust` appends a unique `_cb=<n>` query per request (query only — never the host); `--max-connections <N>` caps concurrent connections (see below) |
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

The two HTTP/2 primitives (`h2-rapid-reset`, `h2-continuation`) negotiate h2 via
ALPN for `https` and prior-knowledge h2c for `http`; the rate cap is
reinterpreted per primitive (resets/sec, frames/sec). They send no application
data and read no response, so `--slo-*` / `--watchdog` don't apply.

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

**L3/L4 — isolated-lab only.** Requires raw target IPs matching a CIDR `--allow`,
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
count. `--connect-timeout-ms` (default 500) bounds a single attempt; an attempt
that outlives it is abandoned and counted in the `timeout` bucket:

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

The log is append-only JSONL with a SHA-256 hash chain: editing, deleting, or
reordering any record is detectable. The log is opened before any traffic and a
write failure aborts the run, so traffic never outruns its own record.

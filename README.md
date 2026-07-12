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
├── crates/l34      # L3/L4 packet generation — lab/isolated nets only  (UDP / TCP-connect / SYN)
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
- **Phase 7** — protocol coverage: TCP-flag floods (ACK/FIN/RST) ✅, TLS slow modes ✅, ICMP/L3 ✅, HTTP/2 rapid-reset ✅, HTTP/2 CONTINUATION flood ✅
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
| `get` / `post` / `head` | fast, constant-rate | `--body` sets the POST body; `--cache-bust` appends a unique `_cb=<n>` query per request (query only — never the host) |
| `slowloris` | slow connection | partial request headers, never terminated |
| `slowbody` | slow connection | oversized `Content-Length`, body trickled a byte at a time (RUDY) |
| `h2-rapid-reset` | HTTP/2 | open a stream, immediately `RST_STREAM` (CVE-2023-44487); rate cap = resets/sec |
| `h2-continuation` | HTTP/2 | HEADERS without `END_HEADERS` + endless `CONTINUATION` frames (CVE-2024-27316); rate cap = frames/sec |

For slow modes the rate cap means *connections opened per second*; `--slow-connections`
is the concurrent ceiling and `--drip-ms` the keep-alive write interval. Slow mode is
http-only for now (an `https` URL is refused fail-closed). Header-profile tests
(`User-Agent`, `Cookie`, `Referer`, …) use the repeatable `--header` flag.

```sh
# POST flood with a body and cache-busting
jinrai --layer l7 --allow '*.staging.internal' --l7-method post \
       --url http://api.staging.internal/ingest --body '{"probe":1}' \
       --cache-bust --rate 200 --duration 30

# Slowloris: hold 200 half-open connections, one header line every 10s
jinrai --layer l7 --allow '*.staging.internal' --l7-method slowloris \
       --url http://api.staging.internal/ --slow-connections 200 \
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
an explicit `--ack-l34-lab` acknowledgement, and a `--port`. `syn` mode needs
`CAP_NET_RAW`/root:

```sh
jinrai --layer l4 --l4-mode udp --allow 10.0.0.0/8 \
       --target 10.1.2.3 --port 9 --ack-l34-lab --rate 1000 --duration 10
```

A target outside every `--allow` block aborts the whole run. There is **no
source-IP spoofing** anywhere: SYN packets always carry the host's real
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

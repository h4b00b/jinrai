# jinrai

Internal network **resilience / stress-testing** tool for authorized internal infrastructure.
Covers L3/L4 and L7. Built in-house and validated in-house per company policy.

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
├── crates/l7       # L7 HTTP/API constant-rate load                    (tokio + reqwest/rustls)
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

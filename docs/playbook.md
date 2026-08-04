# jinrai — test-case playbook

One section per row of a test plan, with the ready-to-paste command and an
explanation of **every switch in it**, so whoever runs the test knows exactly
what lands on the wire and how to read the result.

Reference version: **0.43.0**.

---

## Contents

- [Setup](#setup)
- [The mandatory flags, explained once](#the-mandatory-flags-explained-once)
- [L3/L4 test cases](#l3l4-test-cases) — 1–19
- [L7 test cases](#l7-test-cases) — 20–38
- [Capacity test cases](#capacity-test-cases) — 39–42
- [Out of scope, and why](#out-of-scope-and-why)
- [Reading the run summary](#reading-the-run-summary)
- [Verifying the audit log](#verifying-the-audit-log)
- [When a run reaches nothing](#when-a-run-reaches-nothing)

---

## Setup

Set these once to your own authorized lab values:

```sh
export T=10.0.0.10                       # the target address
export A="--allow $T"                    # the authorization rule
export URL=http://10.0.0.10/             # the L7 datum
export REQ='--ack-lab --audit-log ./runs.jsonl'
export JINRAI_OPERATOR="$(whoami)"       # recorded in every audit record
```

**Add `--dry-run` to any command** to walk the whole refusable path (allowlist,
authorization gate, privilege preflight) and print the plan **without sending a
byte**. It is the right way to try a new line: if the dry run passes, the real
run starts.

Commands marked `[raw]` open raw sockets and need `CAP_NET_RAW` or root. Either
prefix them with `sudo -E`, or grant the capability once:

```sh
sudo setcap cap_net_raw+ep /path/to/jinrai
```

---

## The mandatory flags, explained once

These appear in **every** command in this playbook. Full explanation here; the
per-case tables reference them in one line.

| Switch | What it does |
|---|---|
| `--allow <IP\|CIDR\|name>` | **The authorization list. Repeatable, no default: an empty one authorizes nothing.** This is the safety anchor — jinrai refuses to send traffic anywhere it does not cover. Validation is on the **datum as written**: an IP literal is checked against the IP/CIDR rules, a DNS name against the DNS rules. A name that resolves to an allowlisted IP but matches no DNS rule **is refused**. |
| `--target <IP>` | Destination for L3/L4. **Repeatable**: several targets in one run is the carpet-bombing shape, and the load is spread across all of them. Every target must match an `--allow` rule. |
| `--url <URL>` | The datum for L7 (instead of `--target`). The host is authorized, resolved **once**, and the address is pinned into the HTTP client: DNS cannot move the destination mid-run, and redirects are not followed (they would leave the pin). |
| `--ack-lab` | Acknowledgement that the target is an authorized, isolated lab system. **Required for every layer**, not just L3/L4 — an L7 run needs no privileges and is the easiest to fire by accident. Not needed with `--dry-run`. |
| `--audit-log <PATH>` | Append-only record with a SHA-256 hash chain: one record before any traffic (`RunAuthorized`), one at the end (`RunCompleted`), one for every refusal (`RunRefused`). If the file cannot be opened, the run **does not start**. The alternative is `--no-audit`, which says out loud what omitting `--audit-log` used to say silently. |
| `--rate <N>` | **A safety ceiling in units per second, not a target.** No load profile can exceed it. What a "unit" is depends on the module — stated in every test case below. Max 10 000 000. |
| `--duration <SECS>` | Wall-clock length of the run, in seconds. Max 86400. It bounds the **traffic**, not just the dispatching of it: requests still in flight are cancelled after `--drain-timeout-ms`. |
| `--dry-run` | Validate, authorize, preflight, print the plan, **send nothing**. Exempt from `--ack-lab` and from the audit requirement. |
| `--color <auto\|always\|never>` | Colours the summary. `auto` (default) paints only when stdout is a terminal and `NO_COLOR` is unset, so a redirected report stays plain. Use `always` when piping through `tee` and you still want colour. |
| `--output <human\|line>` | `human` (default) is the readable block; `line` is the single stable line for scripts and log scraping. |

**Ctrl-C always stops everything** (SIGINT and SIGTERM are wired to the kill
switch), the drain still runs, and the audit record is still written.

---

## L3/L4 test cases

### 1 — UDP flood

The baseline volumetric flood: datagrams at a port, which the target must
process and — if nothing is listening — answer with an ICMP port-unreachable for
each one.

```sh
jinrai $A --target $T --port 53 --layer l4 --l4-mode udp \
  --payload-size 512 --rate 50000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `$A` = `--allow <target>` | Authorizes the target. Without it the run is refused. |
| `--target $T` | Where the datagrams go. |
| `--port 53` | Destination port. One port here. |
| `--layer l4` | Selects the L3/L4 module (`l3` and `l4` select the same module; only the reported layer differs). |
| `--l4-mode udp` | The primitive: UDP flood. **No privileges needed** — it uses the kernel's UDP socket. |
| `--payload-size 512` | Payload bytes per datagram (default 64). This is the bandwidth lever: 50 000/s × 512 B ≈ 205 Mbit/s. |
| `--rate 50000` | Ceiling: 50 000 datagrams per second. |
| `--duration 60` | 60 seconds. |
| `$REQ` | `--ack-lab` + `--audit-log` (see above). |

**On the wire:** one packet per unit, real source IP (never spoofed).
**How to read it:** if `attempts` lands below the cap with `failed 0`, the yellow
`bound by` line says whether the limit was this host rather than the target.

---

### 2 — UDP flood, random ports

The same, but the destination port changes per packet: a firewall rule keyed on
one port sees a trickle instead of the run.

```sh
jinrai $A --target $T --port 1-65535 --port-order random --layer l4 --l4-mode udp \
  --rate 50000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--port 1-65535` | **A port spec, not a number.** Takes a single port (`443`), a comma list (`80,443,8080`), an inclusive range (`1000-2000`), or a mix (`80,8000-8100`). Held as ranges, so `1-65535` costs two integers. Port 0 is always refused. |
| `--port-order random` | Draws a port per packet: consecutive packets are unrelated. The default `sequential` walks the set in the order written, advancing once per pass over the targets (so a multi-target run enumerates the whole target × port cross-product). |

Everything else: as in test 1.

> **The guarantee that does not change:** only the **destination** port varies.
> The source IP is never spoofed and the source port stays deterministic —
> randomising that is what makes flows unattributable, and it is absent for the
> same reason source-IP spoofing is.

---

### 3 — UDP carpet bombing

Several destination addresses × a port range: no single address carries the
whole run, so a per-destination threshold never trips.

```sh
jinrai $A --allow 10.0.0.11 --target $T --target 10.0.0.11 \
  --port 1-65535 --port-order random --layer l4 --l4-mode udp \
  --rate 50000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--allow 10.0.0.11` | **A second allowlist rule.** Every target must be authorized: adding a `--target` without its `--allow` refuses the run. |
| `--target` × 2 | The two destinations. The load is divided between them, not multiplied. |
| `--port 1-65535 --port-order random` | As in test 2. |

**On the wire:** `--rate 50000` stays the run total, ~25 000/s per target.

---

### 4 — UDP fragmentation `[raw]`

The datagram is cut **inside the transport header**: fragment 0 carries the
8-byte UDP header, fragment 1 the payload. The destination port is unreadable
until both land, so the target must hold reassembly state before it can decide
anything at all.

```sh
sudo -E jinrai $A --target $T --port 53 --layer l3 --l4-mode udp-frag \
  --payload-size 1400 --rate 20000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `sudo -E` | Needs `CAP_NET_RAW`: jinrai builds the IPv4 header itself. `-E` preserves the environment (`JINRAI_OPERATOR`). **IPv4 only.** |
| `--layer l3` | These modes report **L3**: what they stress is the IP layer (the reassembly table), not the port. |
| `--l4-mode udp-frag` | 2 fragments per unit, cut on an 8-byte boundary. Each unit carries its **own IP identification**, so reassembly entries accumulate instead of overwriting one another. |
| `--payload-size 1400` | Datagram payload **before** fragmentation. Floored at 8 bytes: below that there would be nothing past the UDP header to cut off, and the run would emit ordinary unfragmented datagrams while reporting a fragmentation flood. |
| `--rate 20000` | ⚠️ **`--rate` counts datagrams, not packets.** 20 000 units/s = **40 000 packets/s** on the wire. The summary states the multiplier in its `of which` row. |

---

### 5 — UDP fragmentation, random ports `[raw]`

Fragmentation and random ports together: the port lives in fragment 0 and
changes every unit.

```sh
sudo -E jinrai $A --target $T --port 1-65535 --port-order random --layer l3 \
  --l4-mode udp-frag --payload-size 1400 --rate 20000 --duration 60 $REQ
```

Switches: the union of tests 2 and 4, same meanings.

---

### 6 — TCP SYN flood `[raw]`

The classic: SYNs at rate, each one costing the target a half-open queue entry.

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 --l4-mode syn \
  --rate 50000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode syn` | Raw SYN. The source IP is **the real route-local address** (`source_ipv4_for`), never an arbitrary one: the SYN-ACKs really do come back, and the test is attributable. |
| `--port 445` | Destination port. Pick one with a service behind it, or you are measuring the RST path. |

---

### 7 — TCP SYN, random ports `[raw]`

```sh
sudo -E jinrai $A --target $T --port 1-65535 --port-order random --layer l4 \
  --l4-mode syn --rate 50000 --duration 60 $REQ
```

Switches: test 6 plus `--port` / `--port-order` from test 2.

---

### 8 — TCP carpet bombing `[raw]`

```sh
sudo -E jinrai $A --allow 10.0.0.11 --target $T --target 10.0.0.11 \
  --port 1-65535 --port-order random --layer l4 --l4-mode syn \
  --rate 50000 --duration 60 $REQ
```

Switches: test 3 with `--l4-mode syn` instead of `udp`.

---

### 9 — TCP fragmentation, random ports `[raw]`

A SYN cut into 3: the 20-byte TCP header splits 8 + 8 + 4, so **the ports land
in fragment 0 and the control flags in fragment 1**. Nothing on the path can
tell it is a SYN without reassembling first.

```sh
sudo -E jinrai $A --target $T --port 1-65535 --port-order random --layer l3 \
  --l4-mode tcp-frag --rate 20000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode tcp-frag` | 3 fragments per unit. ⚠️ **`--rate 20000` = 60 000 packets/s** on the wire. |
| `--layer l3` | As in test 4: the IP layer is what is under test. |

---

### 10 — TCP connect / handshake flood

Real handshakes held open against the accept backlog. No privileges: it uses the
kernel stack, and it works over IPv6 too.

```sh
jinrai $A --target $T --port 445 --layer l4 --l4-mode tcp \
  --concurrency 512 --connect-timeout-ms 500 --rate 10000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode tcp` | Connect flood: opens complete connections and holds them. |
| `--concurrency 512` | **Simultaneously open sockets** (default 256, capped at 4096 threads). It is the run's local footprint *and* the handshake parallelism. Once N are open, admitting a new attempt closes the oldest connection. |
| `--connect-timeout-ms 500` | How long one attempt may stay unresolved before it is abandoned and counted in the `timeout` errno bucket (default 500). **This is the real lever:** an attempt that times out holds its slot for the whole timeout, so once a meaningful share of attempts fail, lowering this buys far more offered load than raising `--concurrency`. |
| `--rate 10000` | Ceiling on attempts/s. The reachable rate is about `--concurrency` ÷ mean attempt time. |

**How to read it:** if `attempts` falls well short of the cap, the yellow
`bound by` line says **which of the two knobs** to reach for, with the arithmetic
spelled out.

---

### 11 — TCP PSH-ACK / data flood

Real connections filled with application data: the target must not only accept,
it must read the bytes and hand them up the stack.

```sh
jinrai $A --target $T --port 445 --layer l4 --l4-mode data \
  --payload-size 1400 --concurrency 256 --rate 5000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode data` | PSH-ACK segment flood over established connections. No privileges, IPv4 and IPv6. |
| `--payload-size 1400` | Bytes per write. Here it is the application write size, not a datagram size. |
| `--concurrency 256` | Connections held open at once. |

---

### 12 — TCP ACK / RST / FIN flood `[raw]`

Single flags on connections that do not exist: it exercises the state tracking
of firewalls and stacks.

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 --l4-mode ack \
  --rate 50000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode ack` | One flag per mode. Swap for `rst`, `fin`, `urg`, `cwr`, `ece` — `urg`/`cwr`/`ece` send an otherwise-empty segment carrying only that (rarely standalone) bit. |

> ⚠️ These are *out-of-state* modes. A stateful device anywhere on the path can
> drop them before delivery while the run still reports success — see
> [when a run reaches nothing](#when-a-run-reaches-nothing).

---

### 13 — Anomalous TCP flags (Xmas / NULL) `[raw]`

Illegal or contradictory flag combinations: a probe of how firewalls, IDS and
TCP stacks handle malformed control fields.

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 --l4-mode xmas \
  --rate 50000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode xmas` | FIN+PSH+URG set together. Swap for `null` (no flags at all), `syn-fin` and `syn-rst` (contradictory combinations), or `syn-ack` (a legal handshake *response* to a SYN the target never sent — legal flags, illegal **state**). |

> ⚠️ Also out-of-state: same caveat as test 12.

---

### 14 — TCP options bomb `[raw]`

A SYN whose option block is filled to the 40-byte maximum: the cost is in option
parsing, not in volume.

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 --l4-mode tcp-options \
  --rate 50000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode tcp-options` | SYN with a maximal option block. It opens legitimate state, so stateful devices on the path pass it. |

---

### 15 — ICMP flood `[raw]`

```sh
sudo -E jinrai $A --target $T --layer l3 --l4-mode icmp \
  --payload-size 1400 --rate 50000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode icmp` | Echo-request flood. Swap for `icmp-timestamp` (type 13) or `icmp-address-mask` (type 17): each one forces the target to **answer directly**. |
| *(no `--port`)* | ICMP modes are portless. Passing `--port` here does nothing. |
| `--layer l3` | True L3. |
| `--payload-size 1400` | Payload bytes in the echo. |

---

### 16 — GRE flood `[raw]`

An outer IPv4 header with protocol 47, the 4-byte version-0 GRE header
(RFC 2784), and a complete IPv4/UDP datagram inside it. A target that accepts
protocol 47 must recognise it, strip the outer header and **re-enter its own IP
stack** with the inner packet — roughly two packets' worth of work for one
packet of bandwidth.

```sh
sudo -E jinrai $A --target $T --port 53 --layer l3 --l4-mode gre \
  --rate 20000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode gre` | The encapsulated flood. |
| `--port 53` | ⚠️ The destination port of the **inner** datagram, not the outer one (GRE has no ports). |

> **No spoofing inside the tunnel either:** the encapsulated datagram is
> addressed from the same real source as the outer packet, and the builder has no
> argument with which to express anything else.

---

### 17 — Multi-vector: UDP + TCP `[raw]`

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 \
  --l4-mode udp --l4-mode syn --rate 60000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode` repeated | **Each occurrence adds a vector.** They run concurrently, one thread each, against the same targets, sharing one `--duration`, one kill switch, one audit record and one summary. |
| `--rate 60000` | ⚠️ **The ceiling is shared, not per vector.** Two vectors at 60 000 emit **30 000/s each**. A ceiling that multiplies behind the operator's back is not a ceiling. A rate too small to split is refused rather than rounding a vector to zero. |

**How to read it:** the `of which` row gives the **per-vector breakdown** — one
total cannot tell "both vectors landed" from "one did all the work".

---

### 18 — Multi-vector: UDP / TCP / ICMP `[raw]`

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 \
  --l4-mode udp --l4-mode syn --l4-mode icmp --rate 60000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l4-mode icmp` in the mix | Allowed. `--port` is still required **for the vectors that address one**; ICMP ignores it. |
| `--layer l4` | An all-ICMP run reports L3, a mixed run reports **L4**: calling a run that floods a port "L3" would understate it. |
| `--rate 60000` | 3 vectors → 20 000/s each. |

---

### 19 — Multi-vector: fragmentation + flood `[raw]`

```sh
sudo -E jinrai $A --target $T --port 1-65535 --port-order random --layer l4 \
  --l4-mode udp-frag --l4-mode tcp-frag --l4-mode udp --rate 60000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| three `--l4-mode` | 20 000 units/s each. ⚠️ In packets: udp-frag ×2 + tcp-frag ×3 + udp ×1 = **120 000 packets/s**. Preflight checks **every** vector, so a missing `CAP_NET_RAW` stops the run before any traffic. |
| `--port-order random` | Applies to every vector that addresses a port. |

---

## L7 test cases

None of these need privileges. All use `--url` instead of `--target`.

### 20 — GET flood, with a verdict

```sh
jinrai $A --url $URL --l7-method get --rate 2000 --duration 60 \
  --slo-max-5xx-rate 0.01 --slo-max-p99-ms 500 $REQ
```

| Switch | What it does here |
|---|---|
| `--url $URL` | The authorized datum. The host is resolved once and pinned. |
| `--l7-method get` | Fast request flood (the default). Swap for `post` or `head`. |
| `--rate 2000` | Requests per second. |
| `--slo-max-5xx-rate 0.01` | **The run FAILS if more than 1% of responses are 5xx.** An unmet SLO exits non-zero: that is how a pipeline tells "the target held" from "the target buckled". |
| `--slo-max-p99-ms 500` | FAIL if end-of-run p99 latency exceeds 500 ms. |

Other SLOs available: `--slo-max-error-rate <0.0-1.0>` (transport errors) and
`--slo-max-4xx-rate <F>` (off by default).

---

### 21 — Random-path flood

Every request asks for a URI that **does not exist**: nothing is cacheable, and
the origin answers (and usually logs) all of it.

```sh
jinrai $A --url $URL --l7-method get --random-path --rate 2000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--random-path` | Appends a fresh random segment to the path on every request. It touches the path **only**: the host is never altered, so the authorization and the DNS pin hold for every request of the run. |

**How to read it:** 100% 4xx here is the test working, not the target failing —
the summary says so with `varying: random path`.

---

### 22 — Valid-random flood

The same idea, but the paths come from endpoints that **do exist**: the load
lands on real handlers rather than the 404 path.

```sh
jinrai $A --url $URL --l7-method get --path-file ./endpoints.txt \
  --rate 2000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--path-file <PATH>` | One path per line, blank lines and `#` comments skipped, **every entry must start with a single `/`**. An entry that would move the run to another origin **refuses the run** — it is never silently skipped, because skipping it would mean the list ran differently than it reads. An unreadable file fails at argument-parse time, before the lab acknowledgement. |

Example `endpoints.txt`:

```
# real endpoints on the target
/api/v1/health
/api/v1/users?page=2
/static/app.css
```

---

### 23 — POST flood

```sh
jinrai $A --url $URL --l7-method post --body '{"q":"load"}' --cache-bust \
  --rate 1000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method post` | The write path. |
| `--body '<STRING>'` | The body sent with every POST. |
| `--cache-bust` | Appends a unique `_cb=<n>` query so a cache or CDN cannot answer for the origin. |

---

### 24 — Search-field flood

The one query a cache can never serve: a fresh term on every request.

```sh
jinrai $A --url ${URL}search --l7-method get --search-param q \
  --rate 2000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--search-param q` | Sends `q=<random term>` on every request: in the query string for `get`/`head`, in a form-encoded body for `post` (where it **replaces** `--body`). The term is a pronounceable word, not a hex blob: a blob is equally uncacheable, but a term that looks like a term reaches the same code path a real query does. |

---

### 25 — Session exhaustion

A fresh session **and** a fresh query per request: neither the cache nor the
session store can absorb any of it.

```sh
jinrai $A --url $URL --l7-method get --session-cookie JSESSIONID --search-param q \
  --rate 2000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--session-cookie JSESSIONID` | Sends a distinct, unrecognised `JSESSIONID=<value>` cookie per request, so the target allocates or looks up session state for each one instead of reusing a single session for the whole run. Use the right name for the stack under test: `JSESSIONID`, `PHPSESSID`, `connect.sid`, `ASP.NET_SessionId`. |
| `--search-param q` | As in test 24; they compose. |

---

### 26 — Keep-alive connection exhaustion

The controlled form of the connection-slot attacks: the load is pinned to a
maximum number of connections held busy.

```sh
jinrai $A --url $URL --l7-method get --max-connections 50 --rate 5000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--max-connections 50` | Caps concurrent in-flight requests ≈ concurrent keep-alive connections (default 1024). It is how you probe a server's connection-slot / worker limit. **`--rate` alone does not bound connections**: against a slow target, rate × latency *is* the socket count, and this flag is what keeps the run from becoming a descriptor self-test on your own box. `0` means unbounded — an explicit choice, never the default. |

---

### 27 — Slowloris

Half-open connections, one header line each every so often to keep them alive.

```sh
jinrai $A --url $URL --l7-method slowloris --slow-connections 500 --drip-ms 10000 \
  --rate 50 --duration 300 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method slowloris` | Slow partial headers. Works on `https://` too (a real TLS handshake, then the dribble happens inside the tunnel). |
| `--slow-connections 500` | **Concurrent connection ceiling** for the slow modes and for websocket/sse (default 100). This is the number you are actually testing. |
| `--drip-ms 10000` | Interval between ticks (default 10000): here, how often a piece of header is written. Keep it **below** the target's read timeout, or the target closes first and you have measured nothing. |
| `--rate 50` | ⚠️ For slow modes the ceiling is **connections opened per second**, not requests. With 500 connections at 50/s it takes 10 s to reach steady state. |
| `--duration 300` | These tests are only meaningful when long. |

**How to read it:** declaring the connection ceiling **silences** the shortfall
notes (`bound by`): the run stopped opening because it hit the ceiling you asked
for, not because the host could not go faster.

---

### 28 — RUDY (slow POST body)

```sh
jinrai $A --url $URL --l7-method slowbody --slow-connections 500 --drip-ms 10000 \
  --rate 50 --duration 300 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method slowbody` | A complete request with a declared `Content-Length`, body trickled. |
| `--drip-ms 10000` | Interval between body chunks. |

Everything else: as in test 27.

---

### 29 — Slow read

The read-side mirror of slowbody: a complete, well-formed request, then the
response is drained one small chunk per tick with a shrunken receive window, so
the server cannot flush its buffer.

```sh
jinrai $A --url $URL --l7-method slow-read --slow-connections 500 --drip-ms 10000 \
  --rate 50 --duration 300 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method slow-read` | As above. Point it at a URL that returns a **large** response, or there is nothing to hold back. |
| `--drip-ms 10000` | Here it is the **read** interval, one chunk per tick. |

---

### 30 — WebSocket session exhaustion

The test no read timeout retires: nothing is slow and nothing is malformed —
these are correct sessions that stay open.

```sh
jinrai $A --url ${URL}ws --l7-method websocket --slow-connections 500 \
  --drip-ms 15000 --rate 100 --duration 300 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method websocket` | A proper RFC 6455 upgrade, with a fresh 16-byte `Sec-WebSocket-Key` per connection. |
| `--url ${URL}ws` | ⚠️ **`http://` and `https://`, not `ws://`/`wss://`** — the upgrade *is* an HTTP/1.1 request. For wss, use `https://`. |
| `--slow-connections 500` | Concurrent sessions held: the ceiling you are measuring. |
| `--drip-ms 15000` | Interval of the masked empty Ping that keeps the session alive. |
| `--rate 100` | Connections opened per second. |

**How to read it:** the `of which` row separates a server **declining** the
transport (wrong path, upgrade unsupported) from a connection that never got an
answer. Those are different things and one counter cannot tell them apart.

---

### 31 — SSE session exhaustion

The same idea with an event stream, which needs no keep-alive at all: the server
holds it open by design.

```sh
jinrai $A --url ${URL}events --l7-method sse --slow-connections 500 \
  --rate 100 --duration 300 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method sse` | A normal `Accept: text/event-stream` GET, held open and drained. |

---

### 32 — TLS handshake flood

Full handshake, connection dropped, repeat: the asymmetry is entirely in the
server's crypto cost.

```sh
jinrai $A --url https://$T/ --l7-method tls-handshake --max-connections 200 \
  --rate 500 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method tls-handshake` | **`https://` only.** The ceiling counts handshakes per second. |
| `--url https://...` | Must be TLS. The server certificate is **not verified**, deliberately: the safety boundary is the authorized, pinned host, not the TLS peer identity; the run sends no secrets and reads no response. |
| `--max-connections 200` | Applies to the one-connection-per-unit TLS methods too. |

---

### 33 — TLS ClientHello parser stress

No handshake is completed: the whole connection is spent making the target parse
a huge but **legal** ClientHello.

```sh
jinrai $A --url https://$T/ --l7-method tls-big-hello --rate 500 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method tls-big-hello` | A well-formed hello inflated to the 16 KiB record ceiling: 2048 cipher-suite code points the server must intersect, plus RFC 7685 padding. Swap for `tls-sni-bomb`, which isolates the SNI: ~12 KiB of `server_name` built from legal ≤63-byte DNS labels, so it survives the syntax checks and **reaches the vhost lookup** instead of being discarded as malformed. |
| `--rate 500` | Hellos per second. |

**How to read it:** ⚠️ **do not read the completion count, read the `of which`
row.** `parsed` means the target did the work; `refused with an alert` is the
**healthy** result — the parser rejected it.

---

### 34 — HTTP/2 rapid reset (CVE-2023-44487)

Open a stream, immediately RST_STREAM: the client pays almost nothing, the
server pays, and the concurrent-stream limit does not stop it because the slot
frees instantly.

```sh
jinrai $A --url https://$T/ --l7-method h2-rapid-reset --rate 5000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method h2-rapid-reset` | The ceiling counts **resets per second**. On `https` it uses ALPN `h2`; on `http`, prior-knowledge h2c. |

---

### 35 — The other HTTP/2 floods

Exactly the shape of test 34; only `--l7-method` changes:

| Method | What the server is made to do |
|---|---|
| `h2-made-you-reset` | CVE-2025-8671: a complete request then a 0-increment WINDOW_UPDATE, so **the server** resets the stream (evading rapid-reset mitigations). |
| `h2-continuation` | CVE-2024-27316: HEADERS without END_HEADERS plus endless CONTINUATION frames. |
| `h2-settings` | CVE-2019-9515: empty SETTINGS frames the server must ACK. |
| `h2-ping` | CVE-2019-9512: PING frames the server must PONG. |
| `h2-window-update` | CVE-2019-9514: connection-level flow-control updates on stream 0. |
| `h2-priority` | CVE-2019-9513 (Resource Loop): frames that reshuffle the priority tree. |
| `h2-empty-data` | CVE-2019-9518: 0-length DATA frames without END_STREAM. |
| `h2-bomb` | CVE-2026-49975: HPACK 1-byte-reference header amplification plus a zero initial window, so the amplified memory stays pinned. |

For all of them, `--rate` counts **frames per second**.

---

### 36 — Header-profile test

```sh
jinrai $A --url $URL --l7-method get \
  --header 'User-Agent: LoadTest/1.0' --header 'Referer: https://intranet/' \
  --rate 2000 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--header '<K: V>'` | An extra request header, **repeatable**. This is the hook for request-profile tests (User-Agent, Referer, Cookie…). Requests already carry `User-Agent: jinrai/<version>`; a `--header` of the same name replaces it. |

> Note: User-Agent/Referer rotation in the HULK style is **out of scope by
> design** — that is evasion, not load. This flag exists to send a declared
> profile, not to hide one.

**When the summary and the target's log disagree.** Two request properties decide
whether a run measures the target or the appliance in front of it, and both show
up as a status class you cannot reproduce in a browser against the same URL:

* **No `User-Agent`** — a WAF or bot filter answers a headerless request with a
  challenge or a redirect, so the run reports the filter, not the target. Every
  request now identifies itself; override with `--header` when the test is about
  a specific client profile.
* **A redirect that was counted, not followed** — a target answering `302` to a
  login page reports `3xx 100%`, while a browser ends on the `404` two hops
  later. `--follow-redirects <N>` records the status at the end of the chain
  instead, for up to `N` hops that stay on the authorized origin (host, port and
  scheme unchanged — a `Location:` naming anything else always stops the chain
  and reports the `3xx`). **It costs rate**: a followed hop is a second request
  `--rate` never counted, so `N` hops can offer up to `(1 + N) x --rate`
  requests/sec. Keep `N` at the chain length you actually expect, usually `1`.

---

### 37 — QUIC handshake flood

The same asymmetry as case 32, one step earlier and over UDP: the server
decrypts an Initial, parses a ClientHello and **signs with its private key** for
a client that has proved only that it can receive one round trip.

Run it even when case 32 was fine. HTTP/3 is normally a different code path
behind a different protocol, and the rate limit protecting 443/TCP is often
simply absent from 443/UDP.

```sh
jinrai $A --url https://$T/ --l7-method quic-handshake --max-connections 200 \
  --rate 500 --duration 60 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method quic-handshake` | **`https://` only** — there is no plaintext QUIC. Negotiates ALPN `h3`. The ceiling counts handshakes per second. |
| `--max-connections 200` | Handshakes **in flight**, not total. A target that stalls mid-handshake would otherwise turn the rate into an ever-growing socket count on your own box. |
| `--url https://...` | The certificate is **not verified**, for the same reason as case 32: the boundary is the authorized, pinned host. |

**How to read it:** the `of which` row separates **refused** — the peer answered
in QUIC and declined, nearly always because it does not offer `h3` — from plain
errors. A run that is all refusals is telling you about the endpoint, not its
capacity.

---

### 38 — QUICLORIS

Slowloris carried to HTTP/3: a proper control stream with `SETTINGS`, then a
request stream whose `HEADERS` frame promises 4 KiB and delivers one byte per
tick.

Why this is not case 27 again: an HTTP/1.1 Slowloris is retired by a
request-header read timeout, which every mainstream server grew. QUIC's
equivalent budget is the **idle timeout** — and a connection that is dribbling is
never idle, so the timer that reclaims an abandoned QUIC connection never fires.
Whether anything else reclaims it is the question this run answers.

```sh
jinrai $A --url https://$T/ --l7-method quicloris --slow-connections 300 \
  --drip-ms 10000 --rate 50 --duration 300 $REQ
```

| Switch | What it does here |
|---|---|
| `--l7-method quicloris` | **`https://` only**, ALPN `h3`. Nothing sent is malformed — the request is merely never finished. |
| `--slow-connections 300` | The real bound: connections opened and then **held** for the whole run. |
| `--drip-ms 10000` | One byte of the unfinished `HEADERS` frame every 10s. |
| `--rate 50` | Connections **opened** per second — how fast the 300 are reached, not how fast bytes flow. |
| `--duration 300` | How long they are held. This is the measurement. |

**How to read it:** if all 300 hold for the whole run with no errors, the target
has no concurrent-connection cap, no per-IP limit and no reaper on its HTTP/3
listener.

---

## Capacity test cases

### 39 — Breaking point (knee)

Steps up to the ceiling and **stops at the first step that breaks the SLO**,
reporting the knee of the capacity curve.

```sh
jinrai $A --url $URL --rate 5000 --duration 300 --discover-knee \
  --slo-max-5xx-rate 0.02 $REQ
```

| Switch | What it does here |
|---|---|
| `--discover-knee` | Turns on breaking-point discovery. **Requires at least one `--slo-max-*-rate`**, or the run is refused: without a threshold there is no way to know what "broken" means. Finding the knee is a **success** (exit 0). The watchdog is suppressed during discovery. |
| `--slo-max-5xx-rate 0.02` | The threshold that defines "broken": 2% 5xx. |
| `--rate 5000` | The top of the ramp. |
| `--duration 300` | Total window, divided across the steps. |

**How to read it:** the `knee` row says *held X/s within SLO, first breached at
Y/s*.

---

### 40 — Burst / autoscaling

Holds a baseline, jumps to the ceiling, falls back: the shape that tests how
fast autoscaling reacts.

```sh
jinrai $A --url $URL --profile spike --spike-base 200 --spike-secs 30 \
  --rate 5000 --duration 300 $REQ
```

| Switch | What it does here |
|---|---|
| `--profile spike` | The load shape. Others: `constant` (default), `soak`, `ramp`. |
| `--spike-base 200` | Baseline rate (default: ceiling ÷ 5). |
| `--spike-secs 30` | Peak duration. ⚠️ **Carved out of `--duration`, never added to it**: the baseline fills the rest of the window. |
| `--rate 5000` | The peak *is* the ceiling. A profile shapes traffic **only up to** `--rate`, never above it. |

---

### 41 — Endurance / soak, with a watchdog

```sh
jinrai $A --url $URL --profile soak --rate 500 --duration 3600 \
  --watchdog --slo-max-5xx-rate 0.05 $REQ
```

| Switch | What it does here |
|---|---|
| `--profile soak` | A long flat hold: it surfaces leaks and slow degradation. |
| `--duration 3600` | One hour. |
| `--watchdog` | **Aborts the run** when a rate SLO is breached for several consecutive windows. It can only ever **stop** traffic, never increase it. Inert without at least one `--slo-max-*-rate` to watch (it warns). |
| `--slo-max-5xx-rate 0.05` | What the watchdog watches. |

Tunable: `--watchdog-window <SECS>` (sample window, default 5) and
`--watchdog-breaches <K>` (consecutive breaching windows before abort, default 3).

**How to read it:** a watchdog abort prints `outcome` in **red** and exits
non-zero.

---

### 42 — Ramp

```sh
jinrai $A --url $URL --profile ramp --ramp-start 100 --ramp-steps 10 \
  --rate 5000 --duration 300 $REQ
```

| Switch | What it does here |
|---|---|
| `--profile ramp` | Steps up from `--ramp-start` to the ceiling. |
| `--ramp-start 100` | Starting rate (default 0). |
| `--ramp-steps 10` | Number of equal-length steps (default 10). |

---

## Out of scope, and why

| Use case | Why it is not here |
|---|---|
| **UDP DNS / NTP reflection** | Requires source-IP spoofing. jinrai has no spoofing path **by design**: the source address always comes from real routing, in every mode, GRE encapsulation included. That is the guarantee that makes this tool usable in-house. |
| Smurf / Fraggle / amplification | Same reason: they are reflection attacks. |
| QUIC Retry / token-replay amplification, QUIC reflection via the cert exchange | Same reason again, and worth naming explicitly because QUIC is the protocol most easily turned into a reflector: every variant needs a **forged Initial**. Cases 37–38 bind an ordinary client UDP socket and let the OS assign the source, which is the whole difference between a QUIC load test and a QUIC reflector. |
| Ping of Death / teardrop / Boink | Historical stack crashes, not resilience tests. |
| HULK-style UA/Referer rotation | Vendor-signature evasion, not load. |
| TLS renegotiation | Largely moot on TLS 1.3. |

---

## Reading the run summary

Every run ends with this block. On a terminal it is coloured
(`--color auto|always|never`).

```
==== run summary =========================================================
 target     http://10.0.0.10/
 module     L7 / l7-http-get  (HTTP/1.1 forced)
 window     60.0s elapsed of 60.0s planned, rate cap 2000/s
 started    2026-08-03T09:14:02Z
 finished   2026-08-03T09:15:02Z
 attempts   120000 total, 1994.2/s achieved (100% of the 2000/s cap)
 completed  119940 (99.9%)
   status   2xx 118000 (98.4%)  3xx 0 (0.0%)  4xx 800 (0.7%)  5xx 1140 (0.9%)
   protocol HTTP/1.1 119940
 failed     60 (0.1%), of which 60 timed out
            60 x timeout — our own attempt timeout expired first
 latency    p50 12.4ms   p90 45.1ms   p99 210.0ms   max 1.20s
 outcome    ran to completion
 SLO        FAIL (5xx-rate 0.9% > 0.5%)
==========================================================================
```

| Colour | Meaning |
|---|---|
| 🟢 **green** | the run did what it set out to do: `completed`, `failed 0`, `2xx`, `SLO: PASS`, `ran to completion` |
| 🟡 **yellow** | a caveat about **our** side: `bound by`, `not offered`, local errno buckets (EMFILE, EADDRNOTAVAIL…), an operator abort, `4xx` |
| 🔴 **red** | failure, and the target's own errors: `failed`, `5xx`, remote errno buckets, `SLO: FAIL`, a watchdog abort, the hollow-run `WARNING` |

The lines never to skip:

- **`attempts … achieved (…% of the cap)`** — says whether the load that was
  asked for was actually produced. Without it, a result reads as "the target
  coped" even when the generator never reached the rate.
- **`bound by`** (yellow) — appears when the run did not reach its cap, and
  **names the constraint**. A low percentage with **zero failures** is the most
  misreadable line this tool can print: it looks exactly like a target absorbing
  the difference. If it says `the generator, not the target` or `concurrency,
  not the target`, that shortfall is **not absorbed load**.
- **`of which`** — the breakdown for cases where "completed" covers outcomes
  that mean opposite things: per vector in multi-vector runs, parsed vs. refused
  in the TLS hello tests, declined vs. unanswered for websocket and sse.
- **`failed` plus the errno buckets** — they say **whose** failure it was.
  `ECONNREFUSED`, `ETIMEDOUT` and `ECONNRESET` are target behaviour (the result
  you came for); `EMFILE`, `ENFILE`, `ENOBUFS` and `EADDRNOTAVAIL` are a ceiling
  on **your** host and say nothing about the target.
- **`WARNING`** — 0 completions with only failures: nothing was tested, and the
  process exits non-zero. A `completed 0` is **red**, not green, and in that case
  `outcome` turns yellow too: a green "ran to completion" above a red WARNING
  would be exactly the confidently-wrong green to avoid.

---

## Verifying the audit log

```sh
jinrai --verify-audit ./runs.jsonl
```

Recomputes the whole hash chain and prints every record in readable form. Exits 0
if it is intact, non-zero naming the first break. The chain **continues across
processes**, which is what makes a deleted middle run detectable.

Honest about the limit: this is **tamper-evidence, not non-repudiation**. Anyone
who rewrites the whole file can recompute a clean chain; closing that needs an
HMAC or an external anchor, and it is out of scope.

---

## When a run reaches nothing

A stateful firewall, IDS or middlebox anywhere on the path can drop out-of-state
segments before they are delivered — typically every mode at tests 12 and 13:
`ack`, `fin`, `rst`, `urg`, `cwr`, `ece`, `syn-ack`, `syn-fin`, `syn-rst`,
`xmas`, `null`.

**The local `sendto()` still succeeds**, so jinrai reports
`50000 completed (100%), failed 0` for a run that reached nothing at all. There
is no signal in the summary — the send succeeded, and the tool cannot see past
its own NIC. Confirming delivery has to happen off-tool.

Capture **at the source** to prove what left, and **on the target itself** to
prove what arrived:

```sh
# on the host running jinrai
tcpdump -ni any 'host <target> and tcp port 445'

# on the target
tcpdump -ni any 'host <source> and tcp port 445'
```

Never diagnose this from a third machine: a host that is neither source nor
target sees whatever the switching fabric happens to give it, which is not
evidence either way. If the target's own firewall keeps counters, zero them
before the run and read them after — a counter matching the run's unit count on
an "invalid state" rule is the signature.

The modes that always get through, because they open legitimate connection
state: `syn`, `tcp-options`, `udp`, `tcp`, `data`, the three ICMP modes, and all
of L7.

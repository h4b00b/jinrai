#!/usr/bin/env bash
# Acceptance checks for the tcp-connect-flood fix.
#
# Every case uses the `backlog` listener: bind + listen(4096) and no accept loop
# at all, so the kernel completes each handshake into the accept queue. A
# userspace accept loop under WSL stalls unpredictably and shows up as
# ECONNREFUSED, which would be indistinguishable from a real regression. The
# constraint is that a case must stay under the 4096 backlog, so high rates use a
# short duration.
set -uo pipefail
cd "$(dirname "$0")/.."
. "$HOME/.cargo/env"

BIN=target/release/jinrai
GATE=(--layer l4 --l4-mode tcp --allow 127.0.0.0/8 --target 127.0.0.1 --ack-l34-lab)
PORT=${PORT:-19600}
cargo build --offline --release -q || exit 1

listen_up() {  # <listener_secs>
  PORT=$((PORT + 1))
  : > /tmp/L.log
  ( ulimit -n 65535 2>/dev/null
    exec python3 scripts/lab_listener.py "$PORT" "$1" backlog ) 2>/tmp/L.log &
  LP=$!
  for _ in $(seq 60); do grep -q LISTENING /tmp/L.log 2>/dev/null && return 0; sleep 0.05; done
  echo "  !! listener failed to bind $PORT"
}
listen_down() { kill "$LP" 2>/dev/null; wait "$LP" 2>/dev/null; sleep 1; }

# Run the flood while sampling its open-descriptor count every 0.5s.
flood_with_fds() {  # <jinrai args...>
  "$BIN" "${GATE[@]}" --port "$PORT" "$@" > /tmp/J.log 2>&1 &
  local jp=$!
  : > /tmp/F.log
  while kill -0 "$jp" 2>/dev/null; do
    ls "/proc/$jp/fd" 2>/dev/null | wc -l >> /tmp/F.log
    sleep 0.5
  done
  wait "$jp"
}

report() {
  grep -E '^\[L4|^fd ceiling' /tmp/J.log | sed 's/^/  | /'
  if [ -s /tmp/F.log ]; then
    echo "  fd samples: $(tr '\n' ' ' < /tmp/F.log)"
    echo "  fd peak:    $(sort -n /tmp/F.log | tail -1)"
  fi
}

echo "===== 1. fd count plateaus at --concurrency (256), does not ramp"
listen_up 16; flood_with_fds --rate 200 --duration 10 --concurrency 256; report; listen_down
echo
echo "===== 2. same, smaller cap (64): plateau must track the cap"
listen_up 16; flood_with_fds --rate 200 --duration 10 --concurrency 64; report; listen_down
echo
echo "===== 3. doubling --duration must not change the peak fd count"
echo "  -- 5s --"
listen_up 12; flood_with_fds --rate 200 --duration 5 --concurrency 128; report; listen_down
echo "  -- 10s (2x) --"
listen_up 18; flood_with_fds --rate 200 --duration 10 --concurrency 128; report; listen_down
echo "  -- 20s (4x) --"
listen_up 28; flood_with_fds --rate 100 --duration 20 --concurrency 128; report; listen_down
echo
echo "===== 4. hard+soft ulimit -n 1024, rate 200 duration 10 -> ZERO EMFILE"
listen_up 18
( ulimit -Sn 1024; ulimit -Hn 1024
  echo "  shell: soft=$(ulimit -Sn) hard=$(ulimit -Hn)"
  "$BIN" "${GATE[@]}" --port "$PORT" --rate 200 --duration 10 ) > /tmp/J.log 2>&1
: > /tmp/F.log; grep shell: /tmp/J.log; report; listen_down
echo
echo "===== 5. --concurrency 4000 under a hard 1024 ceiling -> EMFILE, named"
listen_up 12
( ulimit -Sn 1024; ulimit -Hn 1024
  "$BIN" "${GATE[@]}" --port "$PORT" --rate 600 --duration 5 --concurrency 4000 ) \
  > /tmp/J.log 2>&1
: > /tmp/F.log; report; listen_down
echo
echo "===== 6. Pacer: attempts vs rate*duration (duration 2s to stay under backlog)"
printf '  %-6s %-9s %-9s %-8s %-9s %s\n' rate expected attempts errors achieved latency
for rate in 50 100 200 400 800 1600; do
  listen_up 8
  "$BIN" "${GATE[@]}" --port "$PORT" --rate "$rate" --duration 2 --concurrency 256 \
    > /tmp/J.log 2>&1
  listen_down
  line=$(grep '^\[L4' /tmp/J.log)
  sent=$(printf '%s' "$line" | grep -o 'sent=[0-9]*' | cut -d= -f2)
  errs=$(printf '%s' "$line" | grep -o 'errors=[0-9]*' | cut -d= -f2)
  lat=$(printf '%s' "$line" | grep -o 'latency_us([^)]*)')
  bkt=$(printf '%s' "$line" | grep -o 'errno([^)]*)')
  expected=$((rate * 2))
  attempts=$(( ${sent:-0} + ${errs:-0} ))
  pct=$(awk -v a="$attempts" -v e="$expected" 'BEGIN{printf "%.1f%%", 100*a/e}')
  printf '  %-6s %-9s %-9s %-8s %-9s %s %s\n' \
    "$rate" "$expected" "$attempts" "${errs:-0}" "$pct" "$lat" "$bkt"
done

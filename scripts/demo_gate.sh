#!/usr/bin/env bash
# Demo: exercise the safety gate end-to-end.
#
# Each case asserts *why* it failed, not just that it failed. Without that the
# demo is worthless as a regression check: a case that exits 1 because a required
# flag is missing looks identical to one refused by the gate, so the gate could be
# removed entirely and this script would still print all-green.
set -u
BIN=./target/debug/jinrai

fail=0

# expect <exit-code> <substring> -- <argv...>
expect() {
  local want_code="$1" want_text="$2"; shift 3   # third arg is the literal --
  local out code
  out=$("$@" 2>&1); code=$?
  if [ "$code" != "$want_code" ]; then
    echo "  FAIL: expected exit $want_code, got $code"
    echo "$out" | sed 's/^/    | /'
    fail=1
  elif ! printf '%s' "$out" | grep -qF -e "$want_text"; then
    echo "  FAIL: exit $code was right, but for the wrong reason"
    echo "    expected output to mention: $want_text"
    echo "$out" | sed 's/^/    | /'
    fail=1
  else
    echo "  ok (exit $code, for the stated reason)"
  fi
}

echo "=== CASO 1: target autorizzato (10.1.2.3 in 10.0.0.0/8) -> deve passare il gate ==="
# --rate 0 exercises authorization without emitting anything: the gate runs, the
# run is planned, and the engine honours the zero cap before opening a socket.
expect 0 "authorized" -- \
  "$BIN" --layer l7 --url http://10.1.2.3/ \
         --allow 10.0.0.0/8 --allow 192.168.0.0/16 --rate 0 --duration 1
echo

echo "=== CASO 2: target FUORI allowlist (8.8.8.8) -> deve rifiutare ==="
expect 1 "refusing L7 run" -- \
  "$BIN" --layer l7 --url http://8.8.8.8/ --allow 10.0.0.0/8 --rate 0 --duration 1
echo

echo "=== CASO 3: nessun --allow -> fail-closed ==="
expect 1 "no --allow rules given" -- \
  "$BIN" --layer l7 --url http://10.0.0.1/ --rate 0 --duration 1
echo

echo "=== CASO 4: l4 senza --ack-l34-lab -> deve rifiutare ==="
expect 1 "--ack-l34-lab" -- \
  "$BIN" --layer l4 --allow 10.0.0.0/8 --target 10.1.2.3 --port 80 --rate 0 --duration 1
echo

echo "=== CASO 5: --rate oltre il tetto -> rifiutato al parse ==="
expect 1 "--rate must be at most" -- \
  "$BIN" --layer l7 --url http://10.1.2.3/ --allow 10.0.0.0/8 --rate 99999999999
echo

if [ "$fail" = 0 ]; then echo "all gate cases behaved as specified"; else echo "GATE DEMO FAILED"; fi
exit "$fail"

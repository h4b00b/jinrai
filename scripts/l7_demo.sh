#!/usr/bin/env bash
set -u
. "$HOME/.cargo/env"
cd /mnt/d/projects/jinrai

PORT=18080
python3 -m http.server "$PORT" --bind 127.0.0.1 >/tmp/jinrai_http.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 1

echo "===== BUILD ====="
cargo build -q 2>&1 | tail -3
BIN=target/debug/jinrai

echo
echo "===== CASE A: authorized (127.0.0.1 inside 127.0.0.0/8) — should SEND ====="
"$BIN" --allow 127.0.0.0/8 --layer l7 --url "http://127.0.0.1:$PORT/" --rate 5 --duration 2
echo "exit=$?"

echo
echo "===== CASE B: out-of-allowlist (127.0.0.1 NOT inside 10.0.0.0/8) — should REFUSE ====="
"$BIN" --allow 10.0.0.0/8 --layer l7 --url "http://127.0.0.1:$PORT/" --rate 5 --duration 2
echo "exit=$?"

echo
echo "server access log (proves requests only hit the authorized case):"
grep -c "GET" /tmp/jinrai_http.log || true

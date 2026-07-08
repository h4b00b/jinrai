#!/usr/bin/env bash
set -u
. "$HOME/.cargo/env"
cd /mnt/d/projects/jinrai

PORT=18090
python3 -m http.server "$PORT" --bind 127.0.0.1 >/tmp/jinrai_datum.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 1

cargo build -q 2>&1 | tail -3
BIN=target/debug/jinrai
echo "localhost resolves to:"; getent hosts localhost || true
echo

echo "===== CASE A: DNS-name allow authorizes a hostname URL — should SEND ====="
echo "  --allow localhost  --url http://localhost:$PORT/"
"$BIN" --allow localhost --layer l7 --url "http://localhost:$PORT/" --rate 5 --duration 1
echo "exit=$?"
echo

echo "===== CASE B: IP/CIDR allow authorizes an IP-literal URL — should SEND ====="
echo "  --allow 127.0.0.0/8  --url http://127.0.0.1:$PORT/"
"$BIN" --allow 127.0.0.0/8 --layer l7 --url "http://127.0.0.1:$PORT/" --rate 5 --duration 1
echo "exit=$?"
echo

echo "===== CASE C: name NOT in DNS allowlist REFUSED even though it resolves to an allowlisted IP ====="
echo "  --allow 127.0.0.0/8  --url http://localhost:$PORT/   (localhost -> 127.0.0.1, but only an IP rule exists)"
"$BIN" --allow 127.0.0.0/8 --layer l7 --url "http://localhost:$PORT/" --rate 5 --duration 1
echo "exit=$?"
echo

echo "===== CASE D: wildcard DNS rule, name NOT matching — REFUSED ====="
echo "  --allow *.staging.internal  --url http://localhost:$PORT/"
"$BIN" --allow '*.staging.internal' --layer l7 --url "http://localhost:$PORT/" --rate 5 --duration 1
echo "exit=$?"
echo

echo "server GET count (only the authorized sends should appear): $(grep -c GET /tmp/jinrai_datum.log)"

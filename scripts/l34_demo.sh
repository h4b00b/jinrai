#!/usr/bin/env bash
# End-to-end demo of the L3/L4 module. Starts local listeners, runs the CLI
# against 127.0.0.1 only, and shows the safety refusals. Lab/loopback only.
set -u
. "$HOME/.cargo/env"
cd /mnt/d/projects/jinrai || exit 1

cargo build -q 2>&1 | tail -3
BIN=./target/debug/jinrai

UDP_PORT=18091
TCP_PORT=18092

# UDP listener (background).
python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('127.0.0.1',$UDP_PORT))
while True:
    s.recvfrom(2048)
" &
UDP_PID=$!

# TCP listener (background).
python3 -m http.server "$TCP_PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
TCP_PID=$!
sleep 1

cleanup() { kill "$UDP_PID" "$TCP_PID" 2>/dev/null; }
trap cleanup EXIT

echo "=== CASE 1: missing --ack-l34-lab -> refused ==="
"$BIN" --allow 127.0.0.0/8 --layer l4 --l4-mode udp --target 127.0.0.1 --port $UDP_PORT --rate 50 --duration 1
echo "exit=$?"; echo

echo "=== CASE 2: target outside allowlist -> refused ==="
"$BIN" --allow 10.0.0.0/8 --layer l4 --l4-mode udp --target 127.0.0.1 --port $UDP_PORT --ack-l34-lab --rate 50 --duration 1
echo "exit=$?"; echo

echo "=== CASE 3: UDP flood to 127.0.0.1 (authorized) ==="
"$BIN" --allow 127.0.0.0/8 --layer l4 --l4-mode udp --target 127.0.0.1 --port $UDP_PORT --ack-l34-lab --rate 200 --duration 1 --payload-size 32
echo "exit=$?"; echo

echo "=== CASE 4: TCP connect flood to 127.0.0.1 (authorized) ==="
"$BIN" --allow 127.0.0.0/8 --layer l4 --l4-mode tcp --target 127.0.0.1 --port $TCP_PORT --ack-l34-lab --rate 100 --duration 1
echo "exit=$?"; echo

echo "=== CASE 5: SYN flood as normal user -> graceful no-privilege error ==="
"$BIN" --allow 127.0.0.0/8 --layer l4 --l4-mode syn --target 127.0.0.1 --port $TCP_PORT --ack-l34-lab --rate 50 --duration 1
echo "exit=$?"; echo

echo "=== CASE 6: SYN flood with sudo -n (best effort; may need password) ==="
if sudo -n true 2>/dev/null; then
  sudo -n "$BIN" --allow 127.0.0.0/8 --layer l4 --l4-mode syn --target 127.0.0.1 --port $TCP_PORT --ack-l34-lab --rate 50 --duration 1
  echo "exit=$?"
else
  echo "(passwordless sudo unavailable in this shell; skipping real SYN send)"
fi

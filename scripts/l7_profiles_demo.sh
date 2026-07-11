#!/usr/bin/env bash
# Live end-to-end check of Phase 6 (load profiles + breaking-point discovery).
# Starts throwaway loopback HTTP servers and drives the real CLI against them.
set -u
. "$HOME/.cargo/env"
cd /mnt/d/projects/jinrai
cargo build -q --bin jinrai 2>/dev/null
BIN=target/debug/jinrai

# A tiny always-503 server (simulates a target that buckles) and an always-200 one.
python3 - <<'PY' &
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(503); self.send_header('Content-Length','0'); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer(("127.0.0.1",18081),H).serve_forever()
PY
S503=$!
python3 - <<'PY' &
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.send_header('Content-Length','0'); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer(("127.0.0.1",18082),H).serve_forever()
PY
S200=$!
sleep 1

echo "===== 1) knee discovery vs an always-503 target (should find a knee, exit 0) ====="
$BIN --allow 127.0.0.0/8 --url http://127.0.0.1:18081/ \
     --profile ramp --ramp-steps 4 --rate 40 --duration 4 \
     --discover-knee --slo-max-5xx-rate 0.0
echo "exit=$?"

echo
echo "===== 2) knee discovery vs an always-200 target (no knee, held the ramp, exit 0) ====="
$BIN --allow 127.0.0.0/8 --url http://127.0.0.1:18082/ \
     --profile ramp --ramp-steps 4 --rate 40 --duration 4 \
     --discover-knee --slo-max-5xx-rate 0.0
echo "exit=$?"

echo
echo "===== 3) spike profile vs 200 target (base->peak->base, plain run) ====="
$BIN --allow 127.0.0.0/8 --url http://127.0.0.1:18082/ \
     --profile spike --spike-base 10 --rate 60 --spike-secs 1 --duration 2
echo "exit=$?"

echo
echo "===== 4) --discover-knee WITHOUT a rate SLO (should refuse, exit 1) ====="
$BIN --allow 127.0.0.0/8 --url http://127.0.0.1:18082/ --discover-knee --rate 40 --duration 2
echo "exit=$?"

kill $S503 $S200 2>/dev/null
wait 2>/dev/null
echo "done"

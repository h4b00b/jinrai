#!/usr/bin/env bash
set -u
. "$HOME/.cargo/env"
cd /mnt/d/projects/jinrai || exit 1
echo "--- build ---"
cargo build 2>&1 | tail -2
echo "--- SYN no-priv exit code (expect non-zero, refused before 'running') ---"
./target/debug/jinrai --allow 127.0.0.0/8 --layer l4 --l4-mode syn \
  --target 127.0.0.1 --port 80 --ack-l34-lab --rate 10 --duration 1
echo "exit=$?"

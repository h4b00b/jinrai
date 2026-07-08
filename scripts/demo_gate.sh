#!/usr/bin/env bash
# Demo: exercise the safety gate end-to-end (Phase 1).
set -u
BIN=./target/debug/jinrai

echo "=== CASO 1: target autorizzato (10.1.2.3 in 10.0.0.0/8) ==="
"$BIN" --allow 10.0.0.0/8 --allow 192.168.0.0/16 --target 10.1.2.3 --layer l7
echo "exit=$?"
echo

echo "=== CASO 2: target FUORI allowlist (8.8.8.8) -> deve rifiutare ==="
"$BIN" --allow 10.0.0.0/8 --target 8.8.8.8
echo "exit=$?"
echo

echo "=== CASO 3: nessun --allow -> fail-closed ==="
"$BIN" --target 10.0.0.1
echo "exit=$?"

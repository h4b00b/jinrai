#!/usr/bin/env bash
set -u
. "$HOME/.cargo/env"
cd /mnt/d/projects/jinrai || exit 1

echo "=== l34 unit tests ==="
cargo test -p jinrai-l34 2>&1 | grep -E "running [0-9]+ test|test result|^test tests::"

echo
echo "=== clippy (all targets, -D warnings) ==="
cargo clippy --all-targets -- -D warnings 2>&1 | tail -4

#!/usr/bin/env bash
# Rust harness: builds and runs the binary, writing results/raw/rust.jsonl.
# No network I/O is performed by the harness itself (cargo may fetch crates
# the first time it builds).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export PATH="/opt/homebrew/bin:$PATH"
mkdir -p ../../results/raw
RUSTC_VERSION="$(rustc --version)" cargo run --release --quiet -- --out ../../results/raw/rust.jsonl

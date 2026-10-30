#!/usr/bin/env bash
# Go harness entry point: builds and runs main.go, writing results/raw/go.jsonl.
# No network I/O is performed by the harness itself.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export PATH="/usr/local/go/bin:$PATH"
mkdir -p ../../results/raw
go run . -out ../../results/raw/go.jsonl

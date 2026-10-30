#!/usr/bin/env bash
# Reproduce the Node.js results: installs the pinned packages and runs the harness.
set -euo pipefail
cd "$(dirname "$0")"
npm install --no-audit --no-fund --silent
node run.mjs "$@"

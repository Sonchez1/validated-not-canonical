#!/usr/bin/env bash
# Reproduce the Python results: creates a venv, installs the libraries, runs the harness.
set -euo pipefail
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
[ -d .venv ] || "$PY" -m venv .venv
. .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
python run.py "$@"

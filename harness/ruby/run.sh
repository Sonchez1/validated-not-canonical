#!/usr/bin/env bash
# Reproduce the Ruby results: installs the gems into vendor/bundle, runs the harness.
set -euo pipefail
cd "$(dirname "$0")"
# The harness reads a UTF-8 corpus; make sure Ruby does not start in US-ASCII.
case "${LC_ALL:-${LANG:-}}" in
  *UTF-8*|*utf8*|*UTF8*) ;;
  *) export LC_ALL=C.UTF-8 ;;
esac
bundle install --quiet
bundle exec ruby run.rb --out ../../results/raw/ruby.jsonl "$@"

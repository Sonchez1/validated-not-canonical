#!/usr/bin/env bash
# PHP harness entry point: installs dependencies and writes results/raw/php.jsonl
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export PATH="/opt/homebrew/bin:$PATH"
composer install --no-interaction --quiet
php run.php --out ../../results/raw/php.jsonl

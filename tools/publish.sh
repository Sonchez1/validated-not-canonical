#!/usr/bin/env bash
# Publish the public view of this repository: corpus, harnesses, analysis code,
# README. Files that name affected libraries (results outputs, the paper
# source, reports, patches) are removed from the history of the pushed branch
# until the disclosure window closes. Run from anywhere; needs gh logged in as
# the publishing account.
#
#   tools/publish.sh                 # create Sonchez1/validated-not-canonical (public) and push
#   tools/publish.sh --update        # push the filtered current main to the existing repo
set -euo pipefail
REPO_SLUG=${REPO_SLUG:-Sonchez1/validated-not-canonical}
SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/vnc-public.XXXXXX")
WITHHELD="results/raw results/matrix-invisible.md results/matrix-confusable.md results/matrix-idna.md results/matrix-control.md results/disagreements.md results/findings.json results/findings.md results/summary.json paper/main.tex paper/generated.tex paper/main.pdf"

git clone -q "$SRC" "$WORK"
cd "$WORK"
git remote remove origin
git filter-branch -f --index-filter "git rm -r -q --cached --ignore-unmatch $WITHHELD" --prune-empty -- --all >/dev/null 2>&1
rm -rf .git/refs/original
git reflog expire --expire=now --all
git gc -q --prune=now
leak=$(git log main --name-only --pretty=format: | sort -u | grep -E '^(results/(raw|findings|disagree|matrix|summary)|paper/(main|generated)|reports/|fixes/.+/)' || true)
if [ -n "$leak" ]; then echo "refusing to push: withheld paths still in history:"; echo "$leak"; exit 1; fi
echo "filtered history: $(git rev-list --count main) commits, no withheld paths"

if [ "${1:-}" = "--update" ]; then
  git remote add origin "https://github.com/$REPO_SLUG.git"
  git push --force-with-lease origin main
else
  gh repo create "$REPO_SLUG" --public --source=. --remote=origin --push \
    --description "Validated but not canonical: how URL, e-mail and hostname validators in seven ecosystems handle invisible characters, confusables and IDNA edge cases"
  gh repo edit "$REPO_SLUG" --add-topic unicode-security --add-topic idna --add-topic url-parsing \
    --add-topic email-validation --add-topic parser-differential --add-topic security-research
fi
echo "published $REPO_SLUG from $WORK"

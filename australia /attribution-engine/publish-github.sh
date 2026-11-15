#!/usr/bin/env bash
# Publish this folder to a new GitHub repo with the GitHub CLI.  Usage: ./publish-github.sh [repo-name] [private|public]
set -euo pipefail
cd "$(dirname "$0")"
REPO="${1:-attribution-engine}"; VIS="${2:-private}"
command -v gh >/dev/null || { echo "Install GitHub CLI: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || gh auth login
[ -d .git ] || git init -q -b main
git add -A
git diff --cached --quiet || git commit -q -m "Attribution engine: schema, WF-00/01/02 workflows, installer, tests"
gh repo create "$REPO" "--$VIS" --source=. --remote=origin --push
echo "Done: $(gh repo view --json url -q .url)"

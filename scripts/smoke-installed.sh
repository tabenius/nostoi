#!/usr/bin/env bash
set -euo pipefail
nostoi --version
nostoi --help >/dev/null
nostoi tui --help >/dev/null
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
nostoi append "$root/chain.jsonl" --kind release.smoke --actor release-ci --body '{"installed":true}'
nostoi verify "$root/chain.jsonl" --json > "$root/report.json"
grep -Eq '"ok"[[:space:]]*:[[:space:]]*true' "$root/report.json"
nostoi head "$root/chain.jsonl" --json
nostoi append "$root/chain.sqlite" --kind release.smoke --body '{"installed":true}'
nostoi verify "$root/chain.sqlite" --json > "$root/sqlite-report.json"
grep -Eq '"ok"[[:space:]]*:[[:space:]]*true' "$root/sqlite-report.json"
sed 's/release.smoke/release.tampered/' "$root/chain.jsonl" > "$root/broken.jsonl"
set +e
nostoi verify "$root/broken.jsonl" --json
status=$?
set -e
test "$status" -eq 1

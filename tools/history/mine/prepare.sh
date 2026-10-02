#!/bin/bash
# usage: prepare.sh <repo> <outdir> [batch_size]
# Lists the fix commits of a repository oldest first and splits them into
# batches for the triage agents; saves the glint rule list next to them.
# Only reads the repository.
set -euo pipefail
repo=$1
out=$2
size=${3:-180}
mkdir -p "$out"

# Conventional-commit fixes, without the noise of analyzer, formatting and
# documentation work.
git -C "$repo" log --no-merges --format='%h%x09%ad%x09%s' --date=short \
  | awk -F'\t' '$3 ~ /^(fix|security|perf)/' \
  | grep -viE 'violation|analy[sz]er|lint|glint|golangci|quality|compliance|spam|прогресс|progress|итерац|typo|опечат|prettier|gofmt|форматир|readme|\bdocs?\b|документац|claude\.md|agents\.md' \
  > "$out/fix-all.tsv" || true

# Drop commits that touch documentation only; keep the count of changed files.
: > "$out/fix.tsv"
while IFS=$'\t' read -r hash date msg; do
  files=$(git -C "$repo" show --name-only --format= "$hash" | grep -cvE '\.(md|txt)$|^docs/|(^|/)VERSION$' || true)
  [ "$files" -gt 0 ] && printf '%s\t%s\t%s\t%s\n' "$hash" "$date" "$files" "$msg" >> "$out/fix.tsv"
done < "$out/fix-all.tsv"

tac "$out/fix.tsv" > "$out/fix-chrono.tsv"
rm -f "$out"/batch-*.tsv
split -l "$size" -d --additional-suffix=.tsv "$out/fix-chrono.tsv" "$out/batch-"
glint rules > "$out/glint-rules.txt"

echo "fix commits: $(wc -l < "$out/fix-all.tsv") listed, $(wc -l < "$out/fix.tsv") with code"
wc -l "$out"/batch-*.tsv

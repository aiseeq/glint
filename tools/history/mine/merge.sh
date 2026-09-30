#!/bin/bash
# usage: merge.sh <dir with out-*.jsonl>
# Groups the candidates of every batch by class: count, languages, universality,
# glint coverage and the commits that evidence it.
set -euo pipefail
dir=$1
cat "$dir"/out-*.jsonl | jq -c 'select(.summary != true)' > "$dir/all-candidates.jsonl"
echo "== batch summaries"
cat "$dir"/out-*.jsonl | jq -r 'select(.summary == true) | "total=\(.total) cand=\(.candidate_commits) rec=\(.records) dup=\(.duplicate) covered=\(.covered) not=\(.not_ruleable)"'
echo "== classes (count, universal, langs, covered_by, commits)"
jq -s -r '
  group_by(.class) | map({
    class: .[0].class, n: length,
    universal: (map(.universal) | unique | join("/")),
    langs: (map(.lang) | unique | join("/")),
    covered: (map(.covered_by) | unique | join("/")),
    commits: (map(.commit) | join(" "))
  }) | sort_by(-.n)[] | "\(.n)\t\(.universal)\t\(.langs)\t\(.covered)\t\(.class)\t\(.commits)"
' "$dir/all-candidates.jsonl"

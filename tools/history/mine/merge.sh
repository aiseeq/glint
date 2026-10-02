#!/bin/bash
# usage: merge.sh <dir with out-*.jsonl>
# Groups the candidates of every batch by class: count, languages, universality,
# glint coverage and the commits that evidence it.
set -euo pipefail
dir=$1
cat "$dir"/out-*.jsonl | jq -c 'select(.summary != true)' > "$dir/all-candidates.jsonl"
# A record without its commit, kind or class cannot be planned or replayed.
broken=$(jq -c 'select((.commit // "") == "" or (.kind | IN("defect", "introduced") | not) or (.class // "") == "")' "$dir/all-candidates.jsonl")
if [ -n "$broken" ]; then
  echo "records without commit, kind (defect|introduced) or class:" >&2
  echo "$broken" >&2
  exit 1
fi
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

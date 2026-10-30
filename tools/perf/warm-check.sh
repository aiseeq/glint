#!/usr/bin/env bash
# warm-check.sh <project dir> prints the median wall time in ms of `glint check . -o summary`
# run on an unchanged project with a warm cache: the speed reference of glint itself.
#
# Up to 5 runs while 45 s (GLINT_WARM_BUDGET_S) have not passed, at least one: a slower glint
# gives fewer runs and a bigger number, not a timeout the nightly comparison would read as
# "no data". A first run longer than 15 s shrinks the budget to 60 s (GLINT_WARM_LIMIT_S)
# minus that run, so the command still ends within 60 s on the day of the measure. Exit 1
# without an "Error:" line on stderr is a run that reported findings; any other failure ends
# the script with glint's exit code.
set -uo pipefail

[ "$#" -eq 1 ] || { echo "usage: warm-check.sh <project dir>" >&2; exit 2; }
cd "$1" || exit 2
glint=${GLINT:-glint}
budget_ms=$(( ${GLINT_WARM_BUDGET_S:-45} * 1000 ))
limit_ms=$(( ${GLINT_WARM_LIMIT_S:-60} * 1000 ))

samples=()
started=$(date +%s%N)
while (( ${#samples[@]} < 5 )); do
	now=$(date +%s%N)
	(( ${#samples[@]} == 0 || (now - started) / 1000000 < budget_ms )) || break
	err=$("$glint" check . -o summary 2>&1 >/dev/null)
	rc=$?
	end=$(date +%s%N)
	if (( rc != 0 )) && { (( rc != 1 )) || [[ $err == *Error:* ]]; }; then
		[ -z "$err" ] || printf '%s\n' "$err" >&2
		exit "$rc"
	fi
	samples+=( $(( (end - now) / 1000000 )) )
	if (( ${#samples[@]} == 1 && limit_ms - samples[0] < budget_ms )); then
		budget_ms=$(( limit_ms - samples[0] ))
	fi
done

printf '%s\n' "${samples[@]}" | sort -n | awk '{ a[NR] = $1 } END { if (NR % 2) print a[(NR + 1) / 2]; else printf "%.0f\n", (a[NR / 2] + a[NR / 2 + 1]) / 2 }'

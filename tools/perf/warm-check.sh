#!/usr/bin/env bash
# warm-check.sh <project dir> prints the median wall time in ms of `glint check . -o summary`
# run on an unchanged project with a warm cache: the speed reference of glint itself.
#
# The runs and the median are akit's timeit: up to 5 runs while 45 s (GLINT_WARM_BUDGET_S)
# have not passed, at least one, so a slower glint gives fewer runs and a bigger number,
# not a timeout the nightly comparison would read as "no data". A long first run shrinks
# the budget to 60 s (GLINT_WARM_LIMIT_S) minus that run. Exit 1 without an "Error:" line
# on stderr is a run that reported findings; any other failure ends with glint's exit code.
set -uo pipefail

[ "$#" -eq 1 ] || { echo "usage: warm-check.sh <project dir>" >&2; exit 2; }
cd "$1" || exit 2
exec timeit --runs 5 --budget "${GLINT_WARM_BUDGET_S:-45}s" --limit "${GLINT_WARM_LIMIT_S:-60}s" \
	--ok-exit 0,1 --fail-on-stderr 'Error:' -- "${GLINT:-glint}" check . -o summary

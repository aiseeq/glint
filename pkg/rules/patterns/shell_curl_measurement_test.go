package patterns

import "testing"

// A benchmark times requests with curl -w '%{time_total}' and never looks at
// the status: a 404 from a wrong host or a 403 from a missing token is timed
// as if it were a run of the endpoint. A curl with --fail, or whose status a
// later check compares, measures what it means to.
func TestShellCurlStatusUncheckedInMeasurement(t *testing.T) {
	shellWanted(t, "shell-curl-status-unchecked-in-measurement", "bench.sh", `#!/bin/bash
set -euo pipefail
for i in $(seq 1 "$PARALLEL"); do
    curl -s -o "$work/body.$i" -w '%{http_code} %{time_total}\n' -X POST -H "Authorization: Bearer $token" "$BASE/api/run" > "$work/res.$i" & # want
done
wait
cat "$work"/res.* | sort -k2 -n
curl -s -o /dev/null -w 'again: %{time_total} s\n' "$BASE/api/run" # want
curl -sf -o /dev/null -w '%{time_total}\n' "$BASE/api/run"
curl -s --fail-with-body -o /dev/null -w '%{time_total}\n' "$BASE/api/run"
curl -s -o /dev/null -w '%{http_code}\n' "$BASE/health"
`)
	shellWanted(t, "shell-curl-status-unchecked-in-measurement", "checked.sh", `#!/bin/bash
set -euo pipefail
curl -s -o "$work/body" -w '%{http_code} %{time_total}\n' "$BASE/api/run" > "$work/res"
if ! grep -q '^200 ' "$work/res"; then
    echo "not 200" >&2; exit 1
fi
read -r code took < <(curl -s -o /dev/null -w '%{http_code} %{time_total}' "$BASE/api/run")
[[ "$code" == 200 ]] || exit 1
`)
}

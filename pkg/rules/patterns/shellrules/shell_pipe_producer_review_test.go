package shellrules

import "testing"

func TestShellStatusOfPipeTailReviewBoundaries(t *testing.T) {
	shellWanted(t, "shell-status-of-pipe-tail", "last.sh", `curl -fsS "$URL" | jq .; # want
`)
	shellWanted(t, "shell-status-of-pipe-tail", "pipefail.sh", `set -o pipefail
curl -fsS "$URL" | jq .
set +o pipefail
`)
	shellWanted(t, "shell-status-of-pipe-tail", "after.sh", `curl -fsS "$URL" | jq .
set -o pipefail
`)
	shellWanted(t, "shell-status-of-pipe-tail", "capture.sh", `out=$(find . \( -name '*.go' -o -name '*.mod' \) | xargs -r wc -l) && test -n "$out" # want
safe=$(curl -fsS "$URL" | jq .); if [ -z "$safe" ]; then exit 1; fi
if found=$(curl -fsS "$URL" | jq .); then echo "$found"; fi # want
echo 'out=$(curl -fsS u | jq .) && test -n "$out"'
curl -fsS "$URL" | jq . || echo handled
`)
	shellWanted(t, "shell-status-of-pipe-tail", "conditions.sh", `if curl -fsS "$URL" | jq .; then echo ok; fi
while curl -fsS "$URL" | jq .; do echo retry; done
`)
	shellWanted(t, "shell-status-of-pipe-tail", "remote.sh", `ssh host 'bash -s' <<'REMOTE'
curl -fsS "$URL" | jq .
REMOTE
`)
	graftWanted(t, ".graft.yaml", `services:
  app:
    sh: 'curl -fsS "$URL" | jq .'
envs:
  release:
    sh: 'curl -fsS "$URL" | jq .'
tasks:
  good:
    run:
      - sh: "curl -fsS '$URL' | jq ." # want
`)
}

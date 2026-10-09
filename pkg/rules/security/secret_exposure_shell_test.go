package security

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func shellSecretLines(t *testing.T, path, code string) []int {
	t.Helper()
	var lines []int
	for _, v := range NewSecretExposureRule().AnalyzeFile(rulestest.TextFile(t, path, code)) {
		lines = append(lines, v.Line)
	}
	return lines
}

// A setup script prints the generated database password to the terminal:
// it stays in the scrollback, the CI log and the session recording.
func TestSecretExposureEchoedByScript(t *testing.T) {
	code := `#!/bin/bash
DB_PASSWORD=$(openssl rand -hex 16)
echo "  DB Pass:  $DB_PASSWORD"
echo -e "${YELLOW}Save the password!${NC}"
printf '%s\n' "${API_TOKEN}"
echo "DB_PASSWORD=$DB_PASSWORD" >> .env
echo "$REGISTRY_TOKEN" | docker login --password-stdin
echo "token file: $TOKEN_FILE"
echo "DB password is set" >&2
`
	assert.Equal(t, []int{3, 5}, shellSecretLines(t, "setup.sh", code))
}

// A make recipe prints a key it read from the environment.
func TestSecretExposureEchoedByRecipe(t *testing.T) {
	code := "show:\n\t@echo \"key: $$PRIVATE_KEY\"\n\t@echo \"user: $$DB_USER\"\n"
	assert.Equal(t, []int{2}, shellSecretLines(t, "Makefile", code))
}

// A masked prefix, a counter named PASS and a value piped on the next line
// of a recipe are not a printed secret.
func TestSecretExposureShellMaskCounterAndContinuedPipe(t *testing.T) {
	script := `echo "  DB_PASSWORD: ${DB_PASSWORD:0:4}****"
printf "Passed: ${PASS_COUNT}\n"
printf "TOKEN=%s\n" "$BOT_TOKEN" \
  | ssh host 'cat > /tmp/.env'
echo "db: $DB_PASS"
`
	assert.Equal(t, []int{5}, shellSecretLines(t, "status.sh", script))
}

// A print inside a command substitution is captured into a variable, not
// shown: the value never reaches the terminal.
func TestSecretExposureShellCapturedPrint(t *testing.T) {
	script := `DB_PASSWORD=$(set -a; . "$ROOT/.env"; printf '%s' "${DB_PASSWORD:-}")
TOKEN=` + "`echo $API_TOKEN`" + `
(cd /tmp; echo "$API_TOKEN")
VALUE=$(get_value) ; echo "$API_TOKEN"
`
	assert.Equal(t, []int{3, 4}, shellSecretLines(t, "load.sh", script))
}

// The rule's own marker in a script is a '#' comment: it silences the print
// below it, inside a heredoc fed to a remote shell too.
func TestSecretExposureShellMarker(t *testing.T) {
	code := `#!/usr/bin/env bash
set -euo pipefail
creds="$(ssh host 'bash -s' <<'REMOTE'
set -euo pipefail
MARKER
printf 'TOKEN=%s\n' "$BOT_TOKEN"
REMOTE
)"
printf '%s\n' "${#creds}"
`
	marked := strings.Replace(code, "MARKER", "# secret-exposure: safe - the output is captured into creds, not printed", 1)
	assert.Empty(t, shellSecretLines(t, "creds.sh", marked))
	uncaptured := strings.Replace(strings.Replace(marked, `creds="$(ssh`, "ssh", 1), "REMOTE\n)\"\n", "REMOTE\n", 1)
	uncaptured = strings.Replace(uncaptured, "# secret-exposure: safe - the output is captured into creds, not printed", "# printed on the terminal", 1)
	assert.Equal(t, []int{6}, shellSecretLines(t, "creds.sh", uncaptured))
}

// What a heredoc script prints is captured when $( ) takes the whole command
// that reads the heredoc: the value lands in the variable, not on the
// terminal.
func TestSecretExposureHeredocCapturedBySubstitution(t *testing.T) {
	code := `#!/usr/bin/env bash
set -euo pipefail
creds="$(ssh host 'bash -s' <<'REMOTE'
set -euo pipefail
printf 'TOKEN=%s\n' "$BOT_TOKEN"
REMOTE
)"
ssh host 'bash -s' <<'REMOTE'
printf 'TOKEN=%s\n' "$BOT_TOKEN"
REMOTE
`
	assert.Equal(t, []int{9}, shellSecretLines(t, "creds.sh", code))
}

// A print inside a process substitution <( ) feeds the command a file to
// read (curl -H @<(printf ...)), the terminal never sees it; a print inside
// >( ) still writes to the script's own output.
func TestSecretExposureProcessSubstitution(t *testing.T) {
	code := `#!/bin/bash
curl -fsS -H @<(printf 'Authorization: Bearer %s' "$API_TOKEN") \
	"$URL/dump" -o out.dump
tee >(echo "$API_TOKEN") </dev/null
`
	assert.Equal(t, []int{4}, shellSecretLines(t, "fetch.sh", code))
}

package security

import (
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

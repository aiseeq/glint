package shellrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
)

// A captured function prints its progress message on the stdout that carries
// its data: the message becomes the head of the captured value.
func TestShellCapturedFunctionWritesItsOwnMessage(t *testing.T) {
	assert.Equal(t, []string{"sync.sh:5", "sync.sh:7"}, patterntest.ShellFindings(t, "shell-captured-function-writes-logs", map[string]string{
		"sync.sh": `#!/bin/bash
transfer() {
  local body n
  body=$(build_body "$2")
  printf 'Exported from %s: %s rows\n' "$1" "$n"
  if [[ "$n" == "0" ]]; then
    printf 'Nothing to move\n'
    return 0
  fi
  printf '%s' "$body"
}
out=$(transfer local "$payload")
`,
	}))
	// The message is the value: a function that writes only text, or answers
	// with one word on the fallback path.
	assert.Empty(t, patterntest.ShellFindings(t, "shell-captured-function-writes-logs", map[string]string{
		"value.sh": `describe() {
  printf 'build %s on %s\n' "$version" "$host"
}
version_of() {
  if [ -f VERSION ]; then
    cat VERSION
  else
    echo "unknown"
  fi
}
quiet() {
  printf 'Loaded %s rows\n' "$n" >&2
  printf '%s' "$body"
}
d=$(describe)
v=$(version_of)
q=$(quiet)
conf_dir() {
  if [ -d /etc/nginx/sites-enabled ]; then
    echo "/etc/nginx/sites-enabled"
  else
    echo "$CONF_DIR"
  fi
}
c=$(conf_dir)
`,
	}))
	// A test stub prints the log line of the program it imitates.
	assert.Empty(t, patterntest.ShellFindings(t, "shell-captured-function-writes-logs", map[string]string{
		"deploy_test.sh": `migrate_stub() {
  printf 'level=INFO msg="schema is current" version=%s\n' "$1"
  printf '%s' "$out"
}
x=$(migrate_stub 3)
`,
	}))
}

// The psql command lives in a variable without ON_ERROR_STOP and runs the
// migration files: a failed statement still marks the migration applied.
func TestPsqlScriptFromCommandVariable(t *testing.T) {
	assert.Equal(t, []string{"migrate.sh:2"}, patterntest.ShellFindings(t, "psql-script-without-on-error-stop", map[string]string{
		"migrate.sh": `migrate() {
  local PSQL="psql -U $db_user -h $db_host -d $db_name -q"
  for f in migrations/*.sql; do
    if $PSQL -f "$f" 2>&1; then
      $PSQL -c "INSERT INTO schema_migrations (version) VALUES ('$f')"
    fi
  done
}
`,
		"safe.sh": `PSQL="psql -U app -v ON_ERROR_STOP=1"
$PSQL -f schema.sql
${PSQL} < seed.sql
`,
	}))
}

// The status of an API call is dropped with || true: a failed request is
// only an empty value further on.
func TestShellFailureStatusDroppedByOrTrue(t *testing.T) {
	assert.Equal(t, []string{"flags.sh:5", "flags.sh:6"}, patterntest.ShellFindings(t, "shell-failure-fallback-value", map[string]string{
		"flags.sh": `api_get() {
  curl -fsS "$API/$1"
}
show() {
  response=$(api_get "items/$1") || true
  status=$(curl -fsS "$API/status") || :
  render "$response" "$status"
}
`,
	}))
	// A search finding nothing exits 1: || true keeps set -e from stopping.
	assert.Empty(t, patterntest.ShellFindings(t, "shell-failure-fallback-value", map[string]string{
		"search.sh": `set -e
matches=$(grep -c "$pattern" "$file") || true
pids=$(pgrep -f "[w]orker") || true
changed=$(git diff --name-only | grep '\.go$') || true
`,
	}))
}

// A function that selects an env key by its argument and removes the key
// prefix is a hand-written env parser just like one with a literal key.
func TestShellDotenvKeyFromFunctionParameter(t *testing.T) {
	assert.Equal(t, []string{"env.sh:2", "env.sh:3", "env.sh:4"}, patterntest.ShellFindings(t, "hand-rolled-dotenv-parser", map[string]string{
		"env.sh": `#!/bin/sh
val() { grep -h "^$1=" .env /run/app/secrets.env | cut -d= -f2-; }
other() { grep "^$1=" .env | sed 's/^.*=//'; }
read_key() { grep -h "^$1=" .env | cut -d '=' -f 2-; }
`,
	}))
	assert.Empty(t, patterntest.ShellFindings(t, "hand-rolled-dotenv-parser", map[string]string{
		"fixed.sh": `source_env() { . ./.env; }
grep "^$1=" config.txt | cut -d= -f2-
grep "^$1=" .env
`,
	}))
}

// A sed program rewrites .env for docker: it strips quotes and comments its
// own way, and a value with quotes, $ or an inline comment changes on the way.
func TestShellDotenvRewrittenBySed(t *testing.T) {
	assert.Equal(t, []string{"Makefile:3"}, patterntest.ShellFindings(t, "hand-rolled-dotenv-parser", map[string]string{
		"Makefile": `up:
  env_file=$$(mktemp); \
  sed 's/^#.*//; /^$$/d; s/="\(.*\)"/=\1/' $(PWD)/.env > "$$env_file"; \
  docker run --env-file "$$env_file" app
`,
	}))
	assert.Empty(t, patterntest.ShellFindings(t, "hand-rolled-dotenv-parser", map[string]string{
		"deploy.sh": `sed -i "s/^VERSION=.*/VERSION=$v/" .env
grep -v '^#' .env.example | cut -d= -f1
set -a; . ./.env; set +a
`,
	}))
}

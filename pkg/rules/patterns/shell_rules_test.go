package patterns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// recipe turns the two-space indent of a make file sample into the tab make
// requires.
func recipe(source string) string { return strings.ReplaceAll(source, "\n  ", "\n\t") }

// shellFindings runs a registered rule over the files of a root, the make
// files given with recipe indents.
func shellFindings(t *testing.T, name string, files map[string]string) []string {
	t.Helper()
	rule, ok := rules.Get(name)
	require.True(t, ok, name)
	var contexts []*core.FileContext
	for path, source := range files {
		contexts = append(contexts, rulestest.TextFile(t, path, recipe(source)))
	}
	if project, ok := rule.(rules.ProjectFilesRule); ok {
		project.UseProjectFiles(contexts)
	}
	var found []*core.Violation
	for _, ctx := range contexts {
		found = append(found, rule.AnalyzeFile(ctx)...)
	}
	return foundLines(found)
}

// The status after a pipeline is the last command's: tee succeeds, and the
// failed test run passes the target.
func TestShellStatusOfPipeTail(t *testing.T) {
	assert.Equal(t, []string{"Makefile:2", "run.sh:3"}, shellFindings(t, "shell-status-of-pipe-tail", map[string]string{
		"Makefile": `test-unit:
  @(cd web && npx jest 2>&1 | tee -a ../logs/unit.log); code=$$?; \
  exit $$code
test-safe:
  @set -o pipefail; go test ./... | tee log; code=$$?; exit $$code
test-status:
  @go test ./... | tee log; code=$${PIPESTATUS[0]}; exit $$code
test-grep:
  @go test ./... | grep -v noise; code=$$?
`,
		"run.sh": `#!/bin/sh
go test ./... | tee out.log
if [ $? -ne 0 ]; then
  exit 1
fi
`,
	}))
	// A recipe written as bash -c '...' is the script bash runs.
	assert.Equal(t, []string{"Makefile:5"}, shellFindings(t, "shell-status-of-pipe-tail", map[string]string{
		"Makefile": `test-all:
  @bash -c ' \
  echo "start $$(date '"'"'+%H:%M'"'"')"; \
  cd backend && go test ./tests/integration 2>&1 | tee a.log >/dev/null; \
  result=$$?; \
  exit $$result \
  '
`,
	}))
	assert.Empty(t, shellFindings(t, "shell-status-of-pipe-tail", map[string]string{
		"Makefile": `SHELL := /bin/bash
.SHELLFLAGS := -eo pipefail -c
test:
  @go test ./... | tee log; code=$$?; exit $$code
`,
	}))
}

// app-2>/dev/null passes "app-2" to docker and sends stdout to /dev/null.
func TestShellRedirectGluedToWord(t *testing.T) {
	assert.Equal(t, []string{"Makefile:2", "stop.sh:1"}, shellFindings(t, "shell-redirect-glued-to-word", map[string]string{
		"Makefile": `stop:
  docker stop app-2>/dev/null || true
  docker rm app 2>/dev/null || true
  echo "file-2>x"
`,
		"stop.sh": "docker rm -f worker_1>/dev/null\nls dir 1>&2\n",
	}))
}

// The test reads $version before the same recipe line sets it.
func TestMakeVariableReadBeforeAssignment(t *testing.T) {
	assert.Equal(t, []string{"Makefile:2", "Makefile:8"}, shellFindings(t, "make-variable-read-before-assignment", map[string]string{
		"Makefile": `deploy:
  @if [ -z "$$version" ]; then echo none; fi; version=$$(cat VERSION); echo $$version
  @for f in a b; do echo $$f; done
  @name=x; echo $$name
  @echo '$$later'; later=1
check:
  @bash -c ' \
  if [ "$$ok" = 1 ] && [ $$sec_result -eq 0 ]; then echo pass; fi; \
  run-security; sec_result=$$? \
  '
`,
	}))
}

// The log lines of a captured function end up in the value its caller uses
// as a path.
func TestShellCapturedFunctionWritesLogs(t *testing.T) {
	assert.Equal(t, []string{"deploy.sh:13", "deploy.sh:3"}, shellFindings(t, "shell-captured-function-writes-logs", map[string]string{
		"deploy.sh": `#!/bin/bash
log() {
  echo "[deploy] $*"
}
warn() { echo "warn: $*" >&2; }
current_version() {
  log "reading version"
  warn "x"
  cat /opt/app/VERSION
}
v=$(current_version)
image_id() {
  docker build -q . 2>&1
}
id=$(image_id)
log "done"
`,
	}))
	// A call that sends the log to stderr itself keeps the value clean.
	assert.Empty(t, shellFindings(t, "shell-captured-function-writes-logs", map[string]string{
		"quiet.sh": `log_error() { echo "[error] $1"; }
port_for() {
  case "$1" in
    blue) echo 8081 ;;
    *) log_error "unknown: $1" >&2; return 1 ;;
  esac
}
if ! check_port; then log_error "x" >&2; fi
p=$(port_for blue)
`,
	}))
}

// A bare wait returns 0 whatever the jobs returned.
func TestShellWaitIgnoresJobStatus(t *testing.T) {
	// wait "$pid" || true is not reported: the jobs may pass their outcome
	// through result files.
	assert.Equal(t, []string{"Makefile:11", "Makefile:5", "build.sh:3"}, shellFindings(t, "shell-wait-ignores-job-status", map[string]string{
		"build.sh": "build_a &\nbuild_b &\nwait\nwait \"$pid\" || true\n",
		"one.sh":   "build_a\nwait\n",
		"Makefile": `build:
  @wait
  @a & pa=$$!; b & pb=$$!; wait $$pa && wait $$pb
build-all:
  @a & b & wait
sync:
  @( \
    scp a host:/x/ & \
    scp b host:/x/ & \
    # wait for both \
    wait \
  ) || exit 1; \
  wait $$PID_A $$PID_B || true
`,
	}))
}

// The check compares the version with the literal the script itself set.
func TestShellCheckAgainstOwnLiteral(t *testing.T) {
	assert.Equal(t, []string{"verify.sh:4"}, shellFindings(t, "shell-check-against-own-literal", map[string]string{
		"verify.sh": `#!/bin/bash
check_version() {
  local current_version="14"  # from the logs
  if [[ "$current_version" != "14" ]]; then
    exit 1
  fi
}
`,
		"modes.sh": `if [ -f blue ]; then
  MODE="blue"
else
  MODE="green"
fi
if [ "$MODE" != "green" ]; then echo blue; fi
STATUS="unknown"
STATUS=$(curl -s localhost/health)
if [ "$STATUS" != "unknown" ]; then echo ok; fi
`,
	}))
}

// gosec || true lets the security target pass whatever gosec finds.
func TestShellCheckFailureIgnored(t *testing.T) {
	assert.Equal(t, []string{"Makefile:2", "Makefile:3", "Makefile:4", "Makefile:5", "audit.sh:1"}, shellFindings(t, "shell-check-failure-ignored", map[string]string{
		"Makefile": `security:
  gosec ./... || true
  cd web && npm audit --audit-level=high || (echo "audit failed"; exit 0)
  -govulncheck ./...
  trivy fs . || echo "trivy found issues"
  golangci-lint run || exit 1
  gosec ./...
`,
		"audit.sh": "npm audit || :\n",
	}))
}

// psql goes on after a failed statement and exits 0.
func TestPsqlScriptWithoutOnErrorStop(t *testing.T) {
	assert.Equal(t, []string{"migrate.sh:1", "migrate.sh:2", "migrate.sh:3"}, shellFindings(t, "psql-script-without-on-error-stop", map[string]string{
		"migrate.sh": `psql -h db -U app -f schema.sql
cat seed.sql | ssh host "psql -U app app"
psql app < data.sql
psql -v ON_ERROR_STOP=1 -f schema.sql
psql -c "select 1"
cat > "$BIN/psql" <<'STUB'
`,
		"query.sh": `psql_args=(-U app -v ON_ERROR_STOP=1)
printf 'BEGIN;\n%s\nCOMMIT;\n' "$q" | psql "${psql_args[@]}"
psql "${psql_args[@]}" -f schema.sql
`,
	}))
}

// A failed read falls back to the old version, and the deploy records it as
// the new one.
func TestShellFailureFallbackValue(t *testing.T) {
	assert.Equal(t, []string{"sync.sh:1"}, shellFindings(t, "shell-failure-fallback-value", map[string]string{
		"sync.sh": "new_version=$(ssh host cat /opt/app/VERSION || echo \"$old_version\")\nx=$(cat f || echo \"\")\ny=$(cat f) || exit 1\n",
	}))
}

// After 30 failed health checks the switch still happens.
func TestShellPollLoopFallsThrough(t *testing.T) {
	assert.Equal(t, []string{"switch.sh:1"}, shellFindings(t, "shell-poll-loop-falls-through", map[string]string{
		"switch.sh": `for i in $(seq 1 30); do
  if curl -fs localhost:8081/health; then
    break
  fi
  sleep 2
done
switch_traffic green
`,
		"checked.sh": `for i in $(seq 1 30); do
  curl -fs localhost/health && break
  sleep 2
done
if ! curl -fs localhost/health; then exit 1; fi
ready=0
for i in {1..10}; do
  if pg_isready; then ready=1; break; fi
  sleep 1
done
[ "$ready" = 1 ] || exit 1
for i in $(seq 1 15); do
  kill -0 $PID || break
  if [ $i -eq 8 ]; then kill -9 $PID; fi
  sleep 0.1
done
rm -f pidfile
for i in $(seq 1 30); do
  if curl -fs localhost/health; then break; fi
  sleep 1
  if [ $i -gt 29 ]; then echo "timeout" >&2; return 1; fi
done
next_step
`,
	}))
}

// The build runs once; after the sources change the stale binary stays.
func TestShellBuildSkippedWhenBinaryExists(t *testing.T) {
	assert.Equal(t, []string{"Makefile:2"}, shellFindings(t, "shell-build-skipped-when-binary-exists", map[string]string{
		"Makefile": `tool:
  @if [ ! -x bin/tool ]; then go build -o bin/tool ./cmd/tool; fi
  @if [ ! -x bin/gen ]; then go install golang.org/x/tools/cmd/gen@latest; fi
  @if [ ! -x bin/x ] || [ cmd/x/main.go -nt bin/x ]; then go build -o bin/x ./cmd/x; fi
  @hash=$$(find . -name '*.go' | xargs cat | sha256sum); \
  if [ ! -f bin/app ] || [ "$$hash" != "$$(cat .hash)" ]; then go build -o bin/app ./cmd/app; fi
`,
	}))
}

// Overwriting a running binary in place: the service on the host crashes or
// runs a half-written file.
func TestShellBinaryCopiedOverInPlace(t *testing.T) {
	assert.Equal(t, []string{"Makefile:2"}, shellFindings(t, "shell-binary-copied-over-in-place", map[string]string{
		"Makefile": `deploy-agent:
  scp bin/agent $(HOST):/opt/app/bin/agent
  scp bin/agent $(HOST):/opt/app/bin/agent.new && ssh $(HOST) mv /opt/app/bin/agent.new /opt/app/bin/agent
  scp bin/agent $(HOST):/tmp/agent
  scp bin/agent $(HOST):/opt/app/bin/ ; ssh $(HOST) 'install -m 755 x y'
`,
	}))
}

// The developer's .env replaces the server's own on every deploy.
func TestShellLocalEnvCopiedToRemote(t *testing.T) {
	assert.Equal(t, []string{"deploy.sh:1", "deploy.sh:2"}, shellFindings(t, "shell-local-env-copied-to-remote", map[string]string{
		"deploy.sh": "scp .env \"$HOST:/opt/app/.env\"\nrsync -az ./.env.prod $HOST:/opt/app/\nscp .env.example $HOST:/opt/app/\nscp $HOST:/opt/app/.env ./backup.env\nscp .env $HOST:/opt/app/shared/.env.new &\n",
	}))
}

// A sibling script renamed away: the rollback fails exactly when it is needed.
func TestShellScriptReferenceMissing(t *testing.T) {
	assert.Equal(t, []string{"ops/rollback.sh:3"}, shellFindings(t, "shell-script-reference-missing", map[string]string{
		"ops/rollback.sh": `#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$SCRIPT_DIR/switch-nginx-fixed.sh" blue
"$SCRIPT_DIR/switch-nginx.sh" blue
if [ -x "$SCRIPT_DIR/optional.sh" ]; then "$SCRIPT_DIR/optional.sh"; fi
ssh host "$REMOTE_DIR/remote.sh"
"$OTHER/elsewhere.sh"
`,
		"ops/switch-nginx.sh": "echo switch\n",
	}))
}

// The database password is in the repository and in the process list.
func TestShellDBPasswordLiteral(t *testing.T) {
	assert.Equal(t, []string{"Makefile:2", "Makefile:3", "Makefile:4"}, shellFindings(t, "shell-db-password-literal", map[string]string{
		"Makefile": `migrate:
  ssh host "./migrate -db 'host=127.0.0.1 user=app password=app dbname=app sslmode=disable' up"
  PGPASSWORD=secret psql -h db -U app
  migrate -database postgres://app:app@localhost/app up
  PGPASSWORD="$$DB_PASSWORD" psql -h db
  migrate -database "postgres://app:$$DB_PASSWORD@localhost/app" up
  ./tool --password=$$PASS --user=x
`,
	}))
}

// A captured function ends in grep | head | cut without pipefail: an
// unreadable file (grep status 2) gives the caller an empty value and
// status 0, the same as a missing key. pipefail set only inside a heredoc
// for a remote shell does not cover the script.
func TestShellStatusOfPipeTailInCapturedFunction(t *testing.T) {
	assert.Equal(t, []string{"lib.sh:4"}, shellFindings(t, "shell-status-of-pipe-tail", map[string]string{
		"lib.sh": `#!/bin/bash
local_dsn() {
    if [ -n "${DSN:-}" ]; then printf '%s' "$DSN"; return; fi
    [ -f "$ROOT/.env" ] && grep -E '^DSN=' "$ROOT/.env" | head -1 | cut -d= -f2-
}
names() {
    printf '%s\n' a b c | sort
}
dsn="$(local_dsn)"
list="$(names)"
out=$(ssh_cmd "bash -s" <<'REMOTE'
set -euo pipefail
ls /srv
REMOTE
)
`,
	}))
	assert.Empty(t, shellFindings(t, "shell-status-of-pipe-tail", map[string]string{
		"lib.sh": `#!/bin/bash
set -o pipefail
local_dsn() {
    grep -E '^DSN=' "$ROOT/.env" | head -1 | cut -d= -f2-
}
dsn="$(local_dsn)"
`,
	}))
}

// stderr merged into a captured value that is then compared exactly: a
// warning the remote prints ("could not change directory") makes the value
// match no case.
func TestShellCapturedStderrComparedExactly(t *testing.T) {
	assert.Equal(t, []string{"preflight.sh:3"}, shellFindings(t, "shell-captured-function-writes-logs", map[string]string{
		"preflight.sh": `#!/bin/bash
check() {
    result=$(ssh_cmd "sudo -u app psql '$DSN' -XqAt -c \"SELECT true\"" 2>&1) || rc=$?
    case "$result" in
        t) return 1 ;;
        f) return 0 ;;
    esac
    log=$(make build 2>&1)
    printf '%s\n' "$log"
}
`,
	}))
}

// A function whose opening brace is followed only by a comment reads like
// one whose brace ends the line: the loop inside it is seen like any other,
// and so is a loop after it, which a brace taken for an unclosed group hid.
func TestShellGroupClosedByBraceOnItsOwnLine(t *testing.T) {
	assert.Equal(t, []string{"carousel.sh:10", "carousel.sh:3"}, shellFindings(t, "shell-poll-loop-falls-through", map[string]string{
		"carousel.sh": `wait_session() { # waits for the compositor
  local i
  for i in $(seq 1 40); do
    pgrep -x sway >/dev/null && break
    sleep 1
  done
  start_player
}

for i in $(seq 1 30); do
  curl -fs localhost/health && break
  sleep 2
done
switch_traffic
`,
	}))
}

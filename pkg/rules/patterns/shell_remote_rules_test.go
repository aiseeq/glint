package patterns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// A multi-line script handed to a remote shell runs every line whatever the
// one before it returned, and ssh reports the status of the last line only.
func TestRemoteMultilineScriptWithoutErrexit(t *testing.T) {
	assert.Equal(t, []string{"deploy.sh:27", "deploy.sh:5", "deploy.sh:9"}, shellFindings(t, "remote-multiline-script-without-errexit", map[string]string{
		"deploy.sh": `#!/bin/bash
set -euo pipefail
remote() { ssh "$HOST" "$@"; }
install_all() {
  remote_sudo "
    gunzip -f /tmp/app.gz && mv /tmp/app $APP_BIN
    echo '$VERSION' > $APP_DIR/VERSION
  "
  ssh "$HOST" 'sudo bash -c "
    mkdir -p /opt/app/bin
    chown app:app /opt/app
  "'
}
checked() {
  remote_sudo "set -e
    gunzip -f /tmp/app.gz
    mv /tmp/app $APP_BIN
  "
  remote_sudo '
    dnf install -y nginx 2>/dev/null ||
    dnf install -y nginx1 2>/dev/null ||
    { yum install -y nginx; }
  '
  remote_sudo "cat > $CONF << 'EOF'
server { listen 80; }
EOF"
  bash -c "
    cd /srv/app
    make build
  "
}
`,
	}))
	// One command, a list joined by && and a make recipe are not scripts of
	// several independent lines.
	assert.Empty(t, shellFindings(t, "remote-multiline-script-without-errexit", map[string]string{
		"single.sh": `remote_sudo "
  systemctl restart app
"
remote_sudo "mkdir -p /opt/app &&
  chown app /opt/app"
remote "psql -lqt | grep -qw $DB || \
  psql -c \"CREATE DATABASE $DB OWNER $DB_USER;\""
echo "
  first
  second
"
`,
	}))
}

// A command that prints its answer and exits non-zero, followed by
// || echo LITERAL inside the capture: the capture holds both lines.
func TestShellFallbackEchoDuplicatesCommandOutput(t *testing.T) {
	assert.Equal(t, []string{"probe.sh:2", "probe.sh:3", "probe.sh:4", "probe.sh:5", "probe.sh:6"}, shellFindings(t, "shell-fallback-echo-duplicates-command-output", map[string]string{
		"probe.sh": `set -o pipefail
state="SERVICE=$(systemctl is-active app 2>/dev/null || echo inactive)"
count=$(psql -lqt 2>/dev/null | grep -cw appdb || echo 0)
code=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || echo "000")
listen=$(remote "grep -c 'listen.*443' $CONF 2>/dev/null || echo 0")
status=$(remote "systemctl is-active app" | head -1 || echo "unknown")
`,
	}))
	// The fallback replaces an empty answer: the command prints nothing when
	// it fails, or the echo writes nothing that survives the capture.
	assert.Empty(t, shellFindings(t, "shell-fallback-echo-duplicates-command-output", map[string]string{
		"quiet.sh": `body=$(curl -sf "$URL" || echo "")
has=$(remote "[ -f $CONF ] && echo yes || echo no")
n=$(grep -q ready "$LOG" || echo missing)
s=$(systemctl is-active app) || s=inactive
head=$(remote "systemctl is-active app" | head -1 || echo "unknown")
v=$(cat VERSION || echo dev)
`,
	}))
}

// eval of a remote report whose NAME=value lines reuse the names of the
// script's own settings: the report overwrites them.
func TestShellEvalOutputOverwritesScriptVariable(t *testing.T) {
	assert.Equal(t, []string{"deploy.sh:14", "deploy.sh:21"}, shellFindings(t, "shell-eval-output-overwrites-script-variable", map[string]string{
		"deploy.sh": `#!/bin/bash
ssh_cmd() { ssh "$HOST" "$@"; }
APP_DIR="/opt/app"
APP_BIN="/opt/app/bin/app"
APP_ENV="/opt/app/.env"
STATE=$(ssh_cmd 'bash -s' <<'PROBE'
    echo "NGINX=$(command -v nginx >/dev/null 2>&1 && echo yes || echo no)"
    echo "APP_BIN=$([ -f /opt/app/bin/app ] && echo yes || echo no)"
    echo "APP_ENV=$([ -f /opt/app/.env ] && echo yes || echo no)"
PROBE
)
INFO=$(ssh_cmd 'printf "OS=%s\n" "$(uname)"')

eval "$STATE"
eval "$INFO"
scp "$LOCAL_BIN" "$HOST:$APP_BIN"
probe() {
  echo "APP_DIR=$(test -d /opt/app && echo yes)"
}
REPORT=$(probe)
eval "$REPORT"
`,
	}))
}

// A rule appended to pg_hba.conf lands after the catch-all rules of the
// default file: the first matching line wins, and the new one is never used.
func TestPgHbaRuleAppendedAfterCatchAll(t *testing.T) {
	assert.Equal(t, []string{"setup.sh:4", "setup.sh:5", "setup.sh:7"}, shellFindings(t, "pg-hba-rule-appended-after-catch-all", map[string]string{
		"setup.sh": `remote_sudo '
  HBA=$(sudo -u postgres psql -t -c "SHOW hba_file" | tr -d " ")
  sed -i "/^local.*all.*all/i local   appdb   app   md5" "$HBA"
  echo "host    appdb   app   127.0.0.1/32   md5" >> "$HBA"
  printf "hostssl appdb app 0.0.0.0/0 scram-sha-256\n" | tee -a "$HBA"
'
echo "local all app peer" >> /var/lib/pgsql/data/pg_hba.conf
echo "listen_addresses = '*'" >> "$PG_CONF"
`,
	}))
}

// A deploy that rewrites the nginx site on every run while certbot --nginx
// edits that file in place: the TLS server block certbot added is lost.
func TestDeployOverwritesConfigEditedByCertbot(t *testing.T) {
	assert.Equal(t, []string{"deploy.sh:3"}, shellFindings(t, "deploy-overwrites-config-edited-by-certbot", map[string]string{
		"deploy.sh": `NGINX_CONF="/etc/nginx/conf.d/app.conf"
step "Configuring nginx"
remote_sudo "cat > $NGINX_CONF << 'EOF'
server { listen 80; server_name $DOMAIN; }
EOF
nginx -t && systemctl reload nginx"
if [ "$HAS_SSL" = "no" ]; then
  remote_sudo "certbot --nginx -d $DOMAIN --non-interactive --redirect"
fi
`,
	}))
	// Written only when it is missing; a script that never runs certbot.
	assert.Empty(t, shellFindings(t, "deploy-overwrites-config-edited-by-certbot", map[string]string{
		"guarded.sh": `NGINX_CONF="/etc/nginx/conf.d/app.conf"
HAS_CONF=$(remote "[ -f $NGINX_CONF ] && echo yes || echo no")
if [ "$HAS_CONF" = "no" ]; then
  remote_sudo "cat > $NGINX_CONF << 'EOF'
server { listen 80; }
EOF"
fi
remote_sudo "certbot --nginx -d $DOMAIN --non-interactive"
`,
		"plain.sh": `remote_sudo "cat > /etc/nginx/conf.d/app.conf << 'EOF'
server { listen 80; }
EOF"
`,
		// certonly only fetches the certificate and leaves the files alone.
		"certonly.sh": `cat > "/etc/nginx/conf.d/${DOMAIN}.conf" << EOF
server { listen 80; }
EOF
certbot certonly --nginx -d "$DOMAIN" --non-interactive
`,
		// The script writes the TLS server block itself after certbot.
		"own-tls.sh": `cat > "/etc/nginx/conf.d/${DOMAIN}.conf" << EOF
server { listen 80; }
EOF
if certbot --nginx -d "$DOMAIN" --non-interactive --redirect; then
  cat > "/etc/nginx/conf.d/${DOMAIN}.conf" << EOF
server {
  listen 443 ssl;
  ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
}
EOF
fi
`,
	}))
}

// Under set -e a capture whose command exits non-zero for the very value
// the next lines handle stops the script before the handler runs.
func TestShellSetEExitsBeforeFailureHandler(t *testing.T) {
	assert.Equal(t, []string{"deploy.sh:4", "deploy.sh:8"}, shellFindings(t, "shell-set-e-exits-before-failure-handler", map[string]string{
		"deploy.sh": `#!/bin/bash
set -euo pipefail
remote_sudo "systemctl restart app" || true
STATUS=$(remote "systemctl is-active app 2>/dev/null")
if [ "$STATUS" != "active" ]; then
  rollback "service not running: $STATUS"
fi
BODY=$(curl -sf "http://127.0.0.1:8080/health")
if [ -z "$BODY" ]; then
  rollback "no health answer"
fi
OK=$(remote "systemctl is-active app" | head -1 || echo unknown)
if [ "$OK" != "active" ]; then rollback "down"; fi
local_state() {
  local s
  s=$(systemctl is-enabled app) || s=disabled
  if [ "$s" = "disabled" ]; then return 1; fi
}
VERSION=$(cat VERSION)
if [ -z "$VERSION" ]; then exit 1; fi
`,
	}))
	// Without set -e the handler runs.
	assert.Empty(t, shellFindings(t, "shell-set-e-exits-before-failure-handler", map[string]string{
		"check.sh": `STATUS=$(systemctl is-active app)
if [ "$STATUS" != "active" ]; then echo down; fi
`,
	}))
}

// A smoke check that greps a page for a text no template or source of the
// application contains: the text was renamed, and every check fails.
func TestSmokeCheckGrepsRenamedUIText(t *testing.T) {
	files := map[string]string{
		"web/templates/layout.html": `<footer>Acme Console</footer>`,
		"internal/web/title.go": `package web

const Title = "Order Desk"
`,
		"scripts/smoke.sh": `check_body() { local tag="$1" body="$2"; if echo "$body" | grep -q 'Old Footer Name'; then echo "OK:$tag"; fi; }
for p in /orders /reports; do
  body=$(curl -s "$BASE$p")
  echo "$body" | grep -q 'Old Footer Name' && echo "OK:$p"
  echo "$body" | grep -q 'Acme Console' && echo "OK:$p"
  echo "$body" | grep -q 'Order Desk' && echo "OK:$p"
  echo "$body" | grep -q '"status":"ok"' && echo "OK:$p"
done
curl -s "$BASE/" | grep -qi 'acme console' || fail "no footer"
grep -q 'Legacy Title' <<< "$page" || fail "no title"
grep -q 'Legacy Title' "$LOG" || fail "no log line"
echo "$response" | grep -q "mermaid" || fail "no diagram script"
`,
	}
	assert.Equal(t, []string{"scripts/smoke.sh:1", "scripts/smoke.sh:10", "scripts/smoke.sh:4"}, shellFindings(t, "smoke-check-greps-renamed-ui-text", files))
	// Without the application's sources the rule cannot tell.
	assert.Empty(t, shellFindings(t, "smoke-check-greps-renamed-ui-text", map[string]string{"scripts/smoke.sh": files["scripts/smoke.sh"]}))
}

// A one-off command that reads the unit's first environment file and not the
// second one the service also gets: the command runs without the secrets.
func TestOneoffCommandEnvDiffersFromServiceUnit(t *testing.T) {
	files := map[string]string{
		"scripts/deploy.sh": `APP_ENV="/opt/app/.env"
APP_BIN="/opt/app/bin/app"
`,
		"scripts/lib.sh": `LOADER="/usr/local/bin/app-secrets"
write_unit() {
  remote_sudo "cat > /etc/systemd/system/app.service << 'EOF'
[Service]
EnvironmentFile=/opt/app/.env
EnvironmentFile=-/run/app/secrets.env
ExecStartPre=$LOADER
ExecStart=/opt/app/bin/app
EOF"
}
backfill() {
  remote "sudo -u app bash -c \"set -a; source '$APP_ENV'; set +a; exec '$APP_BIN' --backfill\""
  remote "sudo -u app bash -c \"set -a; source '$APP_ENV'; source /run/app/secrets.env; set +a; exec '$APP_BIN' --check\""
  remote_sudo "set -a; source '$APP_ENV'; set +a
RUNTIME_DIRECTORY=/run/app-deploy '$LOADER'"
}
`,
		"scripts/ops.sh": `REMOTE_ENV="/opt/app/.env"
ssh "$HOST" "sudo bash -c 'set -a; source $REMOTE_ENV; set +a; psql \"\$DB_DSN\" -c \"SELECT 1\"'"
. ./local.env
`,
	}
	assert.Equal(t, []string{"scripts/lib.sh:12", "scripts/ops.sh:2"}, shellFindings(t, "oneoff-command-env-differs-from-service-unit", files))
	// The loader line kept in a variable spliced into the unit, and a command
	// that runs the loader itself; a test script asserting the unit text.
	assert.Empty(t, shellFindings(t, "oneoff-command-env-differs-from-service-unit", map[string]string{
		"lib.sh": `LOADER="/usr/local/bin/app-secrets"
unit() {
  local pre=""
  [ "$WITH_LOADER" = yes ] && pre="ExecStartPre=$LOADER
EnvironmentFile=-/run/app/secrets.env
"
  remote_sudo "cat > /etc/systemd/system/app.service << EOF
EnvironmentFile=/opt/app/.env
${pre}ExecStart=/opt/app/bin/app
EOF"
}
remote_sudo "set -e
set -a; source /opt/app/.env; set +a
RUNTIME_DIRECTORY=/run/app-deploy $LOADER >/dev/null"
`,
		"lib_test.sh": `assert_contains "$out" "EnvironmentFile=/opt/app/extra.env"
remote "set -a; source /opt/app/.env; set +a; true"
`,
	}))
	// A unit with one environment file: sourcing it is the service's
	// environment.
	assert.Empty(t, shellFindings(t, "oneoff-command-env-differs-from-service-unit", map[string]string{
		"lib.sh": `remote_sudo "cat > /etc/systemd/system/app.service << 'EOF'
EnvironmentFile=/opt/app/.env
EOF"
remote "set -a; source /opt/app/.env; set +a; /opt/app/bin/app --check"
`,
	}))
}

// The golang image sets GOTOOLCHAIN=local: an image older than the go line of
// go.mod refuses to build the module.
func TestCIToolchainImageOlderThanGoMod(t *testing.T) {
	root := t.TempDir()
	write := func(path, content string) *core.FileContext {
		full := filepath.Join(root, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
		ctx, err := core.NewFileContextChecked(full, root, []byte(content), core.DefaultConfig())
		require.NoError(t, err)
		return ctx
	}
	write("go.mod", "module example.com/app\n\ngo 1.25.0\n")
	write("tools/go.mod", "module example.com/tools\n\ngo 1.22\n")
	files := []*core.FileContext{
		write("bitbucket-pipelines.yml", `image: golang:1.24

pipelines:
  default:
    - step:
        image: golang:1.25-alpine
        script:
          - go test ./...
    - step:
        image:
          name: docker.io/library/golang:1.23.4
    - step:
        image: node:20
`),
		write(".github/workflows/ci.yml", `jobs:
  test:
    container: golang:1.24.6-bookworm
`),
		write("Dockerfile", "FROM golang:1.24 AS build\nFROM gcr.io/distroless/static\n"),
		write("tools/Dockerfile", "FROM golang:1.22-alpine\n"),
		write(".gitlab-ci.yml", "image: golang:1.25\n"),
	}
	rule := NewCIToolchainImageOlderThanGoModRule()
	var found []*core.Violation
	for _, ctx := range files {
		found = append(found, rule.AnalyzeFile(ctx)...)
	}
	assert.Equal(t, []string{".github/workflows/ci.yml:3", "Dockerfile:1", "bitbucket-pipelines.yml:1", "bitbucket-pipelines.yml:11"}, foundLines(found))
}

// Repro from a real project: a deploy script glued a double-quoted part with
// set -e and the variables to expand to a single-quoted part with the remote
// commands - one shell word, and set -e is in it.
func TestRemoteScriptErrexitGluedQuotes(t *testing.T) {
	shellWanted(t, "remote-multiline-script-without-errexit", "deploy.sh", `#!/bin/bash
ssh "$HOST" "set -euo pipefail; tag=$TAG; "'docker pull "app:$tag"
    docker tag "app:$tag" app:current'
ssh "$HOST" "tag=$TAG; "'docker pull "app:$tag" # want
    docker tag "app:$tag" app:current'
`)
}

// A heredoc fed to ssh inside "$( ... )": the quotes within the substitution
// are words of the command it runs, not the end of the outer string, so the
// heredoc is no quoted multi-line argument. Outside the substitution the same
// call is not reported either.
func TestRemoteScriptErrexitHeredocInQuotedSubstitution(t *testing.T) {
	assert.Empty(t, shellFindings(t, "remote-multiline-script-without-errexit", map[string]string{
		"creds.sh": `#!/usr/bin/env bash
set -euo pipefail
creds="$(ssh "$HOST" 'bash -s' <<'REMOTE'
set -euo pipefail
set -a; . /opt/app/.env; set +a
if [ -z "${TOKEN:-}" ]; then
    echo "MISSING TOKEN" >&2; exit 1
fi
printf 'T=%s\n' "${#TOKEN}"
REMOTE
)"
printf '%s\n' "$creds"
`,
	}))
	// A multi-line script quoted inside the substitution is still one.
	shellWanted(t, "remote-multiline-script-without-errexit", "status.sh", `#!/bin/bash
out="$(ssh "$HOST" 'systemctl restart app # want
    systemctl is-active app')"
`)
}

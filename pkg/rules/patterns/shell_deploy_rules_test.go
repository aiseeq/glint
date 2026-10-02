package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Under set -e a failed command before the last && does not stop the script:
// the success log after the list is printed whatever happened.
func TestShellAndListFailurePasses(t *testing.T) {
	assert.Equal(t, []string{"switch.sh:12", "switch.sh:6"}, shellFindings(t, "shell-and-list-failure-passes", map[string]string{
		"switch.sh": `#!/bin/bash
set -euo pipefail

switch_proxy() {
    sudo sed -i "s/old/new/" "$conf"
    sudo proxy -t && sudo proxy -s reload
    log_success "Proxy switched"
    stop_old
}

cd "$dir"
sudo proxy -t && sudo proxy -s reload
echo "Proxy switched to $port"
`,
	}))
	// The list is the last command, a condition, or followed by a fallback;
	// a script without set -e does not stop on any failure.
	assert.Empty(t, shellFindings(t, "shell-and-list-failure-passes", map[string]string{
		"ok.sh": `#!/bin/bash
set -e
if sudo proxy -t && sudo proxy -s reload; then
    log_success "switched"
fi
sudo proxy -t && sudo proxy -s reload || { log_error "failed"; exit 1; }
log_success "switched"
[[ -f "$conf" ]] && source "$conf"
log_info "loaded"
check() {
    sudo proxy -t && sudo proxy -s reload
}
`,
		"loose.sh": `#!/bin/bash
sudo proxy -t && sudo proxy -s reload
echo "switched"
`,
	}))
}

// A single health request right after starting a container fails on a cold
// start and aborts the operation that needed the container.
func TestShellHealthCheckWithoutWait(t *testing.T) {
	assert.Equal(t, []string{"Makefile:3", "rollback.sh:5"}, shellFindings(t, "shell-health-check-without-wait", map[string]string{
		"rollback.sh": `#!/bin/bash
if ! docker ps --filter "name=$c" | grep -q .; then
    docker start "$c" >/dev/null
fi
if ! curl -f -s "http://127.0.0.1:$port/api/health" > /dev/null; then
    log_error "not healthy"
    exit 1
fi
`,
		"Makefile": `up:
  @docker compose up -d api
  @curl -fsS http://localhost:8080/healthz
`,
	}))
	assert.Empty(t, shellFindings(t, "shell-health-check-without-wait", map[string]string{
		"wait.sh": `#!/bin/bash
docker start "$c"
for i in $(seq 1 30); do
    if curl -fs "http://127.0.0.1:$port/api/health" >/dev/null; then
        break
    fi
    sleep 2
done
systemctl restart app
curl --retry 10 --retry-connrefused -fs http://localhost/health
docker run -d --name x img
sleep 5
curl -fs http://localhost/health
`,
	}))
}

// A make variable the caller sets on the command line, pasted inside single
// quotes, breaks the shell word at its first apostrophe.
func TestMakeVariableInSingleQuotes(t *testing.T) {
	assert.Equal(t, []string{"Makefile:5"}, shellFindings(t, "make-variable-in-single-quotes", map[string]string{
		"Makefile": `API_BODY ?=
API_PATH ?=

request:
  @body=$$(printf '%s' '$(API_BODY)' | base64 -w0); \
  curl -X POST "$(API_PATH)" -d "$$body"
`,
	}))
	assert.Empty(t, shellFindings(t, "make-variable-in-single-quotes", map[string]string{
		"Makefile": `export API_BODY_ENV = $(API_BODY)
COLOR := \033[0;32m

request:
  @printf '%s' "$$API_BODY_ENV" | base64 -w0
  @printf '$(COLOR)done\n'
  @path='$(API_PATH)'; echo "$$path"
`,
		// A value the makefile fixes itself carries no apostrophe.
		"keys.mk": `KEY_COMMENT := monitor-backup-check

keys:
  @ssh $(HOST) 'ssh-keygen -q -N "" -C $(KEY_COMMENT) -f $(KEY)'
`,
	}))
}

// export NAME=$(cmd) returns export's status: a failed command passes and the
// variable is empty.
func TestShellExportMasksSubstitutionStatus(t *testing.T) {
	assert.Equal(t, []string{"Makefile:3", "run.sh:4"}, shellFindings(t, "shell-export-masks-substitution-status", map[string]string{
		"Makefile": `reference:
  @set -a; . ./.env; set +a; \
    export ADMIN_TOKEN=$$(python3 tools/make-token.py); \
    cd backend && go test ./tests/ -run TestReference
`,
		"run.sh": `#!/bin/bash
set -euo pipefail
run() {
    local answer=$(curl -fsS "$url")
    printf '%s\n' "$answer"
}
`,
	}))
	assert.Empty(t, shellFindings(t, "shell-export-masks-substitution-status", map[string]string{
		"Makefile": `reference:
  @export ADMIN_TOKEN=$$(python3 tools/make-token.py); \
    if [ -z "$$ADMIN_TOKEN" ]; then echo "no token" >&2; exit 1; fi; \
    go test ./...
`,
		"ok.sh": `#!/bin/bash
export ROOT=$(dirname "$0")
local stamp=$(date +%s)
export TOKEN
TOKEN=$(python3 make-token.py)
readonly HOST=$(hostname)
`,
		// A value compared, a capture with its own fallback, a value only
		// shown in a message: the script already decides what an empty means.
		"status.sh": `#!/bin/bash
status() {
    local code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    if [ "$code" = "200" ]; then log_success "up"; fi
    local tail=$(docker logs "$name" 2>&1 | tail -5 || echo "")
    printf '%s\n' "$tail"
    local state=$(docker ps --filter "name=$name" --format "{{.Status}}")
    log_info "Container: $state"
    local active=$(get_active)
    [[ "$active" == "blue" ]] && echo green
    local recent=$(docker logs "$name" 2>&1 | tail -50)
    notify "$recent"
}
get_active() { cat "$state_file"; }
`,
	}))
}

// A body passed whole as one argument or one variable of a remote command
// line hits the per-argument limit once the data grows.
func TestShellPayloadAsArgument(t *testing.T) {
	assert.Equal(t, []string{"check.sh:5", "helpers.sh:11", "helpers.sh:5"}, shellFindings(t, "shell-payload-as-argument", map[string]string{
		"helpers.sh": `#!/bin/bash
local_api() {
    local method="$1" path="$2" body="${3:-}"
    local args=(-sfS -X "$method")
    args+=(-H 'Content-Type: application/json' --data-binary "$body")
    curl "${args[@]}" "${base}${path}"
}
remote_api() {
    local body="${3:-}" body_b64=''
    body_b64=$(printf '%s' "$body" | base64 -w0)
    ssh "$host" "CHECK_PATH='$2' CHECK_BODY_B64='$body_b64' bash -s" < check.sh
}
`,
		"check.sh": `#!/bin/bash
API_BODY=""
API_BODY=$(printf '%s' "$API_BODY_B64" | base64 -d)
curl_args=(-sfS -X POST)
curl_args+=(--data-binary "$API_BODY")
curl "${curl_args[@]}" "$url"
`,
	}))
	assert.Empty(t, shellFindings(t, "shell-payload-as-argument", map[string]string{
		"ok.sh": `#!/bin/bash
payload=$(jq -n --arg name "$name" '{name: $name}')
curl -fsS -X POST -d "$payload" "$url"
send() {
    local body="$1"
    printf '%s' "$body" | curl -fsS --data-binary @- "$url"
    printf '%s' "$body" > "$file"
    curl -fsS --data-binary "@$file" "$url"
}
dump() {
    local db="$1"
    need=$(sudo -u postgres psql -d "$db" -tAc "SELECT 1")
}
`,
	}))
}

// The stderr of a service call that feeds a pipe is thrown away: the consumer
// gets an empty input, and the reason of the failure is lost.
func TestShellPipeProducerStderrDiscarded(t *testing.T) {
	assert.Equal(t, []string{"flags.sh:13", "flags.sh:5"}, shellFindings(t, "shell-pipe-producer-stderr-discarded", map[string]string{
		"flags.sh": `#!/bin/bash
api_get() {
    local path="$1"
    if [ "$env" = "prod" ]; then
        make -C "$root" --no-print-directory api-request PATH_ARG="$path" 2>/dev/null
        return
    fi
    curl -sfS "${base}${path}"
}
status() {
    api_get "/journal" | python3 render.py status
}
curl -fsS "$url" 2>/dev/null | jq '.items'
`,
	}))
	assert.Empty(t, shellFindings(t, "shell-pipe-producer-stderr-discarded", map[string]string{
		"ok.sh": `#!/bin/bash
count=$(ls "$dir" 2>/dev/null | wc -l)
grep -r TODO src 2>/dev/null | head
fetch() {
    curl -sfS "$url" 2>/dev/null
}
answer=$(fetch)
curl -fsS "$url" 2>"$log" | jq .
curl -sf "$url/health" 2>/dev/null | jq '.status' || echo "not reachable"
if ! curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -q 200; then
    echo "server not running"
fi
ssh "$host" "docker ps -q 2>/dev/null" | wc -l
`,
	}))
}

// Under set -u a variable assigned only in a case arm is unbound when the
// input lacks that key, while its siblings are initialized before the loop.
func TestShellVariableUnsetUnderNounset(t *testing.T) {
	assert.Equal(t, []string{"sync-env.sh:14"}, shellFindings(t, "shell-variable-unset-under-nounset", map[string]string{
		"sync-env.sh": `#!/usr/bin/env bash
set -euo pipefail
public_key=""
provider=""
clients=""
while IFS='=' read -r key value; do
    case "$key" in
        PUBLIC_KEY) public_key="$value" ;;
        PROVIDER) provider="$value" ;;
        CLIENTS) clients="$value" ;;
        CLIENT_WRITES) client_writes="$value" ;;
    esac
done < "$file"
CLIENT_WRITES="$client_writes" awk '{print}' "$env_file"
`,
	}))
	assert.Empty(t, shellFindings(t, "shell-variable-unset-under-nounset", map[string]string{
		"ok.sh": `#!/usr/bin/env bash
set -euo pipefail
public_key=""
provider=""
client_writes=""
while IFS='=' read -r key value; do
    case "$key" in
        PUBLIC_KEY) public_key="$value" ;;
        PROVIDER) provider="$value" ;;
        CLIENT_WRITES) client_writes="$value" ;;
        EXTRA) extra="$value" ;;
    esac
done < "$file"
echo "$client_writes ${extra:-}"
`,
		"line.sh": `#!/usr/bin/env bash
set -u
name=$(basename "$0")
fmt=""
case "$cmd" in
    ps)
        all=0 quiet=0 name="" fmt=""
        case "$1" in
            -a) all=1 ;;
            -q) quiet=1 ;;
            --name) name=$2 ;;
            --format) fmt=$2 ;;
        esac
        echo "$all $quiet $name $fmt"
        ;;
esac
`,
		"loose.sh": `#!/usr/bin/env bash
a=""
b=""
case "$1" in
    x) a=1 ;;
    y) b=1 ;;
    z) c=1 ;;
esac
echo "$c"
`,
	}))
}

// A quote inside bash -c '...' closes the script: the rest of the command
// becomes extra arguments of bash and never runs.
func TestShellCScriptSplitByQuote(t *testing.T) {
	assert.Equal(t, []string{"Makefile:2"}, shellFindings(t, "shell-c-script-split-by-quote", map[string]string{
		"Makefile": `deploy:
  @bash -c ' \
    set -e; \
    HEALTH=$$(curl -sf http://127.0.0.1/api/health); \
    if echo "$$HEALTH" | jq -e '.data.healthy == true' > /dev/null; then \
      echo ok; \
    fi; \
    echo phase 7'
`,
	}))
	assert.Empty(t, shellFindings(t, "shell-c-script-split-by-quote", map[string]string{
		"Makefile": `deploy:
  @bash -c ' \
    if echo "$$HEALTH" | jq -e ".data.healthy == true" > /dev/null; then \
      echo ok; \
    fi'
quoted:
  @bash -c 'echo '"'"'quoted'"'"' and '\''more'\'''
args:
  @bash -c 'echo "$$0 $$1"' first second
`,
	}))
}

// A secret in a command's arguments is visible in ps to every user of the
// host while the command runs.
func TestSecretInCommandArgument(t *testing.T) {
	assert.Equal(t, []string{"bootstrap.sh:2", "bootstrap.sh:3", "check.sh:3", "helpers.sh:3"}, shellFindings(t, "secret-in-command-argument", map[string]string{
		"check.sh": `#!/bin/bash
TOKEN=$(python3 make-token.py)
curl_args=(-sfS -X "$API_METHOD" -H "Cookie: admin_token=$TOKEN")
curl "${curl_args[@]}" "$url"
`,
		"helpers.sh": `local_call() {
    local method="$1"
    local args=(-sfS -X "$method" -H "Cookie: admin_token=$local_token")
    curl "${args[@]}" "$base"
}
`,
		"bootstrap.sh": `#!/bin/bash
sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
curl -fsS -H "Authorization: Bearer $api_token" "$url"
`,
	}))
	assert.Empty(t, shellFindings(t, "secret-in-command-argument", map[string]string{
		"ok.sh": `#!/bin/bash
printf 'Cookie: admin_token=%s\n' "$TOKEN" > "$header_file"
curl -fsS -H "@$header_file" "$url"
sudo -u postgres psql <<SQL
CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
SQL
curl -fsS -H "X-Request-Id: $request_id" "$url"
echo "token file: $TOKEN_FILE"
`,
	}))
}

// A generated secret applied to a database or service before it is written
// anywhere is lost when the script stops in between; a rerun makes another.
func TestGeneratedSecretUsedBeforeSaved(t *testing.T) {
	assert.Equal(t, []string{"bootstrap.sh:6"}, shellFindings(t, "generated-secret-used-before-saved", map[string]string{
		"bootstrap.sh": `#!/bin/bash
set -e
DB_PASSWORD="${DB_PASSWORD:-$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)}"
DB_USER=app

sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
certbot certonly --nginx -d "$domain"
cat > "$root/.env" << ENVEOF
DB_PASSWORD=$DB_PASSWORD
ENVEOF
`,
	}))
	assert.Empty(t, shellFindings(t, "generated-secret-used-before-saved", map[string]string{
		"saved.sh": `#!/bin/bash
DB_PASSWORD=$(openssl rand -hex 24)
printf 'DB_PASSWORD=%s\n' "$DB_PASSWORD" > "$secret_file"
chmod 600 "$secret_file"
sudo -u postgres psql -c "CREATE USER app WITH PASSWORD '$DB_PASSWORD';"
`,
		"heredoc.sh": `#!/bin/bash
JWT_SECRET=$(openssl rand -base64 48)
cat > "$root/.env" <<EOF
JWT_SECRET=$JWT_SECRET
EOF
docker compose up -d
`,
	}))
}

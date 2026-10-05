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

// deployFindings runs a registered rule over the files of a root: Go files
// with their syntax trees, make files with recipe indents.
func deployFindings(t *testing.T, name string, files map[string]string) []string {
	t.Helper()
	rule, ok := rules.Get(name)
	require.True(t, ok, name)
	var contexts []*core.FileContext
	for path, source := range files {
		if strings.HasSuffix(path, ".go") {
			contexts = append(contexts, rulestest.GoFile(t, path, source))
			continue
		}
		if strings.HasSuffix(path, ".mk") || strings.HasSuffix(path, "Makefile") {
			source = recipe(source)
		}
		contexts = append(contexts, rulestest.TextFile(t, path, source))
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

const deployEnvConfig = `package config

import "os"

type Config struct {
	DBHost, RPCProvider, ExplorerToken, Admins, Writes, Debug, Region string
}

func Load() Config {
	return Config{
		DBHost:        os.Getenv("APP_DB_HOST"),
		RPCProvider:   os.Getenv("CHAIN_RPC_PROVIDER"),
		ExplorerToken: os.Getenv("EXPLORER_TOKEN"),
		Admins:        os.Getenv("ADMIN_EMAILS"),
		Writes:        os.Getenv("SERVICE_CLIENT_WRITES"),
		Debug:         os.Getenv("APP_DEBUG"),
		Region:        envOr("APP_REGION", "eu"),
	}
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
`

const deployEnvExample = `APP_DB_HOST=127.0.0.1
CHAIN_RPC_PROVIDER=fast        # fast (recommended) or public
EXPLORER_TOKEN=                # read-only explorer token
ADMIN_EMAILS=                  # REQUIRED - exact emails, comma-separated
APP_DEBUG=                     # optional, true prints request bodies
APP_REGION=eu
`

const deployEnvBootstrap = `#!/bin/bash
set -euo pipefail
cat > "$ROOT/shared/.env" << ENVEOF
APP_DB_HOST=127.0.0.1
ADMIN_EMAILS=
SERVICE_CLIENTS=
SERVICE_CLIENT_PORTFOLIOS=
ENVEOF
`

// A key the code reads that the deploy never writes is missing on the
// server: the integration it configures silently stays off there.
func TestEnvKeyMissingFromDeployEnv(t *testing.T) {
	assert.Equal(t, []string{"deploy.mk:5", "deploy.mk:5", "deploy.mk:5", "deploy.mk:5"},
		deployFindings(t, "env-key-missing-from-deploy-env", map[string]string{
			"internal/config/config.go": deployEnvConfig,
			".env.example":              deployEnvExample,
			"deploy/bootstrap.sh":       deployEnvBootstrap,
			// CHAIN_RPC_PROVIDER and EXPLORER_TOKEN are in the example and
			// nowhere on the server; ADMIN_EMAILS is required and the
			// template leaves it empty; SERVICE_CLIENT_WRITES is missing
			// next to the SERVICE_CLIENT_ keys the deploy carries.
			"deploy.mk": `deploy:
  deploy_env=$$(mktemp); \
  trap 'rm -f "$$deploy_env"' EXIT; \
  if [ -z "$${ANON_KEY:-}" ]; then exit 1; fi; \
  printf "ANON_KEY=%s\nSERVICE_CLIENTS=%s\nSERVICE_CLIENT_PORTFOLIOS=%s\n" "$$ANON_KEY" "$$SERVICE_CLIENTS" "$$SERVICE_CLIENT_PORTFOLIOS" > "$$deploy_env"; \
  scp -q "$$deploy_env" $$VPS:/tmp/deploy-env
`,
		}))
}

// The deploy writes every key the code needs; an optional key, a key with
// a default in the code, and a key only tests read are not needed.
func TestEnvKeyMissingFromDeployEnvComplete(t *testing.T) {
	assert.Empty(t, deployFindings(t, "env-key-missing-from-deploy-env", map[string]string{
		"internal/config/config.go": deployEnvConfig,
		"internal/config/config_test.go": `package config

import "os"

func audit() string { return os.Getenv("APP_AUDIT_TOKEN") }
`,
		".env.example":        deployEnvExample + "APP_AUDIT_TOKEN=\n",
		"deploy/bootstrap.sh": deployEnvBootstrap,
		"deploy.mk": `deploy:
  printf "ANON_KEY=%s\nSERVICE_CLIENTS=%s\nSERVICE_CLIENT_PORTFOLIOS=%s\nSERVICE_CLIENT_WRITES=%s\nCHAIN_RPC_PROVIDER=%s\nEXPLORER_TOKEN=%s\nADMIN_EMAILS=%s\n" a b c d e f g > "$$deploy_env"
`,
	}))
	// A project whose deploy writes no env file manages it elsewhere.
	assert.Empty(t, deployFindings(t, "env-key-missing-from-deploy-env", map[string]string{
		"internal/config/config.go": deployEnvConfig,
		".env.example":              deployEnvExample,
		"deploy.mk": `deploy:
  scp .env.prod $$VPS:/srv/app/.env
`,
	}))
}

// Without a writer that carries keys, the template is filled by hand: a
// required key it leaves empty is the operator's to fill, while a key it
// does not list at all is one nobody fills.
func TestEnvKeyMissingFromDeployEnvTemplateOnly(t *testing.T) {
	assert.Equal(t, []string{"deploy/bootstrap.sh:3", "deploy/bootstrap.sh:3", "deploy/bootstrap.sh:3"},
		deployFindings(t, "env-key-missing-from-deploy-env", map[string]string{
			"internal/config/config.go": deployEnvConfig,
			".env.example":              deployEnvExample,
			"deploy/bootstrap.sh":       deployEnvBootstrap,
		}))
}

// Docker runs the health check inside the container with its environment:
// a port the image declares as configurable but the check spells as a
// literal makes the container unhealthy when the port is changed.
func TestDockerfileHealthcheckLiteralPort(t *testing.T) {
	assert.Equal(t, []string{"deploy/Dockerfile:6"}, deployFindings(t, "dockerfile-healthcheck-literal-port", map[string]string{
		"deploy/Dockerfile": `FROM alpine:3.20
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8080

HEALTHCHECK --interval=30s --timeout=10s \
    CMD curl -f http://localhost:8080/api/health || exit 1
EXPOSE 8080
`,
	}))
	// The check reads the variable, checks another port, or the image
	// declares no port at all.
	assert.Empty(t, deployFindings(t, "dockerfile-healthcheck-literal-port", map[string]string{
		"Dockerfile": `FROM alpine:3.20
ENV SERVER_PORT=8080
HEALTHCHECK CMD curl -f "http://localhost:${SERVER_PORT}/api/health" || exit 1
`,
		"Dockerfile.metrics": `FROM alpine:3.20
ARG APP_PORT=8080
HEALTHCHECK CMD wget -qO- http://127.0.0.1:9100/metrics || exit 1
`,
		"Dockerfile.plain": `FROM alpine:3.20
HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1
`,
	}))
}

const hostNetworkNginx = `server {
    listen 443 ssl;
    location / {
        proxy_pass http://127.0.0.1:8081;
    }
}
`

// With host networking a service bound to 0.0.0.0 listens on every
// interface of the host, past the reverse proxy that fronts it.
func TestHostNetworkServiceBindsAllInterfaces(t *testing.T) {
	assert.Equal(t, []string{"deploy/bootstrap.sh:9", "deploy/compose/docker-compose.blue.yml:7"},
		deployFindings(t, "host-network-service-binds-all-interfaces", map[string]string{
			"deploy/nginx/site.conf": hostNetworkNginx,
			"deploy/compose/docker-compose.blue.yml": `services:
  app:
    image: app:latest
    container_name: app-blue
    network_mode: host
    environment:
      - SERVER_HOST=0.0.0.0
      - SERVER_PORT=8081
    env_file:
      - ../shared/.env
`,
			"deploy/bootstrap.sh": `#!/bin/bash
set -euo pipefail
cat > "$ROOT/green/docker-compose.yml" << EOF
services:
  app:
    image: app:$TAG
    network_mode: "host"
    environment:
      LISTEN_ADDR: ":8082"
EOF
`,
		}))
	// A service on the bridge network must bind 0.0.0.0 to be reached
	// through its published port; a host-network service on loopback, or a
	// host without a local reverse proxy, is not the case.
	assert.Empty(t, deployFindings(t, "host-network-service-binds-all-interfaces", map[string]string{
		"deploy/nginx/site.conf": hostNetworkNginx,
		"docker-compose.yml": `services:
  api:
    image: api
    ports:
      - "127.0.0.1:8081:8081"
    environment:
      - SERVER_HOST=0.0.0.0
  worker:
    image: worker
    network_mode: host
    environment:
      - SERVER_HOST=127.0.0.1
`,
	}))
	assert.Empty(t, deployFindings(t, "host-network-service-binds-all-interfaces", map[string]string{
		"compose.yaml": `services:
  edge:
    image: edge
    network_mode: host
    environment:
      - SERVER_HOST=0.0.0.0
`,
	}))
}

// A read handed to a fallback helper with a literal has a default in the
// code; a read formatted into a string does not.
func TestEnvKeyMissingFromDeployEnvFallbackHelper(t *testing.T) {
	assert.Equal(t, []string{"deploy.mk:2"}, deployFindings(t, "env-key-missing-from-deploy-env", map[string]string{
		"internal/config/config.go": `package config

import (
	"cmp"
	"fmt"
	"os"
)

func endpoints() []string {
	return []string{
		firstNonEmpty(os.Getenv("GRAPH_ENDPOINT"), "https://graph.example.com"),
		cmp.Or(os.Getenv("RPC_ENDPOINT"), "https://rpc.example.com"),
		fmt.Sprintf("https://%s/api", os.Getenv("API_HOST")),
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
`,
		".env.example": "GRAPH_ENDPOINT=https://graph.example.com\nRPC_ENDPOINT=\nAPI_HOST=\n",
		"deploy.mk": `deploy:
  printf "ANON_KEY=%s\n" "$$ANON_KEY" > "$$deploy_env"
`,
	}))
}

// The env template's word on a key outweighs its siblings: a key it calls
// conditional stays unreported next to the written provider key.
func TestEnvKeyMissingFromDeployEnvConditionalSibling(t *testing.T) {
	assert.Empty(t, deployFindings(t, "env-key-missing-from-deploy-env", map[string]string{
		"internal/config/config.go": `package config

import "os"

func rpc() (string, string) { return os.Getenv("CHAIN_RPC_PROVIDER"), os.Getenv("CHAIN_RPC_URL") }
`,
		".env.example": "CHAIN_RPC_PROVIDER=fast\nCHAIN_RPC_URL=      # Required only for CHAIN_RPC_PROVIDER=custom\n",
		"deploy.mk": `deploy:
  printf "CHAIN_RPC_PROVIDER=%s\n" "$$CHAIN_RPC_PROVIDER" > "$$deploy_env"
`,
	}))
}

// A flag compared with a literal and a value used only when set may stay
// empty; a value checked for emptiness to fail is needed.
func TestEnvKeyMissingFromDeployEnvGuardedRead(t *testing.T) {
	assert.Equal(t, []string{"deploy.mk:2"}, deployFindings(t, "env-key-missing-from-deploy-env", map[string]string{
		"internal/config/config.go": `package config

import (
	"errors"
	"os"
	"time"
)

func load() (time.Duration, bool, string, error) {
	interval := time.Hour
	if v := os.Getenv("SYNC_INTERVAL"); v != "" {
		interval, _ = time.ParseDuration(v)
	}
	region := "eu"
	if v := os.Getenv("APP_REGION"); v == "" {
		v = region
	}
	enabled := os.Getenv("ALERTS_ENABLED") == "true"
	if v := os.Getenv("SIGNING_KEY"); v == "" {
		return 0, false, "", errors.New("SIGNING_KEY is required")
	}
	return interval, enabled, region, nil
}
`,
		".env.example": "SYNC_INTERVAL=1h\nAPP_REGION=eu\nALERTS_ENABLED=false\nSIGNING_KEY=\n",
		"deploy.mk": `deploy:
  printf "ANON_KEY=%s\n" "$$ANON_KEY" > "$$deploy_env"
`,
	}))
}

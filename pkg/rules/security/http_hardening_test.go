package security

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func textRuleLines(t *testing.T, rule fileRule, path, content string) []int {
	t.Helper()
	var lines []int
	for _, v := range rule.AnalyzeFile(rulestest.TextFile(t, path, content)) {
		lines = append(lines, v.Line)
	}
	slices.Sort(lines)
	return lines
}

// A skip list matched by prefix that holds "/" skips everything; the same
// list matched exactly, or a prefix list without the root, does not.
func TestPathPrefixAllowlistMatchesAll(t *testing.T) {
	code := `package middleware

import (
	"net/http"
	"strings"
)

var publicPrefixes = []string{"/static/", "/"}

func limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		skip := []string{"/health", "/", "/assets/"}
		for _, p := range skip {
			if r.URL.Path == p || strings.HasPrefix(r.URL.Path, p) {
				next.ServeHTTP(w, r)
				return
			}
		}
		for _, p := range publicPrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				return
			}
		}
		exact := []string{"/", "/health"}
		for _, p := range exact {
			if r.URL.Path == p {
				return
			}
		}
		prefixes := []string{"/assets/", "/static/"}
		for _, p := range prefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				return
			}
		}
	})
}
`
	assert.Equal(t, []int{14, 20}, ruleLines(t, NewPathPrefixAllowlistRule(), code))
}

// The text of an internal error goes to the client in a 5xx response; the
// same text in a 4xx validation answer, or a 5xx with a fixed message, is fine.
func TestErrorDetailIn5xxResponse(t *testing.T) {
	code := `package api

import (
	"fmt"
	"net/http"
)

func SendError(w http.ResponseWriter, status int, msg, code, details string) {}
func SendInternalServerError(w http.ResponseWriter, msg, details string) {}
func writeJSON(w http.ResponseWriter, status int, v any) {}

func handle(w http.ResponseWriter, err error, upstreamErr error) {
	SendError(w, http.StatusInternalServerError, "Failed to get balance", "BALANCE_FAILED", err.Error())
	http.Error(w, err.Error(), http.StatusInternalServerError)
	SendInternalServerError(w, "failed", err.Error())
	writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("upstream: %v", upstreamErr)})
	SendError(w, http.StatusBadRequest, "invalid", "VALIDATION", err.Error())
	SendError(w, http.StatusInternalServerError, "Failed to get balance", "BALANCE_FAILED", "")
	writeJSON(w, 500, map[string]string{"error": "internal"})
}
`
	assert.Equal(t, []int{13, 14, 15, 16}, ruleLines(t, NewErrorDetailIn5xxResponseRule(), code))
}

// A project helper that logs or reports the details and sends a fixed text,
// or puts them in the body only under a condition (outside production, below
// 500), does not leak them; one that encodes them into the body does, also
// through a chain of helpers.
func TestErrorDetailIn5xxResponseFollowsHelpers(t *testing.T) {
	found := projectFileLines(t, NewErrorDetailIn5xxResponseRule(), map[string]string{
		"httpx/helpers.go": `package httpx

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

type envelope struct{ Message, Code, Details string }

func SendError(w http.ResponseWriter, status int, msg, code, details string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{msg, code, details})
}

func SendInternalServerErrorWithTrace(w http.ResponseWriter, r *http.Request, msg, details string) {
	slog.Error("internal server error", "message", msg, "details", details)
	SendError(w, http.StatusInternalServerError, msg, "INTERNAL_ERROR", "")
}

func SendInternalDev(w http.ResponseWriter, msg, details string, production bool) {
	shown := ""
	if !production {
		shown = details
	}
	SendError(w, http.StatusInternalServerError, msg, "INTERNAL_ERROR", shown)
}

func notifyServerError(r *http.Request, status int, msg, details string) {}

func SendErrorWithTrace(w http.ResponseWriter, r *http.Request, status int, msg, details string) {
	body := envelope{Message: msg}
	if details != "" && status < 500 {
		body.Details = details
	}
	notifyServerError(r, status, msg, details)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func sendInternal(w http.ResponseWriter, msg, details string) {
	sendResponse(w, http.StatusInternalServerError, msg, details)
}

func sendResponse(w http.ResponseWriter, status int, msg, details string) {
	body := envelope{Message: msg}
	if details != "" {
		body.Details = details
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func SendServerError(w http.ResponseWriter, msg, details string) {
	sendInternal(w, msg, details)
}
`,
		"export/csv.go": `package export

func Encode(header []string, rows [][]string) ([]byte, error) { return nil, nil }
`,
		"api/handler.go": `package api

import (
	"net/http"

	"example.com/app/httpx"
)

func handle(w http.ResponseWriter, r *http.Request, err error) {
	httpx.SendError(w, http.StatusInternalServerError, "failed", "X", err.Error())
	httpx.SendInternalServerErrorWithTrace(w, r, "failed", err.Error())
	httpx.SendInternalDev(w, "failed", err.Error(), true)
	httpx.SendErrorWithTrace(w, r, http.StatusInternalServerError, "failed", err.Error())
	httpx.SendServerError(w, "failed", err.Error())
}
`,
	})
	assert.Equal(t, []string{"api/handler.go:10", "api/handler.go:14"}, found)
}

// A response type, named so or declared in a handler, carrying a debug
// section; a debug switch of a config and a response without one are fine.
func TestDebugFieldInResponse(t *testing.T) {
	code := `package api

import (
	"fmt"
	"net/http"
)

type ListResponse struct {
	Items []string ` + "`json:\"items\"`" + `
	Debug any      ` + "`json:\"_debug,omitempty\"`" + `
}

type Config struct {
	Debug   bool   ` + "`json:\"debug\"`" + `
	Details string ` + "`json:\"debug\"`" + `
}

type Strategy struct{ ID string }

func strategies(w http.ResponseWriter, r *http.Request, svc any) {
	type DebugInfo struct {
		ConfigType string ` + "`json:\"configType\"`" + `
	}
	type StrategiesResponse struct {
		Strategies []Strategy ` + "`json:\"strategies\"`" + `
		Debug      DebugInfo  ` + "`json:\"debug\"`" + `
	}
	_ = StrategiesResponse{Debug: DebugInfo{ConfigType: fmt.Sprintf("%T", svc)}}
}
`
	assert.Equal(t, []int{10, 26}, ruleLines(t, NewDebugFieldInResponseRule(), code))
}

// script-src with 'unsafe-inline' or 'unsafe-eval' in a production policy;
// a development policy and style-src are left alone.
func TestCSPUnsafeScript(t *testing.T) {
	code := `package middleware

type CSPDirectives struct {
	DefaultSrc, ScriptSrc, StyleSrc []string
}

func GetProductionCSP() *CSPDirectives {
	return &CSPDirectives{
		DefaultSrc: []string{"'self'"},
		ScriptSrc: []string{
			"'self'",
			"'unsafe-inline'",
			"https://www.example-analytics.com",
		},
		StyleSrc: []string{"'self'", "'unsafe-inline'"},
	}
}

func GetDevelopmentCSP() *CSPDirectives {
	return &CSPDirectives{ScriptSrc: []string{"'self'", "'unsafe-eval'"}}
}

const staticPolicy = "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'unsafe-inline'"

const strictPolicy = "default-src 'self'; script-src 'self' 'strict-dynamic'; style-src 'self' 'unsafe-inline'"
`
	assert.Equal(t, []int{12, 23}, ruleLines(t, NewCSPUnsafeScriptRule(), code))

	conf := `server {
    # add_header Content-Security-Policy "script-src 'unsafe-inline'";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.net" always;
    add_header Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline'" always;
}
`
	assert.Equal(t, []int{3}, textRuleLines(t, NewCSPUnsafeScriptRule(), "nginx/site.conf", conf))
}

// One accepted format is the check; every further accepting comparison is a
// format a sender can choose instead.
func TestSignatureAcceptsAlternateFormats(t *testing.T) {
	code := `package webhook

import (
	"crypto/hmac"
	"crypto/subtle"
	"errors"
)

func mac(data []byte) []byte { return data }

func verifyAny(body, got []byte, ts string) error {
	if sig := mac(body); hmac.Equal(sig, got) {
		return nil
	}
	if sig := mac(append([]byte(ts), body...)); hmac.Equal(sig, got) {
		return nil
	}
	if subtle.ConstantTimeCompare(mac([]byte(ts)), got) == 1 {
		return nil
	}
	return errors.New("signature mismatch")
}

func verifyOne(body, got []byte) error {
	if sig := mac(body); hmac.Equal(sig, got) {
		return nil
	}
	return errors.New("signature mismatch")
}

func rotateKeys(body, got, oldKey, newKey []byte) bool {
	if !hmac.Equal(mac(append(newKey, body...)), got) {
		return false
	}
	return true
}
`
	assert.Equal(t, []int{15, 18}, ruleLines(t, NewSignatureAlternateFormatsRule(), code))
}

// Verification turned off in Go and in a Node test configuration; a config
// that keeps it on is fine.
func TestTLSVerificationDisabled(t *testing.T) {
	code := `package client

import (
	"crypto/tls"
	"net/http"
)

func insecure() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func secure() *tls.Config {
	return &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12}
}
`
	assert.Equal(t, []int{9}, ruleLines(t, NewTLSVerificationDisabledRule(), code))

	script := `import { defineConfig } from '@playwright/test'

process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'
// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
const agent = new https.Agent({ rejectUnauthorized: false })
const strict = new https.Agent({ rejectUnauthorized: true })
export default defineConfig({ use: { baseURL: process.env.BASE_URL } })
`
	assert.Equal(t, []int{3, 5}, textRuleLines(t, NewTLSVerificationDisabledRule(), "e2e/playwright.deploy-test.config.ts", script))
}

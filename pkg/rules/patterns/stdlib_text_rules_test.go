package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A path into one developer's home works on that machine only: the service
// started elsewhere reads no .env, and the helper script is not found.
func TestHardcodedHomePath(t *testing.T) {
	goFile := rulestest.GoFile(t, "cmd/server/env.go", `package main

import "os/exec"

var envPaths = []string{
	".env",
	"../.env",
	"/home/dev/work/shop/.env",
}

func run() error {
	cmd := exec.Command("node", "/home/dev/work/shop-agents/w1/scripts/send.js")
	cmd.Dir = "/Users/dev/work/shop"
	_ = `+"`C:\\Users\\dev\\shop\\.env`"+`
	_ = "/home/"
	_ = "/etc/shop/.env"
	_ = "/homework/notes"
	_ = "~/work/shop/.env"
	return cmd.Run()
}
`)
	rule := NewHardcodedHomePathRule()
	assert.Equal(t, []string{"cmd/server/env.go:12", "cmd/server/env.go:13", "cmd/server/env.go:14", "cmd/server/env.go:8"},
		foundLines(rule.AnalyzeFile(goFile)))

	tsFile := rulestest.TextFile(t, "e2e/utils/admin-token.ts", `// generated once on /home/dev/work/shop
export const command = 'cd /home/dev/work/shop/backend && go run ./cmd/token'
export const local = './backend'
`)
	assert.Equal(t, []string{"e2e/utils/admin-token.ts:2"}, foundLines(rule.AnalyzeFile(tsFile)))

	testFile := rulestest.GoFile(t, "cmd/server/env_test.go", `package main

var fixture = "/home/dev/work/shop/.env"
`)
	assert.Empty(t, rule.AnalyzeFile(testFile), "a test fixture path is data")
}

// A client sending "application/json; charset=utf-8" is not JSON to an exact
// comparison: the body is skipped and the request proceeds without it.
func TestContentTypeExactCompare(t *testing.T) {
	file := rulestest.GoFile(t, "api/handler.go", `package api

import (
	"net/http"
	"strings"
)

func handle(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Content-Type") == "application/json" {
	}
	if req.Header.Get("content-type") != "application/json" {
	}
	switch req.Header.Get("Content-Type") {
	case "text/plain":
	}
	ct := req.Header.Get("Content-Type")
	if ct == "application/json" {
	}
	if strings.HasPrefix(req.Header.Get("Content-Type"), "application/json") {
	}
	if req.Header.Get("Content-Type") == "" {
	}
	if req.Header.Get("Accept") == "application/json" {
	}
}
`)
	assert.Equal(t, []string{"api/handler.go:11", "api/handler.go:14", "api/handler.go:17", "api/handler.go:9"},
		foundLines(NewContentTypeExactCompareRule().AnalyzeFile(file)))
}

// %w means something only to fmt.Errorf: a log line or a Sprintf gets
// "%!w(...)" instead of the error text.
func TestPrintfWrapVerbOutsideErrorf(t *testing.T) {
	file := rulestest.GoFile(t, "service/deposit.go", `package service

import (
	"fmt"
	"log"
)

func process(err error, logger *log.Logger) string {
	logger.Printf("validation failed: %w", err)
	msg := fmt.Sprintf("database error: %w", err)
	_ = fmt.Errorf("begin tx: %w", err)
	_ = wrapf("begin tx: %w", err)
	_ = fmt.Sprintf("100%%w")
	_ = fmt.Sprintf("done: %%w %d", 1)
	logger.Println("literal %w text", err)
	return msg
}

func wrapf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
`)
	rule := NewPrintfWrapVerbRule()
	rule.UseProjectFiles([]*core.FileContext{file})
	assert.Equal(t, []string{"service/deposit.go:10", "service/deposit.go:9"}, foundLines(rule.AnalyzeFile(file)))
}

// Slicing a string by a byte count cuts a multi-byte character in half: the
// varchar column receives invalid UTF-8 and the insert fails.
func TestStringTruncationSplitsRune(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"store/text.go": `package store

import (
	"strings"
	"unicode/utf8"
)

type Record struct{ Description string }

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func clip(r *Record, limit int) {
	if len(r.Description) > limit {
		r.Description = r.Description[:limit] + "..."
	}
}

func clipBytes(b []byte, maxLen int) []byte {
	if len(b) > maxLen {
		return b[:maxLen]
	}
	return b
}

func prefix(s string) string {
	if i := strings.Index(s, ":"); i >= 0 {
		return s[:i]
	}
	return s
}

func runeSafe(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	for maxLen > 0 && !utf8.RuneStart(s[maxLen]) {
		maxLen--
	}
	return s[:maxLen]
}

func unrelated(s string, n int) string {
	return s[:n]
}

func preview(body string) string {
	if len(body) > 200 {
		body = body[:200]
	}
	return body
}

func title(t string) string {
	if len(t) > 12 {
		return t[:12] + "..."
	}
	return t
}

func hasPrefixFold(header, prefix string) bool {
	return len(header) >= len(prefix) && strings.EqualFold(header[:len(prefix)], prefix)
}

func isNew(name string) bool {
	return len(name) > 3 && name[:3] == "New"
}

func day(stamp string) string {
	if len(stamp) >= 10 {
		return stamp[:10]
	}
	return stamp
}

func shortID(requestID string, maxLen int) string {
	if len(requestID) > maxLen {
		return requestID[:maxLen]
	}
	return requestID
}

func before(line string, col int) string {
	if col <= len(line) {
		return line[:col]
	}
	return line
}
`,
	}
	violations, err := NewStringTruncationSplitsRuneRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"store/text.go:14", "store/text.go:19", "store/text.go:53", "store/text.go:60"}, foundLines(violations))
}

// A project that already parses .env with a library keeps a second, weaker
// parser by hand: it misses quotes, export and inline comments.
func TestHandRolledDotenvParser(t *testing.T) {
	loader := rulestest.GoFile(t, "config/bootstrap.go", `package config

import "github.com/joho/godotenv"

func Bootstrap(path string) error { return godotenv.Load(path) }
`)
	parser := rulestest.GoFile(t, "config/loader.go", `package config

import "strings"

func parseEnvFile(data []byte) map[string]string {
	envVars := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if eq := strings.Index(line, "="); eq > 0 {
			envVars[strings.TrimSpace(line[:eq])] = strings.TrimSpace(line[eq+1:])
		}
	}
	return envVars
}

func parseHeaders(data string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[k] = v
		}
	}
	return out
}
`)
	rule := NewHandRolledDotenvParserRule()
	rule.UseProjectFiles([]*core.FileContext{loader, parser})
	assert.Equal(t, []string{"config/loader.go:5"}, foundLines(rule.AnalyzeFile(parser)))

	rule.ResetState()
	rule.UseProjectFiles([]*core.FileContext{parser})
	assert.Empty(t, rule.AnalyzeFile(parser), "without a dotenv library there is nothing to use instead")
}

package duplication

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// Two packages keep their own copy of one small helper: the bodies differ in
// details, so cross-file-duplicate does not see them, and a fix of one (the
// second copy does not wrap a cause twice) never reaches the other.
func TestDuplicateFuncAcrossPackages(t *testing.T) {
	files := map[string]string{
		"poller/poller.go": `package poller

import (
	"context"
	"fmt"
)

func withContextCause(ctx context.Context, err error) error {
	if err == nil || ctx.Err() == nil {
		return err
	}
	return fmt.Errorf("%w: %w", ctx.Err(), err)
}
`,
		"sender/sender.go": `package sender

import (
	"context"
	"errors"
	"fmt"
)

func withContextCause(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	return err
}
`,
	}
	assert.Equal(t, []string{"sender/sender.go:9"}, rulestest.ProjectRulePlaces(t, NewDuplicateFuncAcrossPackagesRule(), files))
}

// One name with another signature, a one-word name every package has its own
// of (run, handle), a constructor of the package's own type, a thin wrapper
// over a shared helper, an exported function, a method, a function without
// parameters, a test file, a mock package and a stand-in package for tests
// (settingstest next to the real api) are not copies.
func TestDuplicateFuncAcrossPackagesAllowed(t *testing.T) {
	files := map[string]string{
		"shared/errs/errs.go": `package errs

import "context"

func WithCause(ctx context.Context, err error) error { return err }
`,
		"a/a.go": `package a

import (
	"context"

	"example.com/rulestest/shared/errs"
)

type store struct{}

func newStore(dsn string) *store { return &store{} }

func parseAmount(s string) (int, error) { return len(s), nil }

func run(ctx context.Context) error { return nil }

func wrapCause(ctx context.Context, err error) error {
	return errs.WithCause(ctx, err)
}

func FormatAmount(n int) string { return "" }

func (s *store) loadRows(limit int) error { return nil }

func defaultLimit() int { return 10 }
`,
		"a/a_test.go": `package a

func mustParse(s string) int { return 0 }
`,
		"b/b.go": `package b

import (
	"context"

	"example.com/rulestest/shared/errs"
)

type store struct{}

func newStore(dsn string) *store { return &store{} }

func parseAmount(s string) (int64, error) { return int64(len(s)), nil }

func run(ctx context.Context) error { return ctx.Err() }

func wrapCause(ctx context.Context, err error) error {
	return errs.WithCause(ctx, err)
}

func FormatAmount(n int) string { return "n" }

func (s *store) loadRows(limit int) error { return nil }

func defaultLimit() int { return 20 }
`,
		"b/b_test.go": `package b

func mustParse(s string) int { return 1 }
`,
		"a/mocks/mocks.go": `package mocks

func parseAmount(s string) (int, error) { return 0, nil }
`,
		"api/server.go": `package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write json", "error", err)
	}
}
`,
		"settings/settingstest/server.go": `// Package settingstest is an in-memory stand-in for the settings API.
package settingstest

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}
`,
	}
	assert.Empty(t, rulestest.ProjectRulePlaces(t, NewDuplicateFuncAcrossPackagesRule(), files))
}

func TestDuplicateFuncAcrossPackagesRenamedBody(t *testing.T) {
	files := map[string]string{
		"httpx/request.go": `package httpx

import "net/http"

func IsStreamRequest(request *http.Request) bool {
	return request.Method == "GET" && (request.Header.Get("Accept") == "text/event-stream" || request.Header.Get("Accept") == "application/stream")
}
`,
		"middleware/stream.go": `package middleware

import "net/http"

func isStreamingRequest(r *http.Request) bool {
	return r.Method == "GET" && (r.Header.Get("Accept") == "text/event-stream" || r.Header.Get("Accept") == "application/stream")
}
`,
	}
	assert.Equal(t, []string{"middleware/stream.go:5"}, rulestest.ProjectRulePlaces(t, NewDuplicateFuncAcrossPackagesRule(), files))
}

func TestDuplicateFuncAcrossPackagesRenamedBodyIgnoresTrivialAndDifferentBodies(t *testing.T) {
	files := map[string]string{
		"alpha/helpers.go": `package alpha

type request struct { Header map[string]string }

func getField(x request) string { return x.Header["Accept"] }
func callField(fn func(string) string, x string) string { return fn(x) }
func repeated(x int) int { if x > 0 { x++; return x }; return 0 }
func SameBody(value int) int { if value > 0 { value++; return value }; return 0 }
func LiteralBody(value int) int { if value > 0 { value++; return value }; return 0 }
func CallBody(value int) int { if value > 0 { value = transform(value); return value }; return 0 }
func transform(value int) int { return value }
`,
		"beta/helpers.go": `package beta

type request struct { Header map[string]string }

func readField(x request) string { return x.Header["Accept"] }
func invokeField(fn func(string) string, value string) string { return fn(value) }
func repeated(value int) int { if value > 0 { value++; return value }; return 0 }
func OtherBody(value int) int { if value > 0 { value++; return value }; return 1 }
func OtherLiteral(value int) int { if value > 0 { value++; return value }; return 0 }
func OtherCall(value int) int { if value > 0 { value = convert(value); return value }; return 0 }
func convert(value int) int { return value }
`,
		"alpha/helpers_test.go": `package alpha
func testCopy(value int) int { if value > 0 { value++; return value }; return 0 }
`,
		"beta/helpers_test.go": `package beta
func testCopy(value int) int { if value > 0 { value++; return value }; return 0 }
`,
	}
	assert.Empty(t, rulestest.ProjectRulePlaces(t, NewDuplicateFuncAcrossPackagesRule(), files))
}

func TestDuplicateFuncAcrossPackagesPrefersImportablePackageToMain(t *testing.T) {
	files := map[string]string{
		"cmd/tool/main.go":      streamFunction("main", "IsStreamRequest", "request"),
		"library/httpx/http.go": streamFunction("httpx", "IsStreamingRequest", "req"),
	}
	violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	assert.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "example.com/rulestest/library/httpx.IsStreamingRequest")
	assert.Contains(t, violations[0].Suggestion, "call it from both")
}

func TestDuplicateFuncAcrossPackagesInternalWithoutSharedImportAdvice(t *testing.T) {
	files := map[string]string{
		"a/internal/shared/stream.go": streamFunction("shared", "IsStreamRequest", "request"),
		"zoutside/main.go":            streamFunction("main", "IsStreamingRequest", "req"),
	}
	violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	assert.Len(t, violations, 1)
	assert.Equal(t, "zoutside/main.go", violations[0].File)
	assert.Contains(t, violations[0].Message, "example.com/rulestest/a/internal/shared.IsStreamRequest")
	assert.Contains(t, violations[0].Message, "move one implementation into a package both can import")
	assert.Contains(t, violations[0].Suggestion, "Move the shared implementation into a package both packages can import")
}

func TestDuplicateFuncAcrossPackagesMainPackagesNeedMoveAdvice(t *testing.T) {
	files := map[string]string{
		"cmd/alpha/main.go": streamFunction("main", "IsStreamRequest", "request"),
		"cmd/beta/main.go":  streamFunction("main", "IsStreamingRequest", "req"),
	}
	violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	assert.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "move one implementation into a package both can import")
	assert.Contains(t, violations[0].Suggestion, "Move the shared implementation into a package both packages can import")
}

func streamFunction(pkg, name, param string) string {
	return fmt.Sprintf(`package %s

import "net/http"

func %s(%s *http.Request) bool {
	return %s.Method == "GET" && (%s.Header.Get("Accept") == "text/event-stream" || %s.Header.Get("Accept") == "application/stream")
}
`, pkg, name, param, param, param, param)
}

// A copy in another Go module of the repository cannot call the original
// without a new module dependency: no finding.
func TestDuplicateFuncAcrossPackagesSkipsAnotherModule(t *testing.T) {
	files := map[string]string{
		"httpx/stream.go":       streamFunction("httpx", "IsStreamRequest", "request"),
		"tools/monitor/go.mod":  "module example.com/monitor\n\ngo 1.22\n",
		"tools/monitor/main.go": streamFunction("main", "isStreamRequest", "req"),
	}
	assert.Empty(t, rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files))

	files["tools/monitor/main.go"] = streamFunction("main", "isStreamRequest", "req")
	files["httpx/stream.go"] = streamFunction("httpx", "isStreamRequest", "req")
	assert.Empty(t, rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files), "same name in another module")
}

// An unexported original has to be exported before the copy can call it.
func TestDuplicateFuncAcrossPackagesUnexportedOriginalAdvisesExport(t *testing.T) {
	files := map[string]string{
		"alpha/stream.go": streamFunction("alpha", "isStreamRequest", "request"),
		"beta/stream.go":  streamFunction("beta", "streaming", "req"),
	}
	violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "export it")
}

// Same-name helpers in two main packages have no package both can import:
// the advice moves the implementation instead of calling across.
func TestDuplicateFuncAcrossPackagesSameNameInMainPackagesAdvisesMove(t *testing.T) {
	label := func() string {
		return `package main

import "strings"

func formatLabel(name string) string { return strings.ToUpper(strings.TrimSpace(name)) + ":" }

func main() { _ = formatLabel("x") }
`
	}
	files := map[string]string{"cmd/a/main.go": label(), "cmd/b/main.go": label()}
	violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	require.Len(t, violations, 2)
	for _, v := range violations {
		assert.Contains(t, v.Message, "move one implementation into a package both can import")
	}
}

// Same-name unexported helpers can be called across only once exported.
func TestDuplicateFuncAcrossPackagesSameNameHelperAdvisesExport(t *testing.T) {
	files := map[string]string{
		"alpha/label.go": "package alpha\n\nimport \"strings\"\n\nfunc formatLabel(name string) string { return strings.ToUpper(name) + \":\" }\n",
		"beta/label.go":  "package beta\n\nimport \"strings\"\n\nfunc formatLabel(name string) string { return strings.ToUpper(name) + \":\" }\n",
	}
	violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].File, "beta/label.go")
	assert.Contains(t, violations[0].Message, "duplicates example.com/rulestest/alpha — keep one implementation, export it")
}

// Two main packages cannot call each other's copy; the library copy is the
// one both can import, so it is the twin named in the advice and is not
// reported itself.
func TestDuplicateFuncAcrossPackagesSameNameTwinIsPackageAllCanImport(t *testing.T) {
	mainLabel := "package main\n\nimport \"strings\"\n\nfunc formatLabel(s string) string { return strings.TrimSpace(s) + \"%s\" }\n\nfunc main() { _ = formatLabel(\"x\") }\n"
	files := map[string]string{
		"cmd/one/main.go": fmt.Sprintf(mainLabel, "1"),
		"cmd/two/main.go": fmt.Sprintf(mainLabel, "2"),
		"text/label.go":   "package text\n\nimport \"strings\"\n\nfunc formatLabel(s string) string { return strings.TrimSpace(s) + \"3\" }\n\nfunc Use(s string) string { return formatLabel(s) }\n",
	}
	violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	require.Len(t, violations, 2)
	for _, v := range violations {
		assert.Contains(t, v.File, "cmd/")
		assert.Contains(t, v.Message, "duplicates example.com/rulestest/text — keep one implementation, export it")
	}
}

// One call of a shared helper is no wrapper when the logic sits in the function
// literal it is given: the copies are the literal, with or without explicit
// type arguments on the call.
func TestDuplicateFuncAcrossPackagesLogicInFunctionLiteralArgument(t *testing.T) {
	lib := `package lib

// Map applies f to every value.
func Map[T, U any](xs []T, f func(T) U) []U {
	out := make([]U, 0, len(xs))
	for _, x := range xs {
		out = append(out, f(x))
	}
	return out
}
`
	copyOf := func(pkg, call string) string {
		return `package ` + pkg + `

import (
	"strconv"
	"strings"

	"example.com/rulestest/lib"
)

func labels(xs []int) []string {
	return ` + call + `(xs, func(x int) string {
		if x < 0 {
			return "neg-" + strconv.Itoa(-x)
		}
		s := strings.Repeat("*", x%5)
		return strconv.Itoa(x) + s
	})
}
`
	}
	for _, call := range []string{"lib.Map[int, string]", "lib.Map"} {
		files := map[string]string{"lib/lib.go": lib, "alpha/alpha.go": copyOf("alpha", call), "beta/beta.go": copyOf("beta", call)}
		assert.Len(t, rulestest.ProjectRulePlaces(t, NewDuplicateFuncAcrossPackagesRule(), files), 1, call)
	}
}

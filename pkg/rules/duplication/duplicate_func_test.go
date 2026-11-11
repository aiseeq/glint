package duplication

import (
	"bytes"
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/aiseeq/glint/pkg/toolcache"
	"golang.org/x/mod/module"
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
	require.Len(t, violations, 2, "with no package to keep it, each copy is to move")
	byFile := map[string]*core.Violation{violations[0].File: violations[0], violations[1].File: violations[1]}
	require.Contains(t, byFile, "zoutside/main.go")
	require.Contains(t, byFile, "a/internal/shared/stream.go")
	assert.Contains(t, byFile["zoutside/main.go"].Message, "example.com/rulestest/a/internal/shared.IsStreamRequest")
	assert.Contains(t, byFile["a/internal/shared/stream.go"].Message, "example.com/rulestest/zoutside.IsStreamingRequest")
	for _, v := range violations {
		assert.Contains(t, v.Message, "move one implementation into a package both can import")
		assert.Contains(t, v.Suggestion, "Move the shared implementation into a package both packages can import")
	}
}

func TestDuplicateFuncAcrossPackagesMainPackagesNeedMoveAdvice(t *testing.T) {
	files := map[string]string{
		"cmd/alpha/main.go": streamFunction("main", "IsStreamRequest", "request"),
		"cmd/beta/main.go":  streamFunction("main", "IsStreamingRequest", "req"),
	}
	violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	require.Len(t, violations, 2, "with no package to keep it, each copy is to move")
	for _, v := range violations {
		assert.Contains(t, v.Message, "move one implementation into a package both can import")
		assert.Contains(t, v.Suggestion, "Move the shared implementation into a package both packages can import")
	}
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

// A package that imports the other copy's package cannot be the one it calls:
// the import back closes a cycle. The copy in the importing package is the
// one to drop and call the imported package instead, directly or through a
// package between them.
func TestDuplicateFuncAcrossPackagesAdviceAvoidsImportCycle(t *testing.T) {
	helper := "package %s\n\nimport \"strings\"\n\nfunc formatLabel(name string) string { return strings.ToUpper(name) + \":\" }\n"
	for name, files := range map[string]map[string]string{
		"direct": {
			"alpha/label.go": fmt.Sprintf(helper, "alpha"),
			"alpha/use.go":   "package alpha\n\nimport \"example.com/rulestest/beta\"\n\nvar _ = beta.Name\n",
			"beta/label.go":  fmt.Sprintf(helper, "beta") + "\nconst Name = \"beta\"\n",
		},
		"through a package": {
			"alpha/label.go": fmt.Sprintf(helper, "alpha"),
			"alpha/use.go":   "package alpha\n\nimport \"example.com/rulestest/mid\"\n\nvar _ = mid.Name\n",
			"mid/mid.go":     "package mid\n\nimport \"example.com/rulestest/beta\"\n\nconst Name = beta.Name\n",
			"beta/label.go":  fmt.Sprintf(helper, "beta") + "\nconst Name = \"beta\"\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
			require.Len(t, violations, 1)
			assert.Equal(t, "alpha/label.go", violations[0].File)
			assert.Contains(t, violations[0].Message, "duplicates example.com/rulestest/beta — keep one implementation, export it")
		})
	}
}

// The same holds for copies matched by body under different names.
func TestDuplicateFuncAcrossPackagesRenamedBodyAvoidsImportCycle(t *testing.T) {
	files := map[string]string{
		"alpha/stream.go": streamFunction("alpha", "IsStreamRequest", "request"),
		"alpha/use.go":    "package alpha\n\nimport \"example.com/rulestest/beta\"\n\nvar _ = beta.IsStreamingRequest\n",
		"beta/stream.go":  streamFunction("beta", "IsStreamingRequest", "req"),
	}
	violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	require.Len(t, violations, 1)
	assert.Equal(t, "alpha/stream.go", violations[0].File)
	assert.Contains(t, violations[0].Message, "example.com/rulestest/beta.IsStreamingRequest")
	assert.Contains(t, violations[0].Suggestion, "call it from both")
}

// go test and go vet build a package with its in-package tests: a test of
// alpha importing beta makes beta importing alpha a cycle there, while an
// external test package (alpha_test) adds no edge to alpha.
func TestDuplicateFuncAcrossPackagesAdviceCountsInPackageTestImports(t *testing.T) {
	helper := "package %s\n\nimport \"strings\"\n\nfunc formatLabel(name string) string { return strings.ToUpper(name) + \":\" }\n"
	files := map[string]string{
		"alpha/label.go":      fmt.Sprintf(helper, "alpha"),
		"alpha/label_test.go": "package alpha\n\nimport (\n\t\"testing\"\n\n\t\"example.com/rulestest/beta\"\n)\n\nfunc TestName(t *testing.T) { _ = beta.Name }\n",
		"beta/label.go":       fmt.Sprintf(helper, "beta") + "\nconst Name = \"beta\"\n",
	}
	violations := rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	require.Len(t, violations, 1)
	assert.Equal(t, "alpha/label.go", violations[0].File)
	assert.Contains(t, violations[0].Message, "duplicates example.com/rulestest/beta")

	files["alpha/label_test.go"] = "package alpha_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/rulestest/beta\"\n)\n\nfunc TestName(t *testing.T) { _ = beta.Name }\n"
	violations = rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	require.Len(t, violations, 1)
	assert.Equal(t, "beta/label.go", violations[0].File, "an external test package closes no cycle")
	assert.Contains(t, violations[0].Message, "duplicates example.com/rulestest/alpha")

	files["alpha/label_test.go"] = "package alpha\n\nimport (\n\t\"testing\"\n\n\t\"example.com/rulestest/testutil\"\n)\n\nfunc TestName(t *testing.T) { _ = testutil.Name }\n"
	files["testutil/util.go"] = "package testutil\n\nimport \"example.com/rulestest/beta\"\n\nconst Name = beta.Name\n"
	violations = rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	require.Len(t, violations, 1)
	assert.Equal(t, "alpha/label.go", violations[0].File, "the test of alpha reaches beta through testutil")
	assert.Contains(t, violations[0].Message, "duplicates example.com/rulestest/beta")
	delete(files, "testutil/util.go")

	delete(files, "alpha/label_test.go")
	files["alpha/label.go"] = "package alpha\n\nimport (\n\t\"strings\"\n\n\t\"example.com/rulestest/mid\"\n)\n\nvar _ = mid.Name\n\nfunc formatLabel(name string) string { return strings.ToUpper(name) + \":\" }\n"
	files["mid/mid.go"] = "package mid\n\nconst Name = \"mid\"\n"
	files["mid/mid_test.go"] = "package mid\n\nimport (\n\t\"testing\"\n\n\t\"example.com/rulestest/beta\"\n)\n\nfunc TestName(t *testing.T) { _ = beta.Name }\n"
	violations = rulestest.RunRuleOnFiles(t, NewDuplicateFuncAcrossPackagesRule(), files)
	require.Len(t, violations, 1)
	assert.Equal(t, "alpha/label.go", violations[0].File, "beta importing alpha closes a cycle in the test of mid")
	assert.Contains(t, violations[0].Message, "duplicates example.com/rulestest/beta")
}

func TestDuplicateFuncAcrossPackagesUnreadTestsKeepNoImplementation(t *testing.T) {
	alpha := types.NewPackage("example.com/x/alpha", "alpha")
	beta := types.NewPackage("example.com/x/beta", "beta")
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	copies := []*types.Func{types.NewFunc(token.NoPos, alpha, "f", sig), types.NewFunc(token.NoPos, beta, "f", sig)}
	newGraph := func(err error) *importGraph {
		graph := newImportGraph(&core.GoProjectContext{})
		graph.tests[alpha.Path()] = testImportList{err: err}
		return graph
	}
	assert.True(t, newGraph(nil).importedByAll(alpha, copies))
	assert.False(t, newGraph(errors.New("unreadable")).importedByAll(alpha, copies), "tests that cannot be read may import beta")
}

func TestDuplicateFuncOfLibraryLocalReplace(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	lib := filepath.Join(root, "lib")
	consumer := filepath.Join(root, "consumer")
	require.NoError(t, os.MkdirAll(lib, 0o755))
	require.NoError(t, os.MkdirAll(consumer, 0o755))
	const body = `package lib

func NormalizeAmount(value int) int {
	if value < 0 {
		value = -value
	}
	value = value * 100
	if value > 100000 {
		value = 100000
	}
	return value
}
`
	require.NoError(t, os.WriteFile(filepath.Join(lib, "go.mod"), []byte("module example.com/owner/lib\n\ngo 1.24\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(lib, "amount.go"), []byte(body), 0o644))
	consumerMod := "module example.com/app\n\ngo 1.24\n\nrequire example.com/owner/lib v0.0.0\nreplace example.com/owner/lib => ../lib\n"
	consumerBody := strings.Replace(body, "package lib", "package app", 1)
	consumerBody = strings.Replace(consumerBody, "NormalizeAmount", "tidyAmount", 1)
	require.NoError(t, os.WriteFile(filepath.Join(consumer, "go.mod"), []byte(consumerMod), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(consumer, "amount.go"), []byte(consumerBody), 0o644))
	fileCtx, err := core.NewFileContextChecked(filepath.Join(consumer, "amount.go"), consumer, []byte(consumerBody), core.DefaultConfig())
	require.NoError(t, err)
	ctx, err := core.LoadGoProject(consumer, []*core.FileContext{fileCtx}, core.GoProjectOptions{})
	require.NoError(t, err)
	rule := NewDuplicateFuncOfLibraryRule()
	before := libraryPackageLoads.Load()
	violations, err := rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "duplicates function NormalizeAmount")
	assert.Contains(t, violations[0].Message, "example.com/owner/lib")
	assert.Contains(t, violations[0].Message, "lib.NormalizeAmount")
	firstLoads := libraryPackageLoads.Load()
	assert.Greater(t, firstLoads, before)
	violations, err = rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, firstLoads, libraryPackageLoads.Load(), "second run should use cached keys")

	updated := strings.Replace(body, "100000", "90000", 1)
	require.NoError(t, os.WriteFile(filepath.Join(lib, "amount.go"), []byte(updated), 0o644))
	updatedConsumer := strings.Replace(consumerBody, "100000", "90000", 1)
	require.NoError(t, os.WriteFile(filepath.Join(consumer, "amount.go"), []byte(updatedConsumer), 0o644))
	fileCtx, err = core.NewFileContextChecked(filepath.Join(consumer, "amount.go"), consumer, []byte(updatedConsumer), core.DefaultConfig())
	require.NoError(t, err)
	ctx, err = core.LoadGoProject(consumer, []*core.FileContext{fileCtx}, core.GoProjectOptions{})
	require.NoError(t, err)
	violations, err = rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Greater(t, libraryPackageLoads.Load(), firstLoads, "changed library tree should miss the cache")
}

func TestDuplicateFuncOfLibraryDoesNotNormalizeLiteralsOrCalleesAway(t *testing.T) {
	for name, consumer := range map[string]string{
		"literal": `package app
func tidyAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 90000 { value = 90000 }
	return value
}
`,
		"callee": `package app
func scaleValue(value int) int { return value * 100 }
func tidyAmount(value int) int {
	if value < 0 { value = -value }
	value = scaleValue(value)
	if value > 100000 { value = 100000 }
	return value
}
`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", consumer,
				map[string]string{"amount.go": `package lib
func NormalizeAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`}, true, "")
			violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
			require.NoError(t, err)
			assert.Empty(t, violations)
		})
	}
}

func TestDuplicateFuncOfLibraryExcludesUnexportedAndInternalPackages(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", `package app
func tidyAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
func tidyInternal(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`, map[string]string{
		"amount.go": `package lib
func normalizeAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`,
		"internal/hidden/amount.go": `package hidden
func NormalizeAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`,
	}, true, "")
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestDuplicateFuncOfLibraryAllowsConfiguredForeignModule(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	consumer := `package app
func tidyAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`
	ctx := duplicateLibraryTestProject(t, "github.com/other/lib", "github.com/client/app", consumer,
		map[string]string{"amount.go": `package lib
func NormalizeAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`}, true, "")
	rule := NewDuplicateFuncOfLibraryRule()
	violations, err := rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	assert.Empty(t, violations)
	require.NoError(t, rule.Configure(map[string]any{"library_modules": []any{"github.com/other/lib"}}))
	violations, err = rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
}

func TestDuplicateFuncOfLibraryUsesModuleCacheAndSkipsMissingSource(t *testing.T) {
	for _, present := range []bool{true, false} {
		t.Run(map[bool]string{true: "module cache", false: "missing"}[present], func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			cacheRoot := t.TempDir()
			t.Setenv("GOMODCACHE", cacheRoot)
			libFiles := map[string]string{"amount.go": `package lib
func NormalizeAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`}
			if present {
				writeLibraryTestModule(t, filepath.Join(cacheRoot, "example.com/owner/lib@v1.0.0"), "example.com/owner/lib", libFiles)
			}
			consumer := `package app
func tidyAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`
			ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", consumer, nil, false, "")
			violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
			require.NoError(t, err)
			if present {
				require.Len(t, violations, 1)
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}

func TestDuplicateFuncOfLibrarySkipsMainPackages(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", libraryAmountCopy,
		map[string]string{"cmd/tool/main.go": `package main
func NormalizeAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
func main() {}
`}, true, "")
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestDuplicateFuncOfLibraryWithoutDependenciesDoesNotHashExecutable(t *testing.T) {
	ctx := rulestest.Project(t, map[string]string{"amount.go": libraryAmountCopy})
	previous := duplicateLibraryBuildHash
	t.Cleanup(func() { duplicateLibraryBuildHash = previous })
	calls := 0
	duplicateLibraryBuildHash = func() (string, error) {
		calls++
		return "synthetic-binary-hash", nil
	}
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	assert.Empty(t, violations)
	assert.Zero(t, calls)
}

// A library dependency whose source is in no replace and no module cache
// gives nothing to compare, so the executable is not hashed for it.
func TestDuplicateFuncOfLibraryDependencyWithoutSourceDoesNotHashExecutable(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOPROXY", "off")
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", libraryAmountCopy, nil, false, "")
	previous := duplicateLibraryBuildHash
	t.Cleanup(func() { duplicateLibraryBuildHash = previous })
	calls := 0
	duplicateLibraryBuildHash = func() (string, error) {
		calls++
		return "synthetic-binary-hash", nil
	}
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	assert.Empty(t, violations)
	assert.Zero(t, calls)
}

func TestDuplicateFuncOfLibraryAnalyzeUsesExecutableHashInCacheKey(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", libraryAmountCopy,
		map[string]string{"amount.go": libraryAmountSource}, true, "")
	previous := duplicateLibraryBuildHash
	t.Cleanup(func() { duplicateLibraryBuildHash = previous })
	buildHash := "synthetic-binary-one"
	duplicateLibraryBuildHash = func() (string, error) { return buildHash, nil }
	loadedBefore := libraryPackageLoads.Load()
	rule := NewDuplicateFuncOfLibraryRule()
	violations, err := rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	firstLoads := libraryPackageLoads.Load()
	assert.Greater(t, firstLoads, loadedBefore)
	buildHash = "synthetic-binary-two"
	violations, err = rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Greater(t, libraryPackageLoads.Load(), firstLoads, "changed executable hash must miss the cache through AnalyzeGoProject")
}

func TestDuplicateFuncOfLibraryCacheKeyIncludesExecutableHash(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dep := libraryDependency{path: "example.com/owner/lib", version: "v1.0.0"}
	cache := toolcache.New("library-build-hash-test")
	firstKey := libraryCacheKey(dep, "tree-hash", "binary-one")
	require.NoError(t, cache.Store(firstKey, libraryCacheEntry{Keys: map[string][]libraryFunction{"body": {{Name: "Normalize"}}}}))
	var entry libraryCacheEntry
	hit, err := cache.Load(firstKey, &entry)
	require.NoError(t, err)
	require.True(t, hit)
	secondKey := libraryCacheKey(dep, "tree-hash", "binary-two")
	hit, err = cache.Load(secondKey, &entry)
	require.NoError(t, err)
	assert.False(t, hit, "a different executable hash must use a different cache entry")
}

func TestDependencySourceEscapesModuleCacheVersion(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("GOMODCACHE", cacheRoot)
	dep := libraryDependency{path: "example.com/Owner/lib", version: "v1.2.3+Meta"}
	escapedPath, err := module.EscapePath(dep.path)
	require.NoError(t, err)
	escapedVersion, err := module.EscapeVersion(dep.version)
	require.NoError(t, err)
	dir := filepath.Join(cacheRoot, escapedPath+"@"+escapedVersion)
	writeLibraryTestModule(t, dir, dep.path, map[string]string{"lib.go": "package lib\n"})
	found, digest, ok, err := dependencySource(t.TempDir(), dep)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, dir, found)
	assert.Equal(t, dep.version, digest)
}

func TestLibraryDependenciesSkipAlternateMajorVersion(t *testing.T) {
	for _, pair := range []struct{ project, dependency string }{
		{"example.com/owner/app/v2", "example.com/owner/app"},
		{"example.com/owner/app", "example.com/owner/app/v3"},
		{"example.com/owner/app/v3", "example.com/owner/app/v2"},
	} {
		dir := t.TempDir()
		version := "v1.0.0"
		switch {
		case strings.HasSuffix(pair.dependency, "/v2"):
			version = "v2.0.0"
		case strings.HasSuffix(pair.dependency, "/v3"):
			version = "v3.0.0"
		}
		goMod := fmt.Sprintf("module %s\n\ngo 1.24\n\nrequire %s %s\n", pair.project, pair.dependency, version)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644))
		deps, err := libraryDependencies(dir, pair.project, nil)
		require.NoError(t, err)
		assert.Empty(t, deps, "project %s must ignore dependency %s", pair.project, pair.dependency)
	}
	assert.False(t, sameModuleMajorBase("example.com/owner/app/v2", "example.com/owner/other"))
	assert.False(t, sameModuleMajorBase("example.com/owner/app/v1", "example.com/owner/app"))
}

func TestDuplicateFuncOfLibraryFindsNestedModule(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	lib := filepath.Join(root, "lib")
	app := filepath.Join(root, "backend")
	writeLibraryTestModule(t, lib, "example.com/owner/lib", map[string]string{"amount.go": libraryAmountSource})
	writeLibraryTestConsumer(t, app, "example.com/owner/backend", "example.com/owner/lib", "../lib", libraryAmountCopy)
	ctx := loadLibraryTestProject(t, root, app, libraryAmountCopy)
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "NormalizeAmount")
}

func TestDuplicateFuncOfLibraryResolvesGoWorkUse(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	lib := filepath.Join(root, "lib")
	app := filepath.Join(root, "app")
	writeLibraryTestModule(t, lib, "example.com/owner/lib", map[string]string{"amount.go": libraryAmountSource})
	writeLibraryTestConsumer(t, app, "example.com/owner/app", "example.com/owner/lib", "", libraryAmountCopy)
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.24\n\nuse (\n ./app\n ./lib\n)\n"), 0o644))
	ctx := loadLibraryTestProject(t, root, app, libraryAmountCopy)
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
}

func TestDuplicateFuncOfLibraryChoosesMatchDeterministically(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	lib := filepath.Join(root, "lib")
	app := filepath.Join(root, "app")
	writeLibraryTestModule(t, lib, "example.com/owner/lib", map[string]string{
		"a/amount.go": `package first
func Alpha(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`,
		"z/amount.go": `package second
func Zeta(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`,
	})
	writeLibraryTestConsumer(t, app, "example.com/owner/app", "example.com/owner/lib", "../lib", libraryAmountCopy)
	ctx := loadLibraryTestProject(t, root, app, libraryAmountCopy)
	for range 4 {
		violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
		require.NoError(t, err)
		require.Len(t, violations, 1)
		assert.Contains(t, violations[0].Message, "function Alpha")
	}
}

func TestDuplicateFuncOfLibraryIgnoresDiskCacheErrors(t *testing.T) {
	cacheHome := filepath.Join(t.TempDir(), "cache-file")
	require.NoError(t, os.WriteFile(cacheHome, []byte("file blocks cache directory creation"), 0o644))
	t.Setenv("GOCACHE", t.TempDir())
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", libraryAmountCopy,
		map[string]string{"amount.go": libraryAmountSource}, true, "")
	t.Setenv("XDG_CACHE_HOME", cacheHome)
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
}

func TestDuplicateFuncOfLibrarySkipsOnlyBrokenLibraryPackage(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOWORK", "off")
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", libraryAmountCopy,
		map[string]string{"amount.go": libraryAmountSource}, true, "")
	appDir := ctx.Packages[0].Package.Module.Dir
	libDir := filepath.Join(filepath.Dir(appDir), "library")
	require.NoError(t, os.MkdirAll(filepath.Join(libDir, "ext"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(libDir, "ext", "broken.go"), []byte("package ext\nimport \"example.com/missing/dep\"\nvar _ dep.Value\n"), 0o644))

	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	before := libraryPackageLoads.Load()
	violations, err := rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Empty(t, warnings.String())
	firstLoads := libraryPackageLoads.Load()
	assert.Greater(t, firstLoads, before)
	cacheDir := filepath.Join(os.Getenv("XDG_CACHE_HOME"), "glint", "tools", "duplicate-func-of-library")
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	require.NotEmpty(t, entries, "valid package keys should be cached despite the broken sibling")

	warnings.Reset()
	violations, err = rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Empty(t, warnings.String())
	assert.Equal(t, firstLoads, libraryPackageLoads.Load(), "cached keys should avoid reloading the broken sibling")
}

func TestDuplicateFuncOfLibraryDoesNotMatchFunctionFromBrokenPackage(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOWORK", "off")
	brokenSource := strings.Replace(libraryAmountSource, "package lib", "package lib\n\nimport missing \"example.com/missing/dependency\"\nvar _ = missing.Value", 1)
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", libraryAmountCopy,
		map[string]string{"amount.go": brokenSource}, true, "")
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	violations, err := rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	assert.Empty(t, violations, "functions from packages with type errors must not be used as library keys")
	assert.Empty(t, warnings.String(), "package type errors are skipped quietly")
}

func TestDuplicateFuncOfLibraryCacheKeyTracksDependencyAvailability(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOWORK", "off")
	cacheRoot := os.Getenv("GOMODCACHE")
	libDir := filepath.Join(cacheRoot, "example.com/owner/lib@v1.0.0")
	require.NoError(t, os.MkdirAll(libDir, 0o755))
	libMod := "module example.com/owner/lib\n\ngo 1.24\n\nrequire example.com/owner/ext v1.0.0\n"
	require.NoError(t, os.WriteFile(filepath.Join(libDir, "go.mod"), []byte(libMod), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(libDir, "amount.go"), []byte(libraryAmountSource), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(libDir, "broken.go"), []byte("package lib\nimport ext \"example.com/owner/ext\"\nvar _ = ext.Value\n"), 0o644))

	validDir := filepath.Join(t.TempDir(), "valid-library")
	writeLibraryTestModule(t, validDir, "example.com/owner/lib", map[string]string{"amount.go": libraryAmountSource})
	validEntry, err := loadLibraryFunctionKeys(validDir)
	require.NoError(t, err)
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", libraryAmountCopy, nil, false, "")
	rule := NewDuplicateFuncOfLibraryRule()
	loads := 0
	rule.loadLibraryKeys = func(string) (libraryCacheEntry, error) {
		loads++
		extDir := filepath.Join(cacheRoot, "example.com/owner/ext@v1.0.0")
		if _, err := os.Stat(extDir); errors.Is(err, os.ErrNotExist) {
			return libraryCacheEntry{Keys: map[string][]libraryFunction{}}, nil
		}
		return validEntry, nil
	}
	violations, err := rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	assert.Empty(t, violations, "the unavailable dependency makes the cached package key empty")
	assert.Equal(t, 1, loads)

	extDir := filepath.Join(cacheRoot, "example.com/owner/ext@v1.0.0")
	writeLibraryTestModule(t, extDir, "example.com/owner/ext", map[string]string{"ext.go": "package ext\nconst Value = 1\n"})
	violations, err = rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1, "a new dependency availability fingerprint must miss the stale key")
	assert.Equal(t, 2, loads)
	violations, err = rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, 2, loads, "the new fingerprint should be cached")
}

func TestDuplicateFuncOfLibraryWarnsOnLocalModuleTreeHashFailure(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", libraryAmountCopy,
		map[string]string{"amount.go": libraryAmountSource}, true, "")
	appDir := ctx.Packages[0].Package.Module.Dir
	libDir := filepath.Join(filepath.Dir(appDir), "library")
	require.NoError(t, os.WriteFile(filepath.Join(libDir, "go.mod"), []byte("module example.com/owner/lib\n\nrequire example.com/owner/ext\n"), 0o644))
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	violations, err := rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	assert.Empty(t, violations)
	assert.Contains(t, warnings.String(), "hash local module tree")
}

func TestLoadLibraryFunctionKeysReturnsPackageLoadError(t *testing.T) {
	_, err := loadLibraryFunctionKeys(filepath.Join(t.TempDir(), "missing-library"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load packages from")
}

func TestSourceModuleExistsReturnsNonMissingStatError(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(file, []byte("file"), 0o644))
	found, err := sourceModuleExists(file)
	assert.False(t, found)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stat module source")
}

func TestWorkspaceModulePathsReturnsReadError(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(parent, []byte("file"), 0o644))
	_, err := workspaceModulePaths(filepath.Join(parent, "go.work"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read workspace")
}

func TestDuplicateFuncOfLibraryDefaultWarningWriterUsesStderr(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	previous := os.Stderr
	os.Stderr = writer
	t.Cleanup(func() { os.Stderr = previous })
	NewDuplicateFuncOfLibraryRule().warnLibraryInput("example.com/owner/lib", "test input", errors.New("synthetic failure"))
	require.NoError(t, writer.Close())
	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	assert.Contains(t, string(output), "warning: duplicate-func-of-library could not test input")
}

func TestLibraryDependencyAvailabilityParseError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/owner/lib\nrequire broken\n"), 0o644))
	_, err := libraryDependencyAvailability(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse library module file")
}

func TestLibraryDependencyAvailabilityStatError(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("GOMODCACHE", cacheRoot)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/owner/lib\n\nrequire example.com/owner/ext v1.0.0\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(cacheRoot, "example.com"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(cacheRoot, "example.com/owner"), []byte("not a directory"), 0o644))
	_, err := libraryDependencyAvailability(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "check required module")
}

func TestLibraryDependencyAvailabilityUsesLocalReplacePath(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("GOMODCACHE", cacheRoot)
	dir := t.TempDir()
	localDir := filepath.Join(dir, "local-ext")
	writeLibraryTestModule(t, localDir, "example.com/owner/local-ext", nil)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/owner/lib\n\nrequire example.com/owner/ext v1.0.0\nreplace example.com/owner/ext => ./local-ext\n"), 0o644))
	fingerprint, err := libraryDependencyAvailability(dir)
	require.NoError(t, err)
	baselineDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(baselineDir, "go.mod"), []byte("module example.com/owner/lib\n\nrequire example.com/owner/ext v1.0.0\n"), 0o644))
	baseline, err := libraryDependencyAvailability(baselineDir)
	require.NoError(t, err)
	assert.NotEqual(t, baseline, fingerprint)
}

func TestLibraryDependencyAvailabilityUsesVersionedReplaceTarget(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("GOMODCACHE", cacheRoot)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/owner/lib\n\nrequire example.com/owner/ext v1.0.0\nreplace example.com/owner/ext v1.0.0 => example.com/owner/fork v2.0.0\n"), 0o644))
	target := filepath.Join(cacheRoot, "example.com/owner/fork@v2.0.0")
	writeLibraryTestModule(t, target, "example.com/owner/fork", nil)
	fingerprint, err := libraryDependencyAvailability(dir)
	require.NoError(t, err)
	baselineDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(baselineDir, "go.mod"), []byte("module example.com/owner/lib\n\nrequire example.com/owner/ext v1.0.0\n"), 0o644))
	baseline, err := libraryDependencyAvailability(baselineDir)
	require.NoError(t, err)
	assert.NotEqual(t, baseline, fingerprint)
}

func TestLibraryReplacementPrefersExactVersion(t *testing.T) {
	mod, err := modfile.Parse("go.mod", []byte("module example.com/owner/lib\n\nrequire example.com/owner/ext v1.0.0\nreplace example.com/owner/ext => example.com/owner/generic v1.0.0\nreplace example.com/owner/ext v1.0.0 => example.com/owner/specific v1.0.0\n"), nil)
	require.NoError(t, err)
	replacement := libraryReplacement(mod.Replace, module.Version{Path: "example.com/owner/ext", Version: "v1.0.0"})
	require.NotNil(t, replacement)
	assert.Equal(t, "example.com/owner/specific", replacement.New.Path)
}

func TestDuplicateFuncOfLibraryWarnsWhenLibraryDependencyGoModCannotBeParsed(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cacheRoot := t.TempDir()
	t.Setenv("GOMODCACHE", cacheRoot)
	ctx := duplicateLibraryTestProject(t, "example.com/owner/lib", "example.com/owner/app", libraryAmountCopy, nil, false, "")
	libDir := filepath.Join(cacheRoot, "example.com/owner/lib@v1.0.0")
	require.NoError(t, os.MkdirAll(libDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(libDir, "go.mod"), []byte("module example.com/owner/lib\nrequire broken\n"), 0o644))
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	_, err := rule.AnalyzeGoProject(ctx)
	require.NoError(t, err)
	assert.Contains(t, warnings.String(), "inspect library dependencies")
	assert.Contains(t, warnings.String(), "parse library module file")
}

func TestDuplicateFuncOfLibraryMissingSourceIsSilent(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("GOMODCACHE", t.TempDir())
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	keys := map[string]libraryMatch{}
	rule.mergeDependencyKeys(keys, goModule{path: "example.com/owner/app", dir: t.TempDir()}, libraryDependency{path: "example.com/owner/lib", version: "v1.0.0"}, toolcache.New("missing-source-test"))
	assert.Empty(t, keys)
	assert.Empty(t, warnings.String())
}

func TestDuplicateFuncOfLibraryWarnsWhenDependenciesCannotBeRead(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	keys := rule.loadModuleLibraryKeys(goModule{path: "example.com/owner/app", dir: dir}, nil, toolcache.New("bad-project-mod-test"))
	assert.Empty(t, keys)
	assert.Contains(t, warnings.String(), "could not read dependencies")
	assert.Contains(t, warnings.String(), "go.mod")
}

func TestDuplicateFuncOfLibraryWarnsWhenSourceLocationFails(t *testing.T) {
	t.Setenv("GOMODCACHE", t.TempDir())
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	keys := map[string]libraryMatch{}
	rule.mergeDependencyKeys(keys, goModule{path: "example.com/owner/app", dir: t.TempDir()}, libraryDependency{path: "invalid path", version: "v1.0.0"}, toolcache.New("bad-source-path-test"))
	assert.Empty(t, keys)
	assert.Contains(t, warnings.String(), "could not locate source")
}

func TestDuplicateFuncOfLibraryWarnsWhenExecutableHashFails(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	project, dep, cache := libraryMergeTestInput(t)
	previous := duplicateLibraryBuildHash
	t.Cleanup(func() { duplicateLibraryBuildHash = previous })
	duplicateLibraryBuildHash = func() (string, error) { return "", errors.New("synthetic executable failure") }
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	rule.mergeDependencyKeys(map[string]libraryMatch{}, project, dep, cache)
	assert.Contains(t, warnings.String(), "could not identify analyzer")
}

func TestDuplicateFuncOfLibraryWarnsWhenCacheLoadFails(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	project, dep, cache := libraryMergeTestInput(t)
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	rule.loadCache = func(*toolcache.Cache, string) (libraryCacheEntry, bool, error) {
		return libraryCacheEntry{}, false, errors.New("synthetic cache read failure")
	}
	rule.loadLibraryKeys = func(string) (libraryCacheEntry, error) {
		return libraryCacheEntry{Keys: map[string][]libraryFunction{}}, nil
	}
	rule.storeCache = func(*toolcache.Cache, string, libraryCacheEntry) error { return nil }
	rule.mergeDependencyKeys(map[string]libraryMatch{}, project, dep, cache)
	assert.Contains(t, warnings.String(), "could not read cache")
}

func TestDuplicateFuncOfLibraryWarnsWhenDiskCacheLoadFails(t *testing.T) {
	cacheHome := filepath.Join(t.TempDir(), "cache-file")
	require.NoError(t, os.WriteFile(cacheHome, []byte("not a directory"), 0o644))
	t.Setenv("XDG_CACHE_HOME", cacheHome)
	project, dep, cache := libraryMergeTestInput(t)
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	rule.loadLibraryKeys = func(string) (libraryCacheEntry, error) {
		return libraryCacheEntry{Keys: map[string][]libraryFunction{}}, nil
	}
	rule.storeCache = func(*toolcache.Cache, string, libraryCacheEntry) error { return nil }
	rule.mergeDependencyKeys(map[string]libraryMatch{}, project, dep, cache)
	assert.Contains(t, warnings.String(), "could not read cache")
}

func TestDuplicateFuncOfLibraryWarnsWhenLibraryLoadFails(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	project, dep, cache := libraryMergeTestInput(t)
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	rule.loadCache = func(*toolcache.Cache, string) (libraryCacheEntry, bool, error) {
		return libraryCacheEntry{}, false, nil
	}
	rule.loadLibraryKeys = func(string) (libraryCacheEntry, error) {
		return libraryCacheEntry{}, errors.New("synthetic package load failure")
	}
	rule.mergeDependencyKeys(map[string]libraryMatch{}, project, dep, cache)
	assert.Contains(t, warnings.String(), "could not load source")
}

func TestDuplicateFuncOfLibraryWarnsWhenCacheStoreFails(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	project, dep, cache := libraryMergeTestInput(t)
	rule := NewDuplicateFuncOfLibraryRule()
	var warnings bytes.Buffer
	rule.warningWriter = &warnings
	rule.loadCache = func(*toolcache.Cache, string) (libraryCacheEntry, bool, error) {
		return libraryCacheEntry{}, false, nil
	}
	rule.loadLibraryKeys = func(string) (libraryCacheEntry, error) {
		return libraryCacheEntry{Keys: map[string][]libraryFunction{}}, nil
	}
	rule.storeCache = func(*toolcache.Cache, string, libraryCacheEntry) error {
		return errors.New("synthetic cache write failure")
	}
	rule.mergeDependencyKeys(map[string]libraryMatch{}, project, dep, cache)
	assert.Contains(t, warnings.String(), "could not write cache")
}

func TestActiveGoWorkReturnsGoEnvFailure(t *testing.T) {
	fakeGoPath(t)
	_, err := activeGoWork(t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query active workspace")
}

func TestWorkspaceModulePathsReturnsParseAndUseFailures(t *testing.T) {
	t.Run("invalid syntax", func(t *testing.T) {
		work := filepath.Join(t.TempDir(), "go.work")
		require.NoError(t, os.WriteFile(work, []byte("go 1.24\nuse (\n"), 0o644))
		_, err := workspaceModulePaths(work)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse workspace")
	})
	t.Run("missing module in use", func(t *testing.T) {
		root := t.TempDir()
		work := filepath.Join(root, "go.work")
		require.NoError(t, os.WriteFile(work, []byte("go 1.24\n\nuse ./missing\n"), 0o644))
		_, err := workspaceModulePaths(work)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read module in workspace use")
	})
}

func TestModuleCacheDirReturnsGoEnvFailure(t *testing.T) {
	t.Setenv("GOMODCACHE", "")
	fakeGoPath(t)
	_, err := moduleCacheDir(t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query module cache")
}

func TestLibraryDependenciesReturnsMalformedGoModError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/owner/app\n\nrequire example.com/owner/lib\n"), 0o644))
	_, err := libraryDependencies(dir, "example.com/owner/app", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func libraryMergeTestInput(t *testing.T) (goModule, libraryDependency, *toolcache.Cache) {
	t.Helper()
	root := t.TempDir()
	projectDir := filepath.Join(root, "app")
	libraryDir := filepath.Join(root, "lib")
	writeLibraryTestModule(t, libraryDir, "example.com/owner/lib", map[string]string{"amount.go": libraryAmountSource})
	return goModule{path: "example.com/owner/app", dir: projectDir}, libraryDependency{path: "example.com/owner/lib", version: "v1.0.0", dir: libraryDir}, toolcache.New("library-error-branches-test")
}

func fakeGoPath(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := filepath.Join(bin, "go")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\necho synthetic go env failure >&2\nexit 27\n"), 0o755))
	t.Setenv("PATH", bin)
}

const libraryAmountSource = `package lib
func NormalizeAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`

const libraryAmountCopy = `package app
func tidyAmount(value int) int {
	if value < 0 { value = -value }
	value = value * 100
	if value > 100000 { value = 100000 }
	return value
}
`

func writeLibraryTestConsumer(t *testing.T, dir, project, dependency, replace, source string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	goMod := "module " + project + "\n\ngo 1.24\n\nrequire " + dependency + " v1.0.0\n"
	if replace != "" {
		goMod += "replace " + dependency + " => " + replace + "\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "amount.go"), []byte(source), 0o644))
}

func loadLibraryTestProject(t *testing.T, root, moduleDir, source string) *core.GoProjectContext {
	t.Helper()
	filePath := filepath.Join(moduleDir, "amount.go")
	fileCtx, err := core.NewFileContextChecked(filePath, root, []byte(source), core.DefaultConfig())
	require.NoError(t, err)
	ctx, err := core.LoadGoProject(root, []*core.FileContext{fileCtx}, core.GoProjectOptions{})
	require.NoError(t, err)
	return ctx
}

func duplicateLibraryTestProject(t *testing.T, dep, project, source string, libFiles map[string]string, local bool, replace string) *core.GoProjectContext {
	t.Helper()
	root := t.TempDir()
	consumer := filepath.Join(root, "consumer")
	require.NoError(t, os.MkdirAll(consumer, 0o755))
	var libraryDir string
	if local {
		libraryDir = filepath.Join(root, "library")
		writeLibraryTestModule(t, libraryDir, dep, libFiles)
		replace = "replace " + dep + " => ../library\n"
	}
	goMod := "module " + project + "\n\ngo 1.24\n\nrequire " + dep + " v1.0.0\n" + replace
	require.NoError(t, os.WriteFile(filepath.Join(consumer, "go.mod"), []byte(goMod), 0o644))
	goFile := filepath.Join(consumer, "amount.go")
	require.NoError(t, os.WriteFile(goFile, []byte(source), 0o644))
	fileCtx, err := core.NewFileContextChecked(goFile, consumer, []byte(source), core.DefaultConfig())
	require.NoError(t, err)
	ctx, err := core.LoadGoProject(consumer, []*core.FileContext{fileCtx}, core.GoProjectOptions{})
	require.NoError(t, err)
	return ctx
}

func writeLibraryTestModule(t *testing.T, dir, modulePath string, files map[string]string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+modulePath+"\n\ngo 1.24\n"), 0o644))
	for name, source := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(source), 0o644))
	}
}

func TestDuplicateFuncAcrossPackagesTestImportThroughDependency(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600))
	}
	write("label.go", "package alpha\n")
	write("_old_test.go", "package alpha\n\nimport (\n")
	alphaTypes := types.NewPackage("example.com/x/alpha", "alpha")
	betaTypes := types.NewPackage("example.com/x/beta", "beta")
	beta := &packages.Package{PkgPath: betaTypes.Path(), Name: "beta"}
	mid := &packages.Package{PkgPath: "example.com/ext/mid", Name: "mid", Imports: map[string]*packages.Package{beta.PkgPath: beta}}
	gamma := &packages.Package{PkgPath: "example.com/x/gamma", Name: "gamma", Imports: map[string]*packages.Package{mid.PkgPath: mid}}
	alpha := &packages.Package{PkgPath: alphaTypes.Path(), Name: "alpha", GoFiles: []string{filepath.Join(dir, "label.go")}}
	ctx := &core.GoProjectContext{Packages: []*core.GoPackageContext{{Package: alpha}, {Package: beta}, {Package: gamma}}}
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	copies := []*types.Func{types.NewFunc(token.NoPos, alphaTypes, "f", sig), types.NewFunc(token.NoPos, betaTypes, "f", sig)}

	assert.True(t, newImportGraph(ctx).importedByAll(alphaTypes, copies), "go skips _old_test.go, so it does not make the tests unread")

	write("label_test.go", "package alpha\n\nimport \"example.com/ext/mid\"\n\nvar _ = mid.Name\n")
	assert.False(t, newImportGraph(ctx).importedByAll(alphaTypes, copies), "the test of alpha reaches beta through mid, a dependency of gamma")
}

package errrules

import (
	"fmt"
	"go/ast"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestFallbackReturn_LiteralAfterFailedCallWithoutErrorResult(t *testing.T) {
	const source = `package svc

import "time"

func parseClock(s string) time.Duration {
	t, e := time.Parse("15:04", s)
	if e != nil {
		return 7 * time.Hour
	}
	return time.Duration(t.Hour()) * time.Hour
}

func parseCount(s string) int {
	n, err := parseInt(s)
	if err != nil {
		return DefaultCount
	}
	return n
}

const DefaultCount = 3

func parseInt(string) (int, error) { return 0, nil }
`
	assert.Empty(t, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "svc/parse.go", source))
	assert.Equal(t, []int{8, 16}, typedFallbackLines(t, "svc/parse.go", source))
}

func TestFallbackReturn_LiteralAfterFailedCallExclusions(t *testing.T) {
	const source = `package svc

import (
	"log/slog"
	"time"
)

func parseInt(string) (int, error) { return 0, nil }
func backup() int { return 1 }

func predicate(s string) bool {
	_, e := time.Parse("15:04", s)
	if e != nil { return false }
	return true
}

func zero(s string) int {
	_, err := parseInt(s)
	if err != nil { return 0 }
	return 1
}

func logged(s string) int {
	_, err := parseInt(s)
	if err != nil {
		slog.Warn("parse failed", "error", err)
		return 3
	}
	return 1
}

func loggedInNestedBranch(s string, verbose bool) int {
	_, err := parseInt(s)
	if err != nil {
		if verbose { slog.Warn("parse failed") }
		return 3
	}
	return 1
}

func explained(s string) int {
	_, err := parseInt(s)
	if err != nil {
		// Use a small value while the optional source is unavailable.
		return 3
	}
	return 1
}

func explainedAfterOtherSuppression(s string) int {
	_, err := parseInt(s)
	if err != nil {
		//nolint:some-other-rule // intentional: use a sentinel after the process exits
		return -1
	}
	return 1
}

func errorResult(s string) (int, error) {
	if _, err := parseInt(s); err != nil { return 3, nil }
	return 1, nil
}

func failover(s string) int {
	_, err := parseInt(s)
	if err != nil { return backup() }
	return 1
}

func selectorField(s string, c config) int {
	n, err := parseInt(s); _ = n
	if err != nil { return c.Default }
	return n
}

func packageSelectorField(s string) int {
	n, err := parseInt(s); _ = n
	if err != nil { return Defaults.Count }
	return n
}

type config struct { Default, Count int }
var Defaults config

func explainedAboveIf(s string) int {
	n, err := parseInt(s)
	// Intentional: preserve the documented default for partial input.
	if err != nil { return 3 }
	return n
}

func explainedOnIf(s string) int {
	n, err := parseInt(s)
	if err != nil { // Best effort: retain the partial value.
		return 3
	}
	return n
}

`
	lines := typedFallbackLines(t, "svc/parse.go", source)
	assert.Equal(t, []int{54}, lines) // A rationale after another rule's nolint is not an explanation.
}

func TestFallbackReturn_LiteralConditionsHaveIndependentNegatives(t *testing.T) {
	const source = `package svc

import "log/slog"

func parse(string) (int, error) { return 0, nil }
func backup() int { return 2 }

func producedValue(s string) int { n, err := parse(s); if err != nil { return backup() }; return n }
func errorRead(s string) int { n, err := parse(s); if err != nil { record(err); return 3 }; return n }
func logging(s string) int { n, err := parse(s); if err != nil { slog.Warn("failed", "err", err); return 3 }; return n }
func errorResult(s string) (int, error) { if _, err := parse(s); err != nil { return 3, nil }; return 1, nil }
func reasonComment(s string) int { n, err := parse(s); if err != nil { // Intentional: documented fallback.
 return 3 }; return n }
func zeroValue(s string) int { n, err := parse(s); if err != nil { return 0 }; return n }
func predicate(s string) bool { n, err := parse(s); if err != nil { return false }; return n > 0 }
func record(error) {}
`
	assert.Empty(t, typedFallbackLines(t, "svc/conditions.go", source))
}

func TestFallbackReturn_LiteralEachExclusion(t *testing.T) {
	cases := []struct {
		name, function string
	}{
		{"call-produced value", `func check(s string) int { n, err := parse(s); if err != nil { return backup() }; return n }`},
		{"error read", `func check(s string) int { n, err := parse(s); if err != nil { record(err); return 3 }; return n }`},
		{"branch log", `func check(s string) int { n, err := parse(s); if err != nil { slog.Warn("failed", "err", err); return 3 }; return n }`},
		{"reason comment", "func check(s string) int { n, err := parse(s); if err != nil {\n// Intentional: retain the documented default.\nreturn 3 }; return n }"},
		{"error result", `func check(s string) (int, error) { _, err := parse(s); if err != nil { return 3, nil }; return 1, nil }`},
		{"zero value", `func check(s string) int { n, err := parse(s); if err != nil { return 0 }; return n }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := fmt.Sprintf("package svc\nimport \"log/slog\"\nvar _ = slog.Warn\nfunc parse(string) (int,error) { return 0,nil }\nfunc backup() int { return 1 }\nfunc record(error) {}\n%s\n", tc.function)
			assert.Empty(t, typedFallbackLines(t, "svc/condition.go", source))
		})
	}
	t.Run("false predicate", func(t *testing.T) {
		const source = `package svc
func parse(string) (bool, error) { return false, nil }
func check(s string) bool { value, err := parse(s); if err != nil { return false }; return value }
`
		assert.Empty(t, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "svc/predicate.go", source))
	})
}

func TestFallbackReturn_LiteralExcludesCallProducedNames(t *testing.T) {
	const source = `package svc
const Default = 3
func check() int { value := backup(); if value > 0 { return Default }; return 0 }
func backup() int { return 1 }
`
	project := rulestest.ProjectRunning(t, map[string]string{"svc/produced.go": source}, "svc/produced.go")
	ctx := project.Files[0]
	var returned ast.Expr
	ast.Inspect(ctx.GoAST, func(node ast.Node) bool {
		ret, ok := node.(*ast.ReturnStmt)
		if ok && len(ret.Results) == 1 {
			if ident, ok := ret.Results[0].(*ast.Ident); ok && ident.Name == "Default" {
				returned = ret.Results[0]
			}
		}
		return true
	})
	if assert.NotNil(t, returned) {
		assert.False(t, isLiteralOrConstantExpr(ctx, returned, map[string]bool{"Default": true}))
		assert.True(t, isLiteralOrConstantExpr(ctx, returned, nil))
	}
}

func TestFallbackReturn_LiteralNoTypesSupportsBlankAndShortResults(t *testing.T) {
	const source = `package svc
import "time"
func parse(string) (int, error) { return 0, nil }
func blank(s string) int { _, err := parse(s); if err != nil { return 3 }; return 1 }
func blankE(s string) time.Duration { _, e := time.Parse("15:04", s); if e != nil { return 7 * time.Hour }; return time.Hour }
func short(s string) int { if _, err := parse(s); err != nil { return 3 }; return 1 }
func single() int { err := setup(); if err != nil { return 3 }; return 1 }
func setup() error { return nil }
`
	want := []int{4, 5, 6, 7}
	assert.Empty(t, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "svc/blank.go", source))
	assert.Equal(t, want, typedFallbackLines(t, "svc/blank.go", source))
}

func TestFallbackReturn_LiteralHandlesShortInitAndNestedFunctionSignatures(t *testing.T) {
	const source = `package svc
import "time"
func parse(string) (int, error) { return 0, nil }
func blank(string) int { if _, err := parse(""); err != nil { return 3 }; return 1 }
func blankE(s string) time.Duration { if _, e := time.Parse("15:04", s); e != nil { return 7 * time.Hour }; return time.Hour }
func outer(s string) (int, error) { inner := func() int { n, err := parse(s); if err != nil { return 3 }; return n }; return inner(), nil }
func setup() error { return nil }
func single() int { err := setup(); if err != nil { return 3 }; return 1 }
`
	assert.Equal(t, []int{4, 5, 6, 8}, typedFallbackLines(t, "svc/short.go", source))
}

func TestFallbackReturn_LiteralIgnoresZeroConstantResults(t *testing.T) {
	const source = `package svc
func parse(string) (int, error) { return 0, nil }
const Zero = 0
const Empty = ""
func zero(s string) int { n, err := parse(s); if err != nil { return Zero }; return n }
func empty(s string) string { n, err := parse(s); if err != nil { return Empty }; return string(rune(n)) }
`
	assert.Empty(t, typedFallbackLines(t, "svc/zero.go", source))
}

func TestFallbackReturn_LiteralUsesErrorTypeWhenAvailable(t *testing.T) {
	const source = `package svc

func parse() (int, error) { return 0, nil }
type customError interface { Error() string }
func parseCustom() (int, customError) { return 0, nil }
type problem struct{}
func inspect() (int, *problem) { return 0, nil }

func typedName() int {
	value, e := parse()
	if e != nil { return 3 }
	return value
}

func misleadingName() int {
	value, err := inspect()
	if err != nil { return 3 }
	return value
}

func customInterface() int {
	value, e := parseCustom()
	if e != nil { return 5 }
	return value
}
`
	assert.Equal(t, []int{11, 23}, typedFallbackLines(t, "svc/parse.go", source))
}

func TestFallbackReturn_LiteralTypedValuesAndScopes(t *testing.T) {
	const source = `package svc
import "time"
type config struct { Default int }
var Defaults config
const Half = 5
const Zero = 0
const Empty = ""
const n = 7
func parse(string) (int, error) { return 0, nil }
func backup() int { return 1 }
func nonzero(s string) int { _, err := parse(s); if err != nil { return int(7*time.Hour) }; return 1 }
func zeroExpressions(s string) int64 { _, err := parse(s); if err != nil { return int64(0) }; return 1 }
func zeroArithmetic(s string) int { _, err := parse(s); if err != nil { return Half*0 }; return 1 }
func constZero(s string) int { _, err := parse(s); if err != nil { return Zero }; return 1 }
func emptyZero(s string) string { _, err := parse(s); if err != nil { return Empty }; return "x" }
func truth(s string) bool { _, err := parse(s); if err != nil { return true }; return false }
func structNonzero(s string) config { _, err := parse(s); if err != nil { return config{Default: 5} }; return config{} }
func sliceNonzero(s string) []int { _, err := parse(s); if err != nil { return []int{1} }; return nil }
func structZero(s string) config { _, err := parse(s); if err != nil { return config{} }; return config{Default: 1} }
func sliceZero(s string) []int { _, err := parse(s); if err != nil { return []int{} }; return []int{1} }
func packageVar(s string) int { _, err := parse(s); if err != nil { return Defaults.Default }; return 1 }
func shadowedConst(s string) int { n, err := parse(s); if err != nil { return n }; return n }
func failover(s string) int { _, err := parse(s); if err != nil { return backup() }; return 1 }
`
	assert.Equal(t, []int{11, 17, 18}, typedFallbackLines(t, "svc/values.go", source))
}

func TestFallbackReturn_LiteralIfInitOkDoesNotPanic(t *testing.T) {
	const source = `package svc
func pair() (int, bool) { return 0, false }
func check() int { if v, ok := pair(); !ok { return 0 } else { return v } }
`
	assert.Empty(t, rulestest.GoFileRuleLines(t, NewFallbackReturnRule(), "svc/panic.go", source))
}

func TestFallbackReturn_LiteralConditionsUseTheirOwnEnclosingSignature(t *testing.T) {
	const source = `package svc
func parse() (int, error) { return 0, nil }
func outer() (int, error) { inner := func() int { _, err := parse(); if err != nil { return 3 }; return 1 }; return inner(), nil }
`
	assert.Equal(t, []int{3}, typedFallbackLines(t, "svc/nested.go", source))
}

func TestFallbackReturn_LiteralDistinguishesErrorResultChannelsByPosition(t *testing.T) {
	const source = `package svc
func lookup(string) (int, error) { return 0, nil }

func index(s string) (int, string) {
	_, err := lookup(s)
	if err != nil { return -1, "bad index" }
	return 1, ""
}

// period reads the interval; errKey names the alert.
func period(fromValue, toValue string) (from, to *int, errKey string) {
	if _, err := lookup(fromValue); err != nil { return nil, nil, "bad_date" }
	if _, err := lookup(toValue); err != nil { return nil, nil, "bad_period" }
	return from, to, ""
}
`
	assert.Equal(t, []int{6}, typedFallbackLines(t, "svc/channels.go", source))
}

func TestFallbackReturn_LiteralTreatsUncertainZeroResultsAsErrorChannels(t *testing.T) {
	const source = `package svc
func lookup(string) (int, error) { return 0, nil }

func sentinel(s string) (int, string) {
	_, err := lookup(s)
	if err != nil { return -1, "bad" }
	return 1, ""
}

func returnedVariables(s string) (n int, errKey string) {
	_, err := lookup(s)
	if err != nil { return -1, "bad" }
	n = 0
	errKey = ""
	return n, errKey
}

func returnedUnassigned(s string) (n int, errKey string) {
	_, err := lookup(s)
	if err != nil { return -1, "bad" }
	n = 1
	return n, errKey
}

func bareReturn(s string) (n int, errKey string) {
	_, err := lookup(s)
	if err != nil { return -1, "bad" }
	n = 0
	errKey = ""
	return
}
`
	assert.Equal(t, []int{6}, typedFallbackLines(t, "svc/channels.go", source))
}

func typedFallbackLines(t *testing.T, path, source string) []int {
	t.Helper()
	project := rulestest.ProjectRunning(t, map[string]string{path: source}, path)
	assert.NotNil(t, project.Files[0].GoTypesInfo)
	return rulestest.ViolationLines(NewFallbackReturnRule().AnalyzeFile(project.Files[0]))
}

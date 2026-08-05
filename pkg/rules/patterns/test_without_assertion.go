package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTestWithoutAssertionRule())
}

// TestWithoutAssertionRule detects Go test functions that cannot fail because
// they never assert anything — typically "documentation" tests that print a
// finding and stay green forever:
//
//	func TestOverflowProtection(t *testing.T) {
//	    result := maxInt64.Mul(million)
//	    t.Logf("VULNERABILITY: No overflow detection on Mul()")
//	}
//
// Such a test claims coverage of behaviour nobody verifies. Either assert what
// the code must do, or delete the test.
//
// The give-away is t.Log/t.Logf standing where an assertion belongs: the test
// states a finding instead of checking it. A test that merely exercises code
// without logging is a different, legitimate thing — it fails if that code
// panics — and is not reported.
//
// Not flagged: tests that assert via testify/t.Error/t.Fatal, tests that hand
// *testing.T to a helper (the helper asserts), tests whose only statement is a
// compile-time assertion (`var _ Iface = (*Impl)(nil)` — the compiler enforces
// it), smoke calls without logging, skipped tests (see skipped-tests),
// TestMain, benchmarks and fuzz targets.
//
// Companion rules: unfalsifiable-test-case covers TS/JS tests whose assertions
// hold regardless of behaviour; tautological-assertion covers `require.True(t,
// true)`. This one covers the "no assertion at all" case in Go.
type TestWithoutAssertionRule struct {
	*rules.BaseRule
}

// NewTestWithoutAssertionRule creates the rule
func NewTestWithoutAssertionRule() *TestWithoutAssertionRule {
	return &TestWithoutAssertionRule{
		BaseRule: rules.NewBaseRule(
			"test-without-assertion",
			"patterns",
			"Detects Go test functions that never assert and therefore cannot fail",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks Go test functions for the missing-assertion pattern
func (r *TestWithoutAssertionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil || !ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !isTestCaseFunc(fn) {
			continue
		}
		if bodyAsserts(fn.Body) || bodySkips(fn.Body) {
			continue
		}
		// Признак «документирующего» теста — печать вместо проверки. Без неё
		// тело теста просто исполняет код и падает на панике: это smoke-проверка.
		if !bodyLogsToTestingT(fn.Body) {
			continue
		}
		pos := ctx.PositionFor(fn)
		if core.LineSuppresses(ctx.GetLine(pos.Line), r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Test '"+fn.Name.Name+"' never asserts anything — it cannot fail and covers nothing")
		v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
		v.WithSuggestion("Assert the behaviour under test (require/assert/t.Fatal), or delete the test instead of claiming coverage")
		violations = append(violations, v)
	}

	return violations
}

// isTestCaseFunc reports whether the declaration is a real test case:
// func TestXxx(t *testing.T). TestMain, benchmarks and fuzz targets are not.
func isTestCaseFunc(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Name.Name == "TestMain" {
		return false
	}
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}
	return paramIsTestingT(fn.Type.Params.List[0])
}

// paramIsTestingT reports whether the parameter is *testing.T.
func paramIsTestingT(param *ast.Field) bool {
	star, ok := param.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing" && sel.Sel.Name == "T"
}

// bodyAsserts reports whether the body contains anything that can fail the
// test: a testify-style assertion, a t.Error/t.Fatal/t.Fail call, or a call
// that hands the *testing.T along to a helper (which asserts on our behalf).
func bodyAsserts(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if callIsFailing(call) || callForwardsTestingT(call) {
			found = true
			return false
		}
		return true
	})
	return found
}

// failingTestMethods are *testing.T methods that can fail a test.
var failingTestMethods = map[string]bool{
	"Error": true, "Errorf": true,
	"Fatal": true, "Fatalf": true,
	"Fail": true, "FailNow": true,
}

// callIsFailing reports whether the call itself can fail the test:
// require.X / assert.X / t.Error* / t.Fatal* / t.Fail*.
func callIsFailing(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch receiver.Name {
	case "require", "assert", "must":
		return true
	}
	return failingTestMethods[sel.Sel.Name]
}

// callForwardsTestingT reports whether the call passes a *testing.T-like
// argument to another function: assertions may live in that helper, and a
// closure passed to t.Run gets its own t (its body is inspected separately).
func callForwardsTestingT(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && isTestingIdentName(ident.Name) {
			return true
		}
	}
	return false
}

// isTestingIdentName reports whether the identifier is the conventional name
// of a *testing.T value.
func isTestingIdentName(name string) bool {
	return name == "t" || name == "tb"
}

// Пропуск теста (t.Skip) — предмет отдельного правила: bodySkips живёт в
// test_external_service.go, второй копии здесь не нужно.

// bodyLogsToTestingT reports whether the body prints through the test handle
// (t.Log/t.Logf and their subtest equivalents) — the marker of a test that
// states a finding instead of asserting it.
func bodyLogsToTestingT(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := sel.X.(*ast.Ident)
		if !ok || !isTestingIdentName(receiver.Name) {
			return true
		}
		if sel.Sel.Name == "Log" || sel.Sel.Name == "Logf" {
			found = true
			return false
		}
		return true
	})
	return found
}

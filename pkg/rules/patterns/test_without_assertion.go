package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
	testingPkgs := testingImportNames(ctx.GoAST)
	if len(testingPkgs) == 0 {
		return nil
	}

	var violations []*core.Violation

	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || goTestFuncKind(fn, testingPkgs) != goTestCase {
			continue
		}
		handles := scopeTestingHandles(nil, fn.Type.Params, testingPkgs)
		if bodyAsserts(fn.Body, handles, testingPkgs) || bodySkips(fn.Body) {
			continue
		}
		// Признак «документирующего» теста — печать вместо проверки. Без неё
		// тело теста просто исполняет код и падает на панике: это smoke-проверка.
		if !bodyLogsToTestingT(fn.Body, handles, testingPkgs) {
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

// goTestKind is what `go test` makes of a top-level function.
type goTestKind int

const (
	goNotTest goTestKind = iota
	goTestCase
	goBenchmark
	goFuzz
	goTestMain
)

// goTestFuncKind classifies a function the way `go test` does: TestXxx(*testing.T),
// BenchmarkXxx(*testing.B), FuzzXxx(*testing.F), where Xxx does not start with a
// lower-case letter, and TestMain(*testing.M). testingPkgs are the names the file
// imports "testing" under. This is the one test-function check of the Go test rules.
func goTestFuncKind(fn *ast.FuncDecl, testingPkgs map[string]bool) goTestKind {
	if fn.Recv != nil || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) > 1 {
		return goNotTest
	}
	param := fn.Type.Params.List[0].Type
	name := fn.Name.Name
	if name == "TestMain" {
		if testingPointer(param, testingPkgs, "M") {
			return goTestMain
		}
		return goNotTest
	}
	for _, kind := range []struct {
		prefix, typ string
		kind        goTestKind
	}{
		{"Test", "T", goTestCase},
		{"Benchmark", "B", goBenchmark},
		{"Fuzz", "F", goFuzz},
	} {
		if !strings.HasPrefix(name, kind.prefix) {
			continue
		}
		rest := name[len(kind.prefix):]
		if rest != "" && rest[0] >= 'a' && rest[0] <= 'z' {
			return goNotTest
		}
		if testingPointer(param, testingPkgs, kind.typ) {
			return kind.kind
		}
		return goNotTest
	}
	return goNotTest
}

// testingImportNames returns the names the file uses for the testing package.
func testingImportNames(file *ast.File) map[string]bool {
	return helpers.PackageAliases(file, `"testing"`, "testing")
}

// testingPointer reports whether the type expression is *<testing>.<name>.
func testingPointer(expr ast.Expr, testingPkgs map[string]bool, name string) bool {
	star, ok := expr.(*ast.StarExpr)
	return ok && testingSelector(star.X, testingPkgs, name)
}

// testingSelector reports whether the expression is <testing>.<name>.
func testingSelector(expr ast.Expr, testingPkgs map[string]bool, name string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && testingPkgs[pkg.Name]
}

// isTestingHandleType reports whether a parameter of this type can fail the
// test: *testing.T, *testing.B, *testing.F or testing.TB.
func isTestingHandleType(expr ast.Expr, testingPkgs map[string]bool) bool {
	return testingPointer(expr, testingPkgs, "T") || testingPointer(expr, testingPkgs, "B") ||
		testingPointer(expr, testingPkgs, "F") || testingSelector(expr, testingPkgs, "TB")
}

// scopeTestingHandles returns the testing handles visible inside a function
// with the given parameters: the outer ones, minus those a parameter shadows,
// plus the parameters typed as a testing handle — whatever they are called.
func scopeTestingHandles(outer map[string]bool, params *ast.FieldList, testingPkgs map[string]bool) map[string]bool {
	handles := make(map[string]bool, len(outer)+1)
	for name := range outer {
		handles[name] = true
	}
	if params == nil {
		return handles
	}
	for _, field := range params.List {
		isHandle := isTestingHandleType(field.Type, testingPkgs)
		for _, name := range field.Names {
			if isHandle {
				handles[name.Name] = true
			} else {
				delete(handles, name.Name)
			}
		}
	}
	return handles
}

// inspectTestingScopes walks the body like ast.Inspect, handing visit the testing
// handles in scope at each node: a closure (a t.Run subtest, a helper literal)
// brings its own parameters into scope.
func inspectTestingScopes(body ast.Node, handles, testingPkgs map[string]bool, visit func(ast.Node, map[string]bool) bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.FuncLit); ok {
			inspectTestingScopes(lit.Body, scopeTestingHandles(handles, lit.Type.Params, testingPkgs), testingPkgs, visit)
			return false
		}
		return visit(n, handles)
	})
}

// bodyAsserts reports whether the body contains anything that can fail the
// test: a testify-style assertion, a t.Error/t.Fatal/t.Fail call on a testing
// handle, or a call that hands a testing handle along to a helper (which
// asserts on our behalf).
func bodyAsserts(body *ast.BlockStmt, handles, testingPkgs map[string]bool) bool {
	found := false
	inspectTestingScopes(body, handles, testingPkgs, func(n ast.Node, inScope map[string]bool) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if callIsFailing(call, inScope) || callForwardsTestingT(call, inScope) {
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
// require.X / assert.X / must.X, or Error*/Fatal*/Fail* on a testing handle.
func callIsFailing(call *ast.CallExpr, handles map[string]bool) bool {
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
	return handles[receiver.Name] && failingTestMethods[sel.Sel.Name]
}

// callForwardsTestingT reports whether the call passes a testing handle to
// another function: assertions may live in that helper.
func callForwardsTestingT(call *ast.CallExpr, handles map[string]bool) bool {
	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && handles[ident.Name] {
			return true
		}
	}
	return false
}

// Пропуск теста (t.Skip) — предмет отдельного правила: bodySkips живёт в
// test_external_service.go, второй копии здесь не нужно.

// bodyLogsToTestingT reports whether the body prints through a testing handle
// (t.Log/t.Logf and their subtest equivalents) — the marker of a test that
// states a finding instead of asserting it.
func bodyLogsToTestingT(body *ast.BlockStmt, handles, testingPkgs map[string]bool) bool {
	found := false
	inspectTestingScopes(body, handles, testingPkgs, func(n ast.Node, inScope map[string]bool) bool {
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
		if !ok || !inScope[receiver.Name] {
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

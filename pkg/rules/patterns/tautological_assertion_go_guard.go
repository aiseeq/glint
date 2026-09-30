package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// Go tests that cannot fail by their control flow rather than by their
// assertion:
//
//	if data, ok := resp["data"].(map[string]any); ok { assert.False(t, data["ok"].(bool)) }
//	if w.TransactionID == nil { t.Logf("not created yet") } else { assert.NotEmpty(...) }
//	if err != nil { t.Skipf("server unavailable: %v", err) }
//
// The assertion runs only when the value is there, and the test passes when
// it is not; a failure of the code under test turns into a skip. Skips on the
// environment (testing.Short, a tool that is not installed, a variable that
// is not set) are left alone.

// environmentProbes are calls whose error says the environment lacks
// something, not that the code under test failed.
var environmentProbes = map[string]bool{
	"exec.LookPath": true, "os.Stat": true, "os.Lstat": true, "os.Getenv": true, "os.LookupEnv": true,
	"net.Dial": true, "net.DialTimeout": true,
}

func (r *TautologicalAssertionRule) goGuardsAndSkips(ctx *core.FileContext, testify map[string]bool) []*core.Violation {
	var violations []*core.Violation
	forEachFunction(ctx.GoAST, func(_ string, _ *ast.FuncType, body *ast.BlockStmt) {
		inLoop := loopStatements(body)
		forEachOwnStatementList(body, func(list []ast.Stmt) {
			for i, stmt := range list {
				ifStmt, ok := stmt.(*ast.IfStmt)
				if !ok {
					continue
				}
				switch {
				// A guard right in a loop body filters the items the test is
				// about; a branch that only fails makes the guard the check.
				case ifStmt.Else == nil && !inLoop[ifStmt] && isCommaOkGuard(ifStmt) && containsValueAssertion(ifStmt.Body, testify):
					violations = append(violations, r.violation(ctx, ctx.LineFor(ifStmt),
						"Assertion runs only when the value is there — without it the test passes checking nothing",
						"Assert the guard itself (require.True(t, ok)) and then the value, or fail in an else branch",
						"self_skipping"))
				case isNilLogOnlyBranch(ifStmt) && containsGoAssertion(ifStmt.Else, testify):
					violations = append(violations, r.violation(ctx, ctx.LineFor(ifStmt),
						"The branch where the value is missing only logs — the assertions below run only when it is there",
						"Fail when the value is missing, or assert that it is expected to be missing",
						"self_skipping"))
				}
				var before ast.Stmt
				if i > 0 {
					before = list[i-1]
				}
				if skip := skipCall(ifStmt.Body); skip != nil && isFailureCondition(ifStmt, before) {
					violations = append(violations, r.violation(ctx, ctx.LineFor(skip),
						"The test skips when the code under test fails — the failure shows as a skip and the suite stays green",
						"Fail the test (require.NoError, t.Fatalf); skip only on the environment, not on the result",
						"skip_on_failure"))
				}
			}
		})
	})
	return violations
}

// isCommaOkGuard reports if v, ok := x.(T); ok or if v, ok := m[k]; ok && ...
func isCommaOkGuard(ifStmt *ast.IfStmt) bool {
	assign, ok := ifStmt.Init.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return false
	}
	switch ast.Unparen(assign.Rhs[0]).(type) {
	case *ast.TypeAssertExpr, *ast.IndexExpr:
	default:
		return false
	}
	okName, isIdent := assign.Lhs[1].(*ast.Ident)
	if !isIdent {
		return false
	}
	for _, operand := range flattenAnd(ifStmt.Cond) {
		if ident, isIdent := ast.Unparen(operand).(*ast.Ident); isIdent && ident.Name == okName.Name {
			return true
		}
	}
	return false
}

// flattenAnd splits a && b && c into its operands.
func flattenAnd(expr ast.Expr) []ast.Expr {
	if bin, ok := ast.Unparen(expr).(*ast.BinaryExpr); ok && bin.Op == token.LAND {
		return append(flattenAnd(bin.X), flattenAnd(bin.Y)...)
	}
	return []ast.Expr{expr}
}

// isNilLogOnlyBranch reports if x == nil { t.Log(...) } else { ... }.
func isNilLogOnlyBranch(ifStmt *ast.IfStmt) bool {
	bin, ok := ast.Unparen(ifStmt.Cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL || !isNilIdent(bin.Y) || ifStmt.Else == nil || len(ifStmt.Body.List) == 0 {
		return false
	}
	for _, stmt := range ifStmt.Body.List {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok || !isTestLog(call) {
			return false
		}
	}
	return true
}

// isTestLog reports t.Log, t.Logf or a print.
func isTestLog(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "Log" || sel.Sel.Name == "Logf" || isFmtPrint(call) || helpers.IsLoggerCall(call)
}

// loopStatements returns the statements directly in the body of a loop.
func loopStatements(body *ast.BlockStmt) map[ast.Stmt]bool {
	inLoop := make(map[ast.Stmt]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		var loopBody *ast.BlockStmt
		switch loop := n.(type) {
		case *ast.RangeStmt:
			loopBody = loop.Body
		case *ast.ForStmt:
			loopBody = loop.Body
		}
		if loopBody != nil {
			for _, stmt := range loopBody.List {
				inLoop[stmt] = true
			}
		}
		return true
	})
	return inLoop
}

// containsValueAssertion reports a testify assertion on a value in the node:
// assert.Fail and a bare t.Error only report that the guard held.
func containsValueAssertion(node ast.Node, testify map[string]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name != "Fail" && sel.Sel.Name != "FailNow" {
			if pkg, ok := sel.X.(*ast.Ident); ok && testify[pkg.Name] {
				found = true
			}
		}
		return !found
	})
	return found
}

// containsGoAssertion reports a testify call or a t.Error/t.Fatal in the node.
func containsGoAssertion(node ast.Node, testify map[string]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && testify[pkg.Name] {
			found = true
		}
		switch sel.Sel.Name {
		case "Error", "Errorf", "Fatal", "Fatalf", "Fail", "FailNow":
			found = found || isTestingHandle(sel.X)
		}
		return !found
	})
	return found
}

// isTestingHandle reports t, b, tb or s.T().
func isTestingHandle(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e.Name == "t" || e.Name == "b" || e.Name == "tb" || e.Name == "tt"
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "T" && len(e.Args) == 0
	}
	return false
}

// skipCall returns a t.Skip, t.Skipf or t.SkipNow the branch makes.
func skipCall(body *ast.BlockStmt) *ast.CallExpr {
	for _, stmt := range body.List {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if ok && strings.HasPrefix(sel.Sel.Name, "Skip") && isTestingHandle(sel.X) {
			return call
		}
	}
	return nil
}

// isFailureCondition reports a condition that holds when the code under test
// failed: an error that is not nil (unless an environment probe returned it),
// a result that is nil, a status code that is not the expected one.
func isFailureCondition(ifStmt *ast.IfStmt, before ast.Stmt) bool {
	for _, operand := range flattenOr(ifStmt.Cond) {
		bin, ok := ast.Unparen(operand).(*ast.BinaryExpr)
		if !ok {
			continue
		}
		if bin.Op == token.NEQ && isNilIdent(bin.Y) {
			if ident, ok := bin.X.(*ast.Ident); ok && isErrorVarName(ident.Name) && !fromEnvironmentProbe(ident.Name, ifStmt.Init, before) {
				return true
			}
		}
		if bin.Op == token.EQL && isNilIdent(bin.Y) {
			// err == nil is the call that worked.
			if ident, ok := bin.X.(*ast.Ident); ok && !isErrorVarName(ident.Name) {
				return true
			}
		}
		if sel, ok := ast.Unparen(bin.X).(*ast.SelectorExpr); ok && sel.Sel.Name == "StatusCode" && bin.Op == token.NEQ {
			return true
		}
	}
	return false
}

// fromEnvironmentProbe reports an error the if's init or the statement before
// it took from an environment probe.
func fromEnvironmentProbe(errName string, stmts ...ast.Stmt) bool {
	for _, stmt := range stmts {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || !assignsName(assign, errName) {
			continue
		}
		if call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); ok && environmentProbes[helpers.ExprText(call.Fun)] {
			return true
		}
	}
	return false
}

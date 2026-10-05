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
//	for _, f := range fixtures { data, err := os.ReadFile(f); if err != nil { continue } ... }
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
	visitors := visitorBodies(ctx.GoAST)
	forEachFunction(ctx.GoAST, func(_ string, ftype *ast.FuncType, body *ast.BlockStmt) {
		inLoop := loopStatements(body)
		forEachOwnStatementList(body, func(list []ast.Stmt) {
			for i, stmt := range list {
				ifStmt, ok := stmt.(*ast.IfStmt)
				if !ok {
					continue
				}
				switch {
				// A guard in a loop or in a visitor filters the items the test
				// is about; a branch that only fails makes the guard the check,
				// and so does a failure the guard returns past. A helper that
				// returns from the guard and goes on with the other kind
				// dispatches by type.
				case ifStmt.Else == nil && !inLoop[ifStmt] && !visitors[body] && isCommaOkGuard(ifStmt) && containsValueAssertion(ifStmt.Body, testify) &&
					!failsPastGuard(body, ifStmt) && !dispatchesByKind(ftype, ifStmt):
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
				if errName := errNilCheckName(ifStmt.Cond); errName != "" && ifStmt.Else == nil && onlyContinues(ifStmt.Body) &&
					!fromEnvironmentProbe(errName, ifStmt.Init, before) && !hasCommentIn(ctx.GoAST, ifStmt.Body) {
					violations = append(violations, r.violation(ctx, ctx.LineFor(ifStmt),
						"The item that failed is skipped without a word — a broken fixture drops out of the check and the test stays green",
						"Fail the test on the error (t.Fatalf, require.NoError), or return it from the helper",
						"error_skipped"))
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

// visitorCalls are the calls that run their function argument once per item:
// a walk over a tree or a range over a collection.
var visitorCalls = map[string]bool{
	"Inspect": true, "Walk": true, "WalkDir": true, "Preorder": true, "Range": true, "ForEach": true, "Each": true,
}

// visitorBodies returns the bodies of the function literals passed to a
// visitor call.
func visitorBodies(file *ast.File) map[*ast.BlockStmt]bool {
	bodies := make(map[*ast.BlockStmt]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		case *ast.Ident:
			name = fun.Name
		}
		if !visitorCalls[name] {
			return true
		}
		for _, arg := range call.Args {
			if lit, ok := arg.(*ast.FuncLit); ok {
				bodies[lit.Body] = true
			}
		}
		return true
	})
	return bodies
}

// dispatchesByKind reports a guard of a function with results that returns
// from the guard: the code after it handles the values the guard does not
// take.
func dispatchesByKind(ftype *ast.FuncType, guard *ast.IfStmt) bool {
	return ftype.Results != nil && len(ftype.Results.List) > 0 && terminatesBlock(guard.Body)
}

// failsPastGuard reports a guard that returns when the value is there and
// falls through to a test failure when it is not.
func failsPastGuard(body *ast.BlockStmt, guard *ast.IfStmt) bool {
	return terminatesBlock(guard.Body) && failsAfter(body, guard)
}

// terminatesBlock reports a block that ends in a return, at its end or at
// the end of the last guard in it.
func terminatesBlock(block *ast.BlockStmt) bool {
	if len(block.List) == 0 {
		return false
	}
	switch last := block.List[len(block.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.IfStmt:
		return last.Else == nil && terminatesBlock(last.Body)
	}
	return false
}

// failsAfter reports a test failure (t.Fatalf, t.Errorf, require.Fail) the
// function reaches after the statement, outside it.
func failsAfter(body *ast.BlockStmt, stmt ast.Stmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || call.Pos() < stmt.End() {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if failingTestMethods[sel.Sel.Name] {
			found = isTestingHandle(sel.X) || helpers.ExprText(sel.X) == "require" || helpers.ExprText(sel.X) == "assert"
		}
		return !found
	})
	return found
}

// onlyContinues reports a branch that is a bare continue.
func onlyContinues(body *ast.BlockStmt) bool {
	if len(body.List) != 1 {
		return false
	}
	branch, ok := body.List[0].(*ast.BranchStmt)
	return ok && branch.Tok == token.CONTINUE
}

// hasCommentIn reports a comment inside a block: the author saying why.
func hasCommentIn(file *ast.File, block *ast.BlockStmt) bool {
	for _, group := range file.Comments {
		if group.Pos() > block.Lbrace && group.End() < block.Rbrace {
			return true
		}
	}
	return false
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

// loopStatements returns the statements anywhere in the body of a loop, out
// of the function literals in it.
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
			ast.Inspect(loopBody, func(m ast.Node) bool {
				if _, isLit := m.(*ast.FuncLit); isLit {
					return false
				}
				if stmt, ok := m.(ast.Stmt); ok {
					inLoop[stmt] = true
				}
				return true
			})
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
		if failingTestMethods[sel.Sel.Name] {
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

package qarules

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() { rules.Register(NewTestWithoutParallelRule()) }

// TestWithoutParallelRule requires opted-in Go tests to start with t.Parallel.
type TestWithoutParallelRule struct {
	*rules.BaseRule
	require bool
}

// NewTestWithoutParallelRule creates the opt-in rule.
func NewTestWithoutParallelRule() *TestWithoutParallelRule {
	return &TestWithoutParallelRule{BaseRule: rules.NewBaseRule(
		"test-without-parallel", "patterns",
		"Detects Go tests that do not call t.Parallel() as their first statement",
		core.SeverityLow,
	)}
}

// Configure enables the rule only when require is explicitly true.
func (r *TestWithoutParallelRule) Configure(settings map[string]any) error {
	require, _, err := rules.BoolSetting(settings, r.Name(), "require")
	if err != nil {
		return err
	}
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.require = require
	return nil
}

// AnalyzeFile reports tests whose first statement is not t.Parallel().
func (r *TestWithoutParallelRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !r.require || ctx == nil || !ctx.IsGoFile() || !ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	testingPkgs := testingImportNames(ctx.GoAST)
	if len(testingPkgs) == 0 {
		return nil
	}
	osPkgs := helpers.PackageAliases(ctx.GoAST, `"os"`, "os")
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || goTestFuncKind(fn, testingPkgs) != goTestCase ||
			len(fn.Type.Params.List[0].Names) != 1 {
			continue
		}
		param := fn.Type.Params.List[0].Names[0].Name
		if len(fn.Body.List) == 0 || firstStatementIsParallel(fn.Body.List[0], param) ||
			testChangesProcessState(fn.Body, param, osPkgs) {
			continue
		}
		pos := ctx.PositionFor(fn)
		if ctx.LineSuppresses(pos.Line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Test '"+fn.Name.Name+"' does not call t.Parallel() as its first statement")
		v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
		v.WithSuggestion("Add t.Parallel() as the first statement, or add a glint exclusion with a reason")
		violations = append(violations, v)
	}
	return violations
}

func firstStatementIsParallel(stmt ast.Stmt, param string) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Parallel" {
		return false
	}
	receiver, ok := sel.X.(*ast.Ident)
	return ok && receiver.Name == param
}

func testChangesProcessState(body *ast.BlockStmt, param string, osPkgs map[string]bool) bool {
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
		if receiver, ok := sel.X.(*ast.Ident); ok && receiver.Name == param &&
			(sel.Sel.Name == "Setenv" || sel.Sel.Name == "Chdir") {
			found = true
			return false
		}
		if sel.Sel.Name == "Chdir" {
			if pkg, ok := sel.X.(*ast.Ident); ok && osPkgs[pkg.Name] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

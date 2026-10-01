package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewResponseHelperResultIgnoredRule())
}

// ResponseHelperResultIgnoredRule detects a dropped answer of a helper that
// writes the HTTP response itself and reports with a bool whether the handler
// may go on:
//
//	_ = ParseJSON(w, req, &body) // on bad input ParseJSON already wrote 400
//	process(body)                // ... and the handler writes a second response
//
// The helper's false means "the response is written, stop". A handler that
// ignores it runs on with an empty value and writes again: the client gets
// the first status, the log gets "superfluous WriteHeader", and the work
// meant for valid input runs on invalid input.
//
// A call the function ends with is not reported: nothing follows it that
// could write again.
type ResponseHelperResultIgnoredRule struct {
	*rules.BaseRule
}

// NewResponseHelperResultIgnoredRule creates the rule
func NewResponseHelperResultIgnoredRule() *ResponseHelperResultIgnoredRule {
	return &ResponseHelperResultIgnoredRule{BaseRule: rules.NewBaseRule(
		"response-helper-result-ignored",
		"patterns",
		"Detects a dropped bool of a helper that writes the HTTP response itself — the handler goes on after the error response is written",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the helper's signature needs types.
func (r *ResponseHelperResultIgnoredRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ResponseHelperResultIgnoredRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the calls whose bool answer is dropped.
func (r *ResponseHelperResultIgnoredRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if file.IsTestFile() {
			return nil
		}
		tail := tailStatements(file.GoAST)
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			if stmt, ok := n.(ast.Stmt); ok && tail[stmt] {
				return true
			}
			var call *ast.CallExpr
			switch stmt := n.(type) {
			case *ast.ExprStmt:
				call, _ = ast.Unparen(stmt.X).(*ast.CallExpr)
			case *ast.AssignStmt:
				if len(stmt.Lhs) == 1 && len(stmt.Rhs) == 1 && isIdentNamed(stmt.Lhs[0], "_") {
					call, _ = ast.Unparen(stmt.Rhs[0]).(*ast.CallExpr)
				}
			}
			if call == nil || !writesResponseAndAnswersBool(info, call) {
				return true
			}
			line := file.LineFor(call)
			if file.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(file.RelPath, line, "The answer of "+types.ExprString(call.Fun)+" is dropped — it writes the error response itself and says false, and the handler goes on to write a second one")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Return from the handler when the helper answers false: if !" + types.ExprString(call.Fun) + "(...) { return }")
			violations = append(violations, v)
			return true
		})
		return violations
	})
}

// writesResponseAndAnswersBool reports a call of a function that takes an
// http.ResponseWriter and returns a single bool.
func writesResponseAndAnswersBool(info *types.Info, call *ast.CallExpr) bool {
	sig, ok := types.Unalias(info.TypeOf(call.Fun)).(*types.Signature)
	if !ok || sig.Results().Len() != 1 {
		return false
	}
	result, ok := sig.Results().At(0).Type().Underlying().(*types.Basic)
	if !ok || result.Kind() != types.Bool {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if isNamedType(sig.Params().At(i).Type(), "net/http", "ResponseWriter") {
			return true
		}
	}
	return false
}

// tailStatements returns the statements a function ends with: the last
// statement of its body, and of the branches of an if, switch or select
// that is itself last. A loop body is never last — the loop goes on.
func tailStatements(file *ast.File) map[ast.Stmt]bool {
	tail := map[ast.Stmt]bool{}
	var markList func(list []ast.Stmt)
	markList = func(list []ast.Stmt) {
		if len(list) == 0 {
			return
		}
		last := list[len(list)-1]
		tail[last] = true
		switch stmt := last.(type) {
		case *ast.BlockStmt:
			markList(stmt.List)
		case *ast.IfStmt:
			markList(stmt.Body.List)
			switch els := stmt.Else.(type) {
			case *ast.BlockStmt:
				markList(els.List)
			case *ast.IfStmt:
				markList([]ast.Stmt{els})
			}
		case *ast.SwitchStmt:
			markClauses(stmt.Body, markList)
		case *ast.TypeSwitchStmt:
			markClauses(stmt.Body, markList)
		case *ast.SelectStmt:
			markClauses(stmt.Body, markList)
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body != nil {
				markList(fn.Body.List)
			}
		case *ast.FuncLit:
			markList(fn.Body.List)
		}
		return true
	})
	return tail
}

// markClauses marks the tails of the clauses of a switch or select.
func markClauses(body *ast.BlockStmt, markList func([]ast.Stmt)) {
	for _, clause := range body.List {
		switch c := clause.(type) {
		case *ast.CaseClause:
			markList(c.Body)
		case *ast.CommClause:
			markList(c.Body)
		}
	}
}

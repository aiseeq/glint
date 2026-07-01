package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewLogAndReturnZeroRule())
}

// LogAndReturnZeroRule detects functions without an error result that log at
// Error/Warn level and immediately return a zero value:
//
//	func (m *TokenManager) getJWTIssuer() string {
//	    if m.config == nil {
//	        m.logger.Error("Configuration not available")
//	        return "" // empty issuer breaks validation much later
//	    }
//	    ...
//	}
//
// The log acknowledges a failure, but the caller receives a sentinel ("" / 0
// / nil) indistinguishable from a valid value. CLAUDE.md: a function that can
// fail must return (T, error).
//
// Not flagged: Info/Debug logs, `return false` (see
// error-masked-as-false-bool), computed recovery values, and HTTP handlers
// (they report the failure via ResponseWriter).
type LogAndReturnZeroRule struct {
	*rules.BaseRule
}

// NewLogAndReturnZeroRule creates the rule
func NewLogAndReturnZeroRule() *LogAndReturnZeroRule {
	return &LogAndReturnZeroRule{
		BaseRule: rules.NewBaseRule(
			"log-and-return-zero",
			"patterns",
			"Detects Error/Warn log followed by a zero-value return in functions without an error result",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks Go functions for the log-then-zero pattern
func (r *LogAndReturnZeroRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		if !hasNonErrorResults(fn.Type.Results) || hasResponseWriterParam(fn.Type.Params) {
			return true
		}

		forEachOwnStatementList(fn.Body, func(list []ast.Stmt) {
			for i := 0; i+1 < len(list); i++ {
				if !isErrorOrWarnLogStmt(list[i]) {
					continue
				}
				ret, ok := list[i+1].(*ast.ReturnStmt)
				if !ok || !allResultsAreZeroValues(ret) {
					continue
				}
				pos := ctx.PositionFor(ret)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Error/Warn log followed by a zero-value return — the caller cannot distinguish this failure from a valid value")
				v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
				v.WithSuggestion("Change the signature to (T, error) and return an explicit error instead of the zero sentinel")
				violations = append(violations, v)
			}
		})

		return true
	})

	return violations
}

// hasNonErrorResults reports whether the function returns at least one value
// and none of the results is the builtin error type.
func hasNonErrorResults(results *ast.FieldList) bool {
	if results == nil || len(results.List) == 0 {
		return false
	}
	for _, field := range results.List {
		if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "error" {
			return false
		}
	}
	return true
}

// hasResponseWriterParam reports whether any parameter is an
// http.ResponseWriter — such functions report failures via the response.
func hasResponseWriterParam(params *ast.FieldList) bool {
	if params == nil {
		return false
	}
	for _, field := range params.List {
		if sel, ok := field.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "ResponseWriter" {
			return true
		}
	}
	return false
}

// forEachOwnStatementList visits every statement list (blocks, case bodies)
// of the function body, pruning nested function literals.
func forEachOwnStatementList(body *ast.BlockStmt, visit func([]ast.Stmt)) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.BlockStmt:
			visit(node.List)
		case *ast.CaseClause:
			visit(node.Body)
		case *ast.CommClause:
			visit(node.Body)
		}
		return true
	})
}

// isErrorOrWarnLogStmt reports whether the statement is a bare Error/Warn
// logger call.
func isErrorOrWarnLogStmt(stmt ast.Stmt) bool {
	exprStmt, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	return ok && isErrorOrWarnLogCall(call)
}

// allResultsAreZeroValues reports whether every returned expression is a zero
// sentinel: "", 0, nil, or an empty composite literal. A lone `false` is left
// to the error-masked-as-false-bool rule.
func allResultsAreZeroValues(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false
	}
	for _, expr := range ret.Results {
		if !isZeroValueExpr(expr) {
			return false
		}
	}
	return true
}

// isZeroValueExpr matches "", 0, 0.0, nil and empty composite literals.
func isZeroValueExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Value == `""` || e.Value == "0" || e.Value == "0.0" || e.Value == "``"
	case *ast.Ident:
		return e.Name == "nil"
	case *ast.CompositeLit:
		return len(e.Elts) == 0
	}
	return false
}

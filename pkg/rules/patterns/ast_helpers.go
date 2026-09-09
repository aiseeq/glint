package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
)

// analyzeGoFunctions runs check over every function body of a Go source file
// and collects what it reports. Rules that work per function share this guard:
// non-Go files, tests and files that failed to parse have nothing to analyze.
func analyzeGoFunctions(ctx *core.FileContext, check func(*ast.FuncDecl) []*core.Violation) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		violations = append(violations, check(fn)...)
	}
	return violations
}

// isNilIdent reports whether the expression is the nil identifier.
func isNilIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}

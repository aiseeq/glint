package patterns

import (
	"fmt"
	"go/ast"
	"go/types"

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

// forEachTypedFuncDecl visits every function with a body in the typed syntax
// of the project's packages, test files included, with its package's types;
// obj is nil for a declaration the type checker did not define.
func forEachTypedFuncDecl(ctx *core.GoProjectContext, visit func(info *types.Info, fn *ast.FuncDecl, obj *types.Func)) error {
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return fmt.Errorf("package has no typed syntax")
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				obj, _ := info.Defs[fn.Name].(*types.Func)
				visit(info, fn, obj)
			}
		}
	}
	return nil
}

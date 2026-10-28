package patternkit

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// RequestParameterNames collects *http.Request parameters: the caller built
// them, so the loop cannot rebuild them either.
func RequestParameterNames(file *ast.File, info *types.Info, funcType *ast.FuncType) map[string]bool {
	names := make(map[string]bool)
	if funcType == nil || funcType.Params == nil {
		return names
	}
	for _, param := range funcType.Params.List {
		if !isHTTPRequestPointerType(file, info, param.Type) {
			continue
		}
		for _, name := range param.Names {
			if name.Name != "_" {
				names[name.Name] = true
			}
		}
	}
	return names
}

// isHTTPRequestPointerType reports whether a type expression is *http.Request:
// by type when info is available, otherwise by the file's import of net/http.
func isHTTPRequestPointerType(file *ast.File, info *types.Info, expr ast.Expr) bool {
	if info != nil {
		return IsPointerToNamedType(info.TypeOf(expr), "net/http", "Request")
	}
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Request" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && helpers.PackageAliases(file, `"net/http"`, "http")[pkg.Name]
}

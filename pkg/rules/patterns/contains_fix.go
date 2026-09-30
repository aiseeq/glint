package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// exactContainsSearch reports whether the helper is exactly
//
//	for _, x := range collection { if x == target { return true } }; return false
//
// over two of its own parameters, with a slice collection whose comparable
// element type is identical to the target's type, in a Go 1.21+ file where
// slices names the standard package. Only then does
// `return slices.Contains(collection, target)` compile and compare the same
// way; it returns the two parameter names for the fixer. The rule reports more
// shapes than this: the rest are left to a human.
func exactContainsSearch(ctx *core.FileContext, fn *ast.FuncDecl, info *types.Info, versions *helpers.GoVersions) (collection, target string, ok bool) {
	if info == nil || versions == nil || len(fn.Body.List) != 2 {
		return "", "", false
	}
	loop, ok := fn.Body.List[0].(*ast.RangeStmt)
	if !ok || loop.Tok != token.DEFINE || (loop.Key != nil && !isIdent(loop.Key, "_")) {
		return "", "", false
	}
	element, ok := loop.Value.(*ast.Ident)
	if !ok || len(loop.Body.List) != 1 {
		return "", "", false
	}
	check, ok := loop.Body.List[0].(*ast.IfStmt)
	if !ok || check.Init != nil || check.Else != nil {
		return "", "", false
	}
	comparison, ok := check.Cond.(*ast.BinaryExpr)
	if !ok || comparison.Op != token.EQL {
		return "", "", false
	}
	var other ast.Expr
	switch {
	case isIdent(comparison.X, element.Name):
		other = comparison.Y
	case isIdent(comparison.Y, element.Name):
		other = comparison.X
	default:
		return "", "", false
	}

	collectionIdent, ok := loop.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	targetIdent, ok := other.(*ast.Ident)
	if !ok || targetIdent.Name == collectionIdent.Name {
		return "", "", false
	}
	if !isParameter(fn, collectionIdent, info) || !isParameter(fn, targetIdent, info) {
		return "", "", false
	}

	slice, ok := info.TypeOf(collectionIdent).Underlying().(*types.Slice)
	if !ok {
		return "", "", false
	}
	targetType := info.TypeOf(targetIdent)
	if targetType == nil || !types.Identical(slice.Elem(), targetType) || !types.Comparable(slice.Elem()) {
		return "", "", false
	}
	if !versions.AtLeast(ctx, info, "go1.21") || !namesStdlibPackages(ctx.GoAST, fn.Body.Pos(), info, "slices") {
		return "", "", false
	}
	return collectionIdent.Name, targetIdent.Name, true
}

// isParameter reports whether the identifier refers to a parameter of fn.
func isParameter(fn *ast.FuncDecl, ident *ast.Ident, info *types.Info) bool {
	variable, ok := info.Uses[ident].(*types.Var)
	return ok && fn.Type.Params != nil &&
		variable.Pos() >= fn.Type.Params.Pos() && variable.Pos() < fn.Type.Params.End()
}

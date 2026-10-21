package helpers

import (
	"go/ast"
	"go/token"
	"go/types"
)

// IsNilIdent reports the nil identifier, parentheses aside.
func IsNilIdent(expr ast.Expr) bool {
	return IsIdentNamed(expr, "nil")
}

// IsIdentNamed reports an identifier of the given name, parentheses aside.
func IsIdentNamed(expr ast.Expr, name string) bool {
	ident := IdentOf(expr)
	return ident != nil && ident.Name == name
}

// IdentOf returns the expression as an identifier, parentheses aside, or nil.
func IdentOf(expr ast.Expr) *ast.Ident {
	ident, _ := ast.Unparen(expr).(*ast.Ident)
	return ident
}

// IsStringLit reports a string literal, parentheses aside.
func IsStringLit(expr ast.Expr) bool {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// ExprName returns the last name of an identifier or a selector (pkg.F,
// x.y.Method), parentheses aside, or "".
func ExprName(expr ast.Expr) string {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// CalleeName returns the name a call calls by (F of pkg.F or x.F), or "".
func CalleeName(call *ast.CallExpr) string {
	if call == nil {
		return ""
	}
	return ExprName(call.Fun)
}

// CalledFunc returns the function or method a call resolves to, an
// instantiated generic (F[int](x)) included, or nil for a call of a func
// value, a conversion or a builtin.
func CalledFunc(call *ast.CallExpr, info *types.Info) *types.Func {
	var ident *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		ident = fun
	case *ast.SelectorExpr:
		ident = fun.Sel
	case *ast.IndexExpr:
		return CalledFunc(&ast.CallExpr{Fun: fun.X}, info)
	case *ast.IndexListExpr:
		return CalledFunc(&ast.CallExpr{Fun: fun.X}, info)
	default:
		return nil
	}
	fn, _ := info.Uses[ident].(*types.Func)
	return fn
}

// ConcatOperands flattens a chain of + into its operands, each without its
// parentheses: a + (b + c) gives a, b, c.
func ConcatOperands(expr ast.Expr) []ast.Expr {
	sum, ok := ast.Unparen(expr).(*ast.BinaryExpr)
	if !ok || sum.Op != token.ADD {
		return []ast.Expr{ast.Unparen(expr)}
	}
	return append(ConcatOperands(sum.X), ConcatOperands(sum.Y)...)
}

// DerefType returns the element type of a pointer, aliases aside, and any
// other type as it is.
func DerefType(t types.Type) types.Type {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		return ptr.Elem()
	}
	return t
}

// IsContextType reports context.Context, aliases aside.
func IsContextType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "context" && named.Obj().Name() == "Context"
}

// ReceiverTypeExported reports a method receiver whose base type is exported.
func ReceiverTypeExported(recv *ast.FieldList) bool {
	return recv != nil && len(recv.List) > 0 && ast.IsExported(ReceiverTypeName(recv.List[0].Type))
}

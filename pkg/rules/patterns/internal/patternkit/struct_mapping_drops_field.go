package patternkit

import (
	"go/ast"
	"go/token"
	"go/types"
)

type StructTarget struct {
	Fields *types.Struct
	Pkg    *types.Package
}

// StructOf returns the struct of a named struct type, through a pointer.
func StructOf(t types.Type) (StructTarget, bool) {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return StructTarget{}, false
	}
	st, ok := named.Underlying().(*types.Struct)
	return StructTarget{Fields: st, Pkg: named.Obj().Pkg()}, ok
}

// CopiedField returns the field selection a value copies: src.X, through
// a conversion or a call on it alone (string(src.X), ptr(src.X)), &src.X
// or *src.X.
func CopiedField(expr ast.Expr, info *types.Info) (*ast.SelectorExpr, bool) {
	for {
		switch e := ast.Unparen(expr).(type) {
		case *ast.UnaryExpr:
			if e.Op != token.AND {
				return nil, false
			}
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.CallExpr:
			if len(e.Args) != 1 {
				return nil, false
			}
			expr = e.Args[0]
		case *ast.SelectorExpr:
			selection, ok := info.Selections[e]
			return e, ok && selection.Kind() == types.FieldVal
		default:
			return nil, false
		}
	}
}

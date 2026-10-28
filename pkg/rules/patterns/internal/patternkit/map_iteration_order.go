package patternkit

import (
	"go/ast"
	"go/types"
	"strings"
)

// IsErrorConstruction recognizes the calls that build an error value.
func IsErrorConstruction(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "errors" {
		return true
	}
	switch selector.Sel.Name {
	case "Errorf", "Error", "Wrap", "Wrapf":
		return true
	}
	return strings.HasPrefix(selector.Sel.Name, "Err")
}

// RootIdent returns the identifier a selector chain starts from: entry in
// entry.ID, nil for anything that is not a chain of selectors.
func RootIdent(expr ast.Expr) *ast.Ident {
	for {
		switch node := ast.Unparen(expr).(type) {
		case *ast.SelectorExpr:
			expr = node.X
		case *ast.Ident:
			return node
		default:
			return nil
		}
	}
}

// IsStringType reports whether t is a string type, named or not.
func IsStringType(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsString != 0
}

// Mentions reports whether the expression reads the named variable.
func Mentions(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

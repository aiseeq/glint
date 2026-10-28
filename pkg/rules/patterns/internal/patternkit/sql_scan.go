package patternkit

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

// SqlxReadArgs is sqlxRead for any typed call.
func SqlxReadArgs(info *types.Info, call *ast.CallExpr) (int, int, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, 0, false
	}
	switch sel.Sel.Name {
	case "Get", "Select", "GetContext", "SelectContext":
	default:
		return 0, 0, false
	}
	if inner, ok := ast.Unparen(sel.X).(*ast.CallExpr); ok {
		if innerSel, ok := inner.Fun.(*ast.SelectorExpr); ok && innerSel.Sel.Name == "Unsafe" {
			return 0, 0, false // Unsafe ignores the columns the struct lacks
		}
	}
	sig, ok := info.TypeOf(call.Fun).(*types.Signature)
	if !ok || !sig.Variadic() || sig.Params().Len() < 3 || sig.Results().Len() != 1 {
		return 0, 0, false
	}
	params := sig.Params()
	destIdx, queryIdx := params.Len()-3, params.Len()-2
	if !types.IsInterface(params.At(destIdx).Type()) || !IsStringType(params.At(queryIdx).Type()) || len(call.Args) <= queryIdx {
		return 0, 0, false
	}
	return destIdx, queryIdx, true
}

// DefiningValue returns the value a local variable is declared with: x :=
// value, var x = value.
func DefiningValue(fn *ast.FuncDecl, info *types.Info, ident *ast.Ident) ast.Expr {
	obj := info.Uses[ident]
	if obj == nil {
		return nil
	}
	var value ast.Expr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if value != nil {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok != token.DEFINE || len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && info.Defs[id] == obj {
					value = node.Rhs[i]
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if info.Defs[name] == obj && i < len(node.Values) {
					value = node.Values[i]
				}
			}
		}
		return true
	})
	if value == nil {
		// x, err := db.Query(...): the first value of a call.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || assign.Tok != token.DEFINE || len(assign.Rhs) != 1 || value != nil {
				return value == nil
			}
			if id, ok := assign.Lhs[0].(*ast.Ident); ok && info.Defs[id] == obj {
				value = assign.Rhs[0]
			}
			return true
		})
	}
	return value
}

// TypeName writes a type without package paths: models.Investment is
// Investment.
func TypeName(typ types.Type) string {
	return types.TypeString(typ, func(*types.Package) string { return "" })
}

// SnakeCase spells a Go name the way a column is: ChannelName is
// channel_name, UserID is user_id.
func SnakeCase(name string) string {
	var b strings.Builder
	runes := []rune(name)
	for i, r := range runes {
		upper := r >= 'A' && r <= 'Z'
		if upper && i > 0 {
			prevLower := runes[i-1] >= 'a' && runes[i-1] <= 'z' || runes[i-1] >= '0' && runes[i-1] <= '9'
			nextLower := i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z'
			if prevLower || (nextLower && runes[i-1] >= 'A' && runes[i-1] <= 'Z') {
				b.WriteByte('_')
			}
		}
		b.WriteString(strings.ToLower(string(r)))
	}
	return b.String()
}

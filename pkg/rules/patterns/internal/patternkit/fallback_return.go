package patternkit

import (
	"go/ast"
)

// IsZeroLiteral reports "", 0, nil.
func IsZeroLiteral(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return e.Value == `""` || e.Value == "0" || e.Value == "``"
	case *ast.Ident:
		return e.Name == "nil"
	}
	return false
}

// IsFmtPrint reports fmt.Print, Printf or Println.
func IsFmtPrint(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "fmt" && (sel.Sel.Name == "Print" || sel.Sel.Name == "Printf" || sel.Sel.Name == "Println")
}

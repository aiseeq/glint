package patternkit

import (
	"go/ast"
	"go/constant"
	"go/types"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// IsTimeNowCall reports time.Now().
func IsTimeNowCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Now" && helpers.IsIdentNamed(sel.X, "time")
}

// DateOnlyLayout reports a constant layout with a year and no time of day:
// "2006-01-02", time.DateOnly, "02.01.2006".
func DateOnlyLayout(info *types.Info, expr ast.Expr) bool {
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	return isDateOnlyLayout(constant.StringVal(tv.Value))
}

// DateOnlyLayoutSyntax is dateOnlyLayout without types: a string literal or
// time.DateOnly.
func DateOnlyLayoutSyntax(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		layout, err := strconv.Unquote(e.Value)
		return err == nil && isDateOnlyLayout(layout)
	case *ast.SelectorExpr:
		return e.Sel.Name == "DateOnly" && helpers.IsIdentNamed(e.X, "time")
	}
	return false
}

func isDateOnlyLayout(layout string) bool {
	return strings.Contains(layout, "2006") && !strings.Contains(layout, "15") && !strings.Contains(layout, "04")
}

// SingleDefinitions maps the local variables of a body defined once (v :=
// expr, var v = expr) and never assigned again to that expression.
func SingleDefinitions(info *types.Info, body *ast.BlockStmt) map[types.Object]ast.Expr {
	defs := make(map[types.Object]ast.Expr)
	assigned := make(map[types.Object]int)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				obj := info.ObjectOf(ident)
				assigned[obj]++
				if len(node.Lhs) == len(node.Rhs) {
					defs[obj] = node.Rhs[i]
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				obj := info.ObjectOf(name)
				assigned[obj]++
				if len(node.Names) == len(node.Values) {
					defs[obj] = node.Values[i]
				}
			}
		}
		return true
	})
	for obj, count := range assigned {
		if count != 1 {
			delete(defs, obj)
		}
	}
	return defs
}

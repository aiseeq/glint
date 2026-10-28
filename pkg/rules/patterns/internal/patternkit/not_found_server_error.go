package patternkit

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// HandlerRequestParam returns the *http.Request parameter of a function that
// also takes an http.ResponseWriter, nil for anything else.
func HandlerRequestParam(fn TypedFunc) *types.Var {
	obj, ok := fn.Info.Defs[fn.Decl.Name].(*types.Func)
	if !ok {
		return nil
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok {
		return nil
	}
	writer := false
	var request *types.Var
	for v := range sig.Params().Variables() {
		switch types.TypeString(v.Type(), nil) {
		case "net/http.ResponseWriter":
			writer = true
		case "*net/http.Request":
			request = v
		}
	}
	if !writer {
		return nil
	}
	return request
}

// ResponderName is a library function handed the request only to answer it.
var ResponderName = regexp.MustCompile(`^(?:Send|send|Write|write|Respond|respond|Render|render|Log|log|Error|error)`)

// ErrNotNilIdent returns err of a condition `err != nil`.
func ErrNotNilIdent(info *types.Info, cond ast.Expr) *ast.Ident {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ || !helpers.IsNilIdent(ast.Unparen(bin.Y)) {
		return nil
	}
	ident, ok := ast.Unparen(bin.X).(*ast.Ident)
	if !ok || !ImplementsError(info.TypeOf(ident)) {
		return nil
	}
	return ident
}

// IsStatusExpr reports an http.Status* constant or a bare integer literal.
func IsStatusExpr(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		return strings.HasPrefix(e.Sel.Name, "Status")
	case *ast.BasicLit:
		return e.Kind == token.INT
	}
	return false
}

// ComparesError reports a branch that tells errors apart: errors.Is or
// errors.As, or a comparison with a sentinel.
func ComparesError(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && helpers.IsIdentNamed(sel.X, "errors") && (sel.Sel.Name == "Is" || sel.Sel.Name == "As") {
				found = true
			}
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				if ident, ok := ast.Unparen(node.Y).(*ast.Ident); ok && SentinelName(ident.Name) {
					found = true
				}
				if sel, ok := ast.Unparen(node.Y).(*ast.SelectorExpr); ok && SentinelName(sel.Sel.Name) {
					found = true
				}
				if fieldComparison(node.X, node.Y) || fieldComparison(node.Y, node.X) {
					found = true
				}
			}
		case *ast.SwitchStmt:
			if isClassificationField(node.Tag) {
				found = true
			}
		}
		return !found
	})
	return found
}

func fieldComparison(left, right ast.Expr) bool {
	if !isClassificationField(left) {
		return false
	}
	switch ast.Unparen(right).(type) {
	case *ast.BasicLit, *ast.Ident, *ast.SelectorExpr:
		return true
	}
	return false
}

func isClassificationField(expr ast.Expr) bool {
	selector, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch selector.Sel.Name {
	case "Code", "Status", "StatusCode", "Kind":
		return true
	}
	return false
}

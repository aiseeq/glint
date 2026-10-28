package patternkit

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// UnmarshalDataParam returns the name of the []byte parameter.
func UnmarshalDataParam(fn *ast.FuncDecl) string {
	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 {
		return ""
	}
	return params[0].Names[0].Name
}

// StringLocals returns the names declared as var x string.
func StringLocals(body *ast.BlockStmt) map[string]bool {
	names := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Values) != 0 {
			return true
		}
		if typ, ok := spec.Type.(*ast.Ident); ok && typ.Name == "string" {
			for _, name := range spec.Names {
				names[name.Name] = true
			}
		}
		return true
	})
	return names
}

// FailsOutsideErrCheck reports a return of a non-nil error that is not
// inside an if err != nil branch: a rejection of the decoded value.
func FailsOutsideErrCheck(body *ast.BlockStmt) bool {
	found := false
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			if IsErrNotNil(node.Cond) {
				if node.Init != nil {
					ast.Inspect(node.Init, walk)
				}
				if node.Else != nil {
					ast.Inspect(node.Else, walk)
				}
				return false
			}
		case *ast.ReturnStmt:
			if len(node.Results) == 1 && !helpers.IsIdentNamed(node.Results[0], "nil") {
				found = true
			}
		}
		return true
	}
	ast.Inspect(body, walk)
	return found
}

// IsErrNotNil reports a condition err != nil.
func IsErrNotNil(cond ast.Expr) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ || !helpers.IsIdentNamed(bin.Y, "nil") {
		return false
	}
	id, ok := bin.X.(*ast.Ident)
	return ok && strings.HasPrefix(strings.ToLower(id.Name), "err")
}

// IsSelectorCall reports pkg.name(...) by the spelling of the call.
func IsSelectorCall(call *ast.CallExpr, pkg, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == name && helpers.IsIdentNamed(sel.X, pkg)
}

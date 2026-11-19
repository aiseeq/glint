package patternkit

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"strconv"
	"strings"
)

// sqlFolder uses parser object identities for lexical scope. Only locals whose
// declaration is their sole write and whose address never escapes are folded.
type sqlFolder struct {
	initLocals func()
	imports    map[string]string
	locals     map[any]bool
	unsafe     map[any]bool
}

func newSQLFolder(root ast.Node) *sqlFolder {
	f := &sqlFolder{}
	f.initLocals = func() { f.collectRootLocals(root) }
	if file, ok := root.(*ast.File); ok {
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || (path != "fmt" && path != "strings") {
				continue
			}
			name := path
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if name != "." && name != "_" {
				if f.imports == nil {
					f.imports = make(map[string]string)
				}
				f.imports[name] = path
			}
		}
	}
	return f
}

// Locals only matter when a candidate string actually references a variable.
func (f *sqlFolder) collectRootLocals(root ast.Node) {
	if f.locals != nil {
		return
	}
	f.locals = make(map[any]bool)
	f.unsafe = make(map[any]bool)
	ast.Inspect(root, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncDecl:
			if n.Body != nil {
				f.collectLocals(n.Body)
			}
			return false
		case *ast.FuncLit:
			f.collectLocals(n.Body)
			return false
		}
		return true
	})
	// Callers sometimes pass a function body rather than a whole file.
	if body, ok := root.(*ast.BlockStmt); ok {
		f.collectLocals(body)
	}
}

func (f *sqlFolder) collectLocals(body *ast.BlockStmt) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				f.write(lhs, n)
			}
		case *ast.ValueSpec:
			for _, id := range n.Names {
				if id.Obj != nil && id.Obj.Kind == ast.Var {
					f.locals[id.Obj] = true
				}
			}
		case *ast.RangeStmt:
			if n.Key != nil {
				f.markUnsafe(n.Key)
			}
			if n.Value != nil {
				f.markUnsafe(n.Value)
			}
		case *ast.IncDecStmt:
			f.markUnsafe(n.X)
		case *ast.UnaryExpr:
			if n.Op == token.AND {
				f.markUnsafe(n.X)
			}
		}
		return true
	})
}

func (f *sqlFolder) write(expr ast.Expr, decl *ast.AssignStmt) {
	id, ok := expr.(*ast.Ident)
	if !ok || id.Obj == nil {
		f.markUnsafe(expr)
		return
	}
	if decl.Tok == token.DEFINE && id.Obj.Decl == decl {
		f.locals[id.Obj] = true
		return
	}
	f.unsafe[id.Obj] = true
}

func (f *sqlFolder) markUnsafe(expr ast.Expr) {
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Obj != nil {
			f.unsafe[id.Obj] = true
		}
		return true
	})
}

func (f *sqlFolder) value(id *ast.Ident) ast.Expr {
	if id.Obj == nil {
		return nil
	}
	if id.Obj.Kind == ast.Var {
		// Parameters, results and range variables cannot be a foldable local.
		switch id.Obj.Decl.(type) {
		case *ast.AssignStmt, *ast.ValueSpec:
		default:
			return nil
		}
		f.initLocals()
		if !f.locals[id.Obj] || f.unsafe[id.Obj] {
			return nil
		}
	} else if id.Obj.Kind != ast.Con {
		return nil
	}
	return DeclaredValue(id)
}

func (f *sqlFolder) isCall(expr ast.Expr) bool {
	if len(f.imports) == 0 {
		return false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Join" && sel.Sel.Name != "Sprintf") {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Obj != nil {
		return false
	}
	return (f.imports[id.Name] == "strings" && sel.Sel.Name == "Join") || (f.imports[id.Name] == "fmt" && sel.Sel.Name == "Sprintf")
}

func (f *sqlFolder) stringValue(expr ast.Expr, depth int) (string, bool) {
	pieces, ok := constSQLStringPieces(expr, f, depth+1)
	var b strings.Builder
	for _, piece := range pieces {
		b.WriteString(piece.text)
	}
	return b.String(), ok
}

func (f *sqlFolder) call(call *ast.CallExpr, depth int) ([]sqlStringPiece, bool) {
	if !f.isCall(call) || len(call.Args) == 0 || depth > 20 {
		return nil, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	var value string
	if sel.Sel.Name == "Join" {
		value, ok = f.join(call, depth)
	} else {
		value, ok = f.sprintf(call, depth)
	}
	if !ok {
		return nil, false
	}
	return []sqlStringPiece{{text: value, pos: call.Pos()}}, true
}

func (f *sqlFolder) join(call *ast.CallExpr, depth int) (string, bool) {
	if len(call.Args) != 2 {
		return "", false
	}
	lit, ok := ast.Unparen(call.Args[0]).(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	typ, ok := lit.Type.(*ast.ArrayType)
	if !ok || typ.Len != nil {
		return "", false
	}
	id, ok := typ.Elt.(*ast.Ident)
	if !ok || id.Name != "string" || id.Obj != nil {
		return "", false
	}
	sep, ok := f.stringValue(call.Args[1], depth)
	if !ok {
		return "", false
	}
	var parts []string
	for _, elt := range lit.Elts {
		part, ok := f.stringValue(elt, depth)
		if !ok {
			return "", false
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, sep), true
}

func (f *sqlFolder) sprintf(call *ast.CallExpr, depth int) (string, bool) {
	format, ok := f.stringValue(call.Args[0], depth)
	if !ok {
		return "", false
	}
	args := make([]any, 0, len(call.Args)-1)
	for _, expr := range call.Args[1:] {
		value, ok := f.formatValue(expr, depth+1)
		if !ok {
			return "", false
		}
		args = append(args, value)
	}
	result := fmt.Sprintf(format, args...)
	if strings.Contains(result, "%!") {
		return "", false
	}
	return result, true
}

func (f *sqlFolder) formatValue(expr ast.Expr, depth int) (any, bool) {
	if depth > 20 {
		return nil, false
	}
	if s, ok := f.stringValue(expr, depth); ok {
		return s, true
	}
	switch v := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if v.Name == "true" && v.Obj == nil {
			return true, true
		}
		if v.Name == "false" && v.Obj == nil {
			return false, true
		}
		if init := f.value(v); init != nil {
			return f.formatValue(init, depth+1)
		}
	case *ast.BasicLit:
		c := constant.MakeFromLiteral(v.Value, v.Kind, 0)
		if c.Kind() == constant.Int {
			n, ok := constant.Int64Val(c)
			return n, ok
		}
		if c.Kind() == constant.Float {
			n, _ := constant.Float64Val(c)
			return n, true
		}
	}
	return nil, false
}

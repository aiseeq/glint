package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
)

// rangeElement is what stands for the element of a range loop: the value
// variable, and the locals the body binds to the element by index at its top
// level (c := &items[i], c := items[i]), the form a loop over large values
// takes instead of copying each one.
type rangeElement struct {
	// idents name the element: the value variable first, then the bound locals.
	idents []*ast.Ident
	// bindings are the statements that bind a local to the element.
	bindings map[ast.Stmt]bool
	// pointers names the locals bound to the element's address (&items[i]):
	// *c is the element.
	pointers map[string]bool
}

// rangeElementOf collects the names of a range loop's element. The index
// binding is matched by the key's name and the collection's spelling, so it
// needs no type information.
func rangeElementOf(loop *ast.RangeStmt) rangeElement {
	elem := rangeElement{bindings: map[ast.Stmt]bool{}, pointers: map[string]bool{}}
	if ident, ok := loop.Value.(*ast.Ident); ok && ident.Name != "_" {
		elem.idents = append(elem.idents, ident)
	}
	key, ok := loop.Key.(*ast.Ident)
	if !ok || key.Name == "_" || loop.Body == nil {
		return elem
	}
	collection := types.ExprString(ast.Unparen(loop.X))
	for _, stmt := range loop.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		rhs := ast.Unparen(assign.Rhs[0])
		addr, addressed := rhs.(*ast.UnaryExpr)
		addressed = addressed && addr.Op == token.AND
		if addressed {
			rhs = ast.Unparen(addr.X)
		}
		index, ok := rhs.(*ast.IndexExpr)
		if !ok || types.ExprString(ast.Unparen(index.X)) != collection {
			continue
		}
		if ident, ok := ast.Unparen(index.Index).(*ast.Ident); !ok || ident.Name != key.Name {
			continue
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name != "_" {
			elem.idents = append(elem.idents, ident)
			elem.bindings[stmt] = true
			elem.pointers[ident.Name] = addressed
		}
	}
	return elem
}

// rangeLoopNames returns the names a range loop gives each item: its key and
// the names of its element.
func rangeLoopNames(loop *ast.RangeStmt) []string {
	var names []string
	if ident, ok := loop.Key.(*ast.Ident); ok && ident.Name != "_" {
		names = append(names, ident.Name)
	}
	for _, ident := range rangeElementOf(loop).idents {
		names = append(names, ident.Name)
	}
	return names
}

// isElement reports an expression that is the element itself: an element
// variable, or the dereference of a local bound to its address.
func (e rangeElement) isElement(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		ident, isIdent := ast.Unparen(star.X).(*ast.Ident)
		return isIdent && e.pointers[ident.Name]
	}
	ident, ok := expr.(*ast.Ident)
	return ok && !e.pointers[ident.Name] && slices.ContainsFunc(e.idents, func(elem *ast.Ident) bool { return elem.Name == ident.Name })
}

// statements returns the body's statements past the element bindings.
func (e rangeElement) statements(body *ast.BlockStmt) []ast.Stmt {
	var stmts []ast.Stmt
	for _, stmt := range body.List {
		if !e.bindings[stmt] {
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

// rangeElementVars returns the objects of a range loop's element variables.
func rangeElementVars(info *types.Info, loop *ast.RangeStmt) []types.Object {
	var vars []types.Object
	for _, ident := range rangeElementOf(loop).idents {
		if obj := info.ObjectOf(ident); obj != nil {
			vars = append(vars, obj)
		}
	}
	return vars
}

// rangeItemVars returns the objects a range loop gives each item: its key and
// its element variables.
func rangeItemVars(info *types.Info, loop *ast.RangeStmt) []types.Object {
	var vars []types.Object
	if ident, ok := loop.Key.(*ast.Ident); ok && ident.Name != "_" {
		if obj := info.ObjectOf(ident); obj != nil {
			vars = append(vars, obj)
		}
	}
	return append(vars, rangeElementVars(info, loop)...)
}

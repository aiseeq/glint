package gorules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// pathsSure reports whether the paths through the callee may decide which
// writes run only past a free slot. They may only where every way the slot
// could be another than the one tested, or be emptied again, is ruled out by
// the shape of the code: the variables the slot is spelled with are never
// written, the seen map is a local the function that runs the loop makes
// afresh and only ever fills there with a mark of that same slot, no goto
// jumps back, and the guard, the marks and the writes sit in one
// function. Anywhere else the free span of the guard decides, as it did
// before the paths were followed.
func (c *dedupCallee) pathsSure(fn *ast.FuncDecl, guard dedupGuard, body *ast.BlockStmt, writes []ast.Stmt, info *types.Info) bool {
	for _, stmt := range append(slices.Clip(writes), guard.marks...) {
		if bodyOf(c.body, stmt) != body {
			return false
		}
	}
	parents := helpers.ParentMap(c.body)
	return c.indexFixed(guard.slot.Index, parents, info) && onlyMarked(fn, guard, info) && !gotoBack(c.body)
}

// indexFixed reports whether the slot index is built of constants and of
// values of the callee - parameters and locals of a basic or struct type, or
// their fields - that nothing writes after they are declared: no assignment,
// ++ or --, no address taken, no method called on them.
func (c *dedupCallee) indexFixed(index ast.Expr, parents map[ast.Node]ast.Node, info *types.Info) bool {
	vars := map[types.Object]bool{}
	if !c.fixedVars(index, vars, info) {
		return false
	}
	fixed := true
	ast.Inspect(c.body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && vars[info.Uses[ident]] {
			fixed = fixed && onlyRead(ident, parents, info)
		}
		return fixed
	})
	return fixed
}

// fixedVars collects the variables the index is spelled with; it reports
// false for any part other than a constant, a variable of the callee of a
// basic or struct type, a field of one, or an operator on those. The address
// of a variable (&slot) is not a read: onlyRead turns it down.
func (c *dedupCallee) fixedVars(expr ast.Expr, vars map[types.Object]bool, info *types.Info) bool {
	switch node := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.ParenExpr:
		return c.fixedVars(node.X, vars, info)
	case *ast.BinaryExpr:
		return c.fixedVars(node.X, vars, info) && c.fixedVars(node.Y, vars, info)
	case *ast.UnaryExpr:
		return c.fixedVars(node.X, vars, info)
	case *ast.SelectorExpr:
		typ := info.TypeOf(node.X)
		if typ == nil {
			return false
		}
		_, onValue := typ.Underlying().(*types.Struct)
		return onValue && c.fixedVars(node.X, vars, info)
	case *ast.Ident:
		switch obj := info.Uses[node].(type) {
		case *types.Const:
			return true
		case *types.Var:
			if obj.Pos() < c.span.Pos() || obj.Pos() >= c.span.End() {
				return false
			}
			switch obj.Type().Underlying().(type) {
			case *types.Basic, *types.Struct:
				vars[obj] = true
				return true
			}
		}
	}
	return false
}

// onlyRead reports whether the use of a variable, or of a field of it, reads
// it: it is not assigned, counted, ranged into, has no address taken and no
// method called on it.
func onlyRead(ident *ast.Ident, parents map[ast.Node]ast.Node, info *types.Info) bool {
	var node ast.Expr = ident
	for {
		switch parent := parents[node].(type) {
		case *ast.ParenExpr:
			node = parent
			continue
		case *ast.SelectorExpr:
			if parent.X != node {
				return true
			}
			if selection := info.Selections[parent]; selection == nil || selection.Kind() != types.FieldVal {
				return false
			}
			node = parent
			continue
		case *ast.AssignStmt:
			return !slices.Contains(parent.Lhs, node)
		case *ast.IncDecStmt:
			return false
		case *ast.UnaryExpr:
			return parent.Op != token.AND
		case *ast.RangeStmt:
			return parent.Key != node && parent.Value != node
		}
		return true
	}
}

// onlyMarked reports whether the seen map is a local of the function that
// runs the loop and that whole function - the loop, the callee, any other
// literal in it - writes the map only with marks of the tested slot
// (seen[slot] = <a constant other than zero or false>, count[slot]++) and
// otherwise only reads it: indexes it, ranges over it, takes its len,
// compares it, discards it. A map of the package or a field of a holder may
// be emptied anywhere - a helper, a method of the holder, the caller - and is
// not; nor is a local that only names such a map or one a call returns.
func onlyMarked(fn *ast.FuncDecl, guard dedupGuard, info *types.Info) bool {
	ident, _ := ast.Unparen(guard.slot.X).(*ast.Ident)
	seen, isVar := info.Uses[ident].(*types.Var)
	if !isVar || seen.Pos() < fn.Body.Pos() || seen.Pos() >= fn.Body.End() {
		return false
	}
	parents := helpers.ParentMap(fn.Body)
	marked := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if def, ok := n.(*ast.Ident); ok && info.Defs[def] == seen {
			marked = madeFresh(def, parents[def], info)
		}
		if use, ok := n.(*ast.Ident); ok && info.Uses[use] == seen {
			marked = guard.onlyMarks(use, parents, info)
		}
		return marked
	})
	return marked
}

// madeFresh reports whether the declaration of the seen map creates a new map
// - with make, a composite literal or no value at all - rather than naming a
// map another name may reach.
func madeFresh(def *ast.Ident, decl ast.Node, info *types.Info) bool {
	var names []*ast.Ident
	var values []ast.Expr
	switch decl := decl.(type) {
	case *ast.AssignStmt:
		for _, name := range decl.Lhs {
			ident, _ := name.(*ast.Ident)
			names = append(names, ident)
		}
		values = decl.Rhs
	case *ast.ValueSpec:
		if len(decl.Values) == 0 {
			return true
		}
		names, values = decl.Names, decl.Values
	}
	at := slices.Index(names, def)
	if at < 0 || len(values) != len(names) {
		return false
	}
	switch value := ast.Unparen(values[at]).(type) {
	case *ast.CompositeLit:
		return true
	case *ast.CallExpr:
		// Of the builtins only make yields a map.
		_, isBuiltin := info.Uses[calleeIdent(value.Fun)].(*types.Builtin)
		return isBuiltin
	}
	return false
}

// onlyMarks reports whether a use of the seen map is a read or a mark of the
// tested slot.
func (g dedupGuard) onlyMarks(use ast.Expr, parents map[ast.Node]ast.Node, info *types.Info) bool {
	switch parent := parents[use].(type) {
	case *ast.IndexExpr:
		return parent.X != use || g.marksOrReads(parent, parents, info)
	case *ast.CallExpr:
		builtin, isBuiltin := info.Uses[calleeIdent(parent.Fun)].(*types.Builtin)
		return isBuiltin && builtin.Name() == "len"
	case *ast.RangeStmt:
		return parent.X == use
	case *ast.BinaryExpr:
		return true
	case *ast.AssignStmt:
		return discarded(parent, use)
	}
	return false
}

// discarded reports whether the assignment hands the value to the blank
// identifier: _ = seen reads the map and keeps nothing of it.
func discarded(assign *ast.AssignStmt, value ast.Expr) bool {
	at := slices.Index(assign.Rhs, value)
	if at < 0 {
		return false
	}
	blank, ok := assign.Lhs[at].(*ast.Ident)
	return ok && blank.Name == "_"
}

func calleeIdent(fun ast.Expr) *ast.Ident {
	ident, _ := ast.Unparen(fun).(*ast.Ident)
	return ident
}

// marksOrReads reports whether the index of the seen map is read, or written
// with a mark of the tested slot.
func (g dedupGuard) marksOrReads(index *ast.IndexExpr, parents map[ast.Node]ast.Node, info *types.Info) bool {
	sameSlot := sameIndex(index.Index, g.slot.Index, info)
	switch parent := parents[index].(type) {
	case *ast.IncDecStmt:
		return sameSlot && parent.Tok == token.INC
	case *ast.AssignStmt:
		at := slices.Index(parent.Lhs, ast.Expr(index))
		if at < 0 {
			return true
		}
		return sameSlot && parent.Tok == token.ASSIGN && len(parent.Rhs) == len(parent.Lhs) && isMarkValue(parent.Rhs[at], info)
	}
	return true
}

// isMarkValue reports whether the value is a constant other than the zero of
// its type and false.
func isMarkValue(expr ast.Expr, info *types.Info) bool {
	value := info.Types[expr].Value
	if value == nil || isZeroConstant(info, expr) {
		return false
	}
	return value.Kind() != constant.Bool || constant.BoolVal(value)
}

// gotoBack reports whether a goto jumps to a label before it.
func gotoBack(body *ast.BlockStmt) bool {
	labels := map[string]token.Pos{}
	ast.Inspect(body, func(n ast.Node) bool {
		if labeled, ok := n.(*ast.LabeledStmt); ok {
			labels[labeled.Label.Name] = labeled.Pos()
		}
		return true
	})
	back := false
	ast.Inspect(body, func(n ast.Node) bool {
		branch, ok := n.(*ast.BranchStmt)
		if ok && branch.Tok == token.GOTO && branch.Label != nil {
			if at, found := labels[branch.Label.Name]; found && at < branch.Pos() {
				back = true
			}
		}
		return !back
	})
	return back
}

// sameIndex reports whether two indexes have the same shape and name the same
// variables, fields and constants: a variable that shadows the tested one is
// another slot however it is spelled.
func sameIndex(left, right ast.Expr, info *types.Info) bool {
	switch x := ast.Unparen(left).(type) {
	case *ast.Ident:
		y, ok := ast.Unparen(right).(*ast.Ident)
		return ok && info.ObjectOf(x) != nil && info.ObjectOf(x) == info.ObjectOf(y)
	case *ast.BasicLit:
		y, ok := ast.Unparen(right).(*ast.BasicLit)
		return ok && x.Kind == y.Kind && x.Value == y.Value
	case *ast.SelectorExpr:
		y, ok := ast.Unparen(right).(*ast.SelectorExpr)
		return ok && sameIndex(x.Sel, y.Sel, info) && sameIndex(x.X, y.X, info)
	case *ast.BinaryExpr:
		y, ok := ast.Unparen(right).(*ast.BinaryExpr)
		return ok && x.Op == y.Op && sameIndex(x.X, y.X, info) && sameIndex(x.Y, y.Y, info)
	case *ast.UnaryExpr:
		y, ok := ast.Unparen(right).(*ast.UnaryExpr)
		return ok && x.Op == y.Op && sameIndex(x.X, y.X, info)
	}
	return false
}

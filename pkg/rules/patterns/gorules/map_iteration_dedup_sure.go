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
// written, the seen map is only ever filled with a mark of that same slot,
// no goto jumps back, and the guard, the marks and the writes sit in one
// function. Anywhere else the free span of the guard decides, as it did
// before the paths were followed.
func (c *dedupCallee) pathsSure(guard dedupGuard, body *ast.BlockStmt, writes []ast.Stmt, info *types.Info) bool {
	for _, stmt := range append(slices.Clip(writes), guard.marks...) {
		if bodyOf(c.body, stmt) != body {
			return false
		}
	}
	parents := helpers.ParentMap(c.body)
	return c.indexFixed(guard.slot.Index, parents, info) && c.onlyMarked(guard, parents, info) && !gotoBack(c.body)
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

// onlyMarked reports whether the callee writes the seen map only with marks
// of the tested slot - seen[slot] = <a constant other than zero or false>,
// count[slot]++ - and otherwise only reads it: indexes it, ranges over it,
// takes its len, compares it. A map reached through a field (s.taken) needs
// its holder used only for its fields.
func (c *dedupCallee) onlyMarked(guard dedupGuard, parents map[ast.Node]ast.Node, info *types.Info) bool {
	isMap, holder, ok := seenMapOf(guard.slot.X, info)
	if !ok {
		return false
	}
	marked := true
	ast.Inspect(c.body, func(n ast.Node) bool {
		expr, isExpr := n.(ast.Expr)
		switch {
		case !isExpr:
		case isMap(expr):
			marked = guard.onlyMarks(expr, parents, info)
			return false
		case holder != nil:
			if ident, isIdent := expr.(*ast.Ident); isIdent && info.Uses[ident] == holder {
				selector, isSelector := parents[ident].(*ast.SelectorExpr)
				marked = isSelector && selector.X == ident && info.Selections[selector] != nil &&
					info.Selections[selector].Kind() == types.FieldVal
			}
		}
		return marked
	})
	return marked
}

// seenMapOf returns how to tell the seen map in the callee - a variable, or a
// field of a variable - and the variable that holds the field.
func seenMapOf(seenMap ast.Expr, info *types.Info) (func(ast.Expr) bool, types.Object, bool) {
	switch node := ast.Unparen(seenMap).(type) {
	case *ast.Ident:
		obj := info.Uses[node]
		return func(expr ast.Expr) bool {
			ident, ok := expr.(*ast.Ident)
			return ok && info.Uses[ident] == obj
		}, nil, obj != nil
	case *ast.SelectorExpr:
		root, ok := node.X.(*ast.Ident)
		if !ok || info.Uses[root] == nil {
			return nil, nil, false
		}
		holder := info.Uses[root]
		return func(expr ast.Expr) bool {
			selector, ok := expr.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != node.Sel.Name {
				return false
			}
			x, ok := selector.X.(*ast.Ident)
			return ok && info.Uses[x] == holder
		}, holder, true
	}
	return nil, nil, false
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
	}
	return false
}

func calleeIdent(fun ast.Expr) *ast.Ident {
	ident, _ := ast.Unparen(fun).(*ast.Ident)
	return ident
}

// marksOrReads reports whether the index of the seen map is read, or written
// with a mark of the tested slot.
func (g dedupGuard) marksOrReads(index *ast.IndexExpr, parents map[ast.Node]ast.Node, info *types.Info) bool {
	sameSlot := types.ExprString(index.Index) == types.ExprString(g.slot.Index)
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

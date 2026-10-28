package gorules

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewNilDstInLoopRule())
}

// appendStyleParams are the parameter names of the standard library's
// append-style functions (strconv.AppendInt's dst, fmt.Append's b,
// binary.Append's buf, utf8.AppendRune's p).
var appendStyleParams = []string{"dst", "buf", "b", "p", "out"}

// NewNilDstInLoopRule creates nil-dst-in-loop: an append-style call - one
// that takes a destination slice and returns it extended, like
// strconv.AppendInt, fmt.Appendf, a decoder's DecodeAll(src, dst) - gets nil
// as the destination in a loop or a //glint:hot function, while its result
// does not outlive the iteration. The API exists to reuse a buffer, and nil
// makes it allocate a new one on every call:
//
//	for _, e := range index { raw, err := dec.DecodeAll(read(e), nil); use(raw) }
//	for _, e := range index { raw, err = dec.DecodeAll(read(e), raw[:0]); use(raw) }
//
// A result kept past the iteration - stored, appended as an element,
// returned, sent, captured - needs its own memory, and nil is right there.
// A call that every path after it takes out of the loop runs once, like a
// call outside a loop.
func NewNilDstInLoopRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"nil-dst-in-loop",
			"patterns",
			"Detects an append-style call (strconv.AppendInt, fmt.Appendf, DecodeAll(src, dst)) given nil as the destination in a loop or a //glint:hot function while the result does not outlive the iteration — every call allocates the buffer the API was built to reuse",
			core.SeverityLow,
		),
		Suggestion: "Keep one buffer outside the loop (or on the receiver) and pass buf[:0]: buf = strconv.AppendInt(buf[:0], n, 10)",
	}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		hot := patternkit.HasDirective(fn.Doc, patternkit.HotFunctionDirective)
		loops := patternkit.LoopBodies(fn.Body)
		var parents map[ast.Node]ast.Node
		var findings []patternkit.FuncFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || (!hot && !patternkit.InsideNodes(loops, call)) {
				return true
			}
			result, name, ok := nilDestination(scope, call)
			if !ok {
				return true
			}
			if parents == nil {
				parents = helpers.ParentMap(fn.Body)
			}
			if !hot && onceInLoops(scope.Info, parents, loops, call) {
				return true
			}
			if !resultOutlives(scope.Info, fn, parents, call, result) {
				findings = append(findings, patternkit.FuncFinding{Node: call, Message: name + " gets nil as its destination and allocates a new buffer on every call — pass a reused buffer as buf[:0]"})
			}
			return true
		})
		return findings
	}
	return r
}

// nilDestination reports an append-style call with nil as its destination:
// a slice parameter whose type a result shares, named like a destination or
// of a function named Append*. A callee whose body is loaded has to append
// to it too: a slice it only hands back is no buffer. It returns the index
// of that result and the callee's name.
func nilDestination(scope patternkit.FuncScope, call *ast.CallExpr) (int, string, bool) {
	info := scope.Info
	if patternkit.BuiltinCallName(info, call) != "" {
		return 0, "", false
	}
	sig, ok := info.TypeOf(call.Fun).(*types.Signature)
	if !ok {
		return 0, "", false
	}
	name := types.ExprString(call.Fun)
	if fn := patternkit.StaticFunc(info, call); fn != nil {
		name = fn.Name()
	}
	for i, arg := range call.Args {
		if !helpers.IsNilIdent(ast.Unparen(arg)) || i >= sig.Params().Len() || (sig.Variadic() && i == sig.Params().Len()-1) {
			continue
		}
		param := sig.Params().At(i)
		if _, isSlice := param.Type().Underlying().(*types.Slice); !isSlice {
			continue
		}
		if !slices.Contains(appendStyleParams, param.Name()) && !strings.HasPrefix(name, "Append") {
			continue
		}
		if decl, loaded := scope.Callee(call); loaded && !appendsToParam(decl, i) {
			continue
		}
		for j := range sig.Results().Len() {
			if types.Identical(sig.Results().At(j).Type(), param.Type()) {
				return j, types.ExprString(call.Fun), true
			}
		}
	}
	return 0, "", false
}

// appendsToParam reports a function whose parameter i is a destination its body
// appends to: the first argument of append, or a nil-able destination of an
// append-style call (strconv.AppendInt(dst, ...), enc.AppendEncode(dst[:0], ...)).
func appendsToParam(fn patternkit.TypedFuncDecl, i int) bool {
	param := patternkit.ParamObject(fn, i)
	if param == nil || fn.Decl.Body == nil {
		return false
	}
	isParam := func(arg ast.Expr) bool {
		if s, ok := ast.Unparen(arg).(*ast.SliceExpr); ok {
			arg = s.X
		}
		ident, ok := ast.Unparen(arg).(*ast.Ident)
		return ok && fn.Info.Uses[ident] == param
	}
	found := false
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if patternkit.BuiltinCallName(fn.Info, call) == "append" {
			found = len(call.Args) > 0 && isParam(call.Args[0])
			return !found
		}
		sig, ok := fn.Info.TypeOf(call.Fun).(*types.Signature)
		if !ok {
			return true
		}
		for j, arg := range call.Args {
			if j < sig.Params().Len() && isParam(arg) &&
				(slices.Contains(appendStyleParams, sig.Params().At(j).Name()) || strings.HasPrefix(types.ExprString(call.Fun), "strconv.Append")) {
				found = true
			}
		}
		return !found
	})
	return found
}

// resultOutlives reports whether the call's result at index result is kept
// past the statement that uses it: assigned to anything but a fresh local,
// returned, put in a literal, sent, appended as an element, or a fresh local
// that is used that way or captured by a closure.
func resultOutlives(info *types.Info, fn *ast.FuncDecl, parents map[ast.Node]ast.Node, call *ast.CallExpr, result int) bool {
	switch parent := parents[call].(type) {
	case *ast.ExprStmt:
		return false
	case *ast.CallExpr:
		return keepsArgument(info, parent, call)
	case *ast.AssignStmt:
		if parent.Tok != token.DEFINE || len(parent.Rhs) != 1 || result >= len(parent.Lhs) {
			return true
		}
		ident, ok := parent.Lhs[result].(*ast.Ident)
		if !ok {
			return true
		}
		obj := info.Defs[ident]
		return obj == nil || localKept(info, fn, parents, obj)
	}
	return true
}

// keepsArgument reports a call that keeps an argument: append adds it as an
// element. A spread append(dst, src...) copies it.
func keepsArgument(info *types.Info, call *ast.CallExpr, arg ast.Expr) bool {
	if patternkit.BuiltinCallName(info, call) != "append" {
		return false
	}
	return call.Args[0] == arg || !call.Ellipsis.IsValid()
}

// localKept reports whether a local slice escapes the statement that uses it.
func localKept(info *types.Info, fn *ast.FuncDecl, parents map[ast.Node]ast.Node, obj types.Object) bool {
	kept := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok || kept || info.Uses[ident] != obj {
			return !kept
		}
		for node := ast.Node(ident); node != nil && !kept; node = parents[node] {
			if _, isClosure := node.(*ast.FuncLit); isClosure {
				kept = true
			}
		}
		switch parent := parents[ident].(type) {
		case *ast.AssignStmt:
			kept = kept || slices.Contains(parent.Rhs, ast.Expr(ident))
		case *ast.ReturnStmt, *ast.CompositeLit, *ast.KeyValueExpr, *ast.SendStmt:
			kept = true
		case *ast.CallExpr:
			kept = kept || keepsArgument(info, parent, ident)
		}
		return !kept
	})
	return kept
}

// onceInLoops reports a call that the loops around it run at most once: in
// each of them every path from the call leaves the loop. A closure in a loop
// may be called on every iteration.
func onceInLoops(info *types.Info, parents map[ast.Node]ast.Node, loops []ast.Node, call *ast.CallExpr) bool {
	for child, node := ast.Node(call), parents[call]; node != nil; child, node = node, parents[node] {
		switch n := node.(type) {
		case *ast.FuncLit:
			return !patternkit.InsideNodes(loops, n)
		case *ast.ForStmt:
			if child == n.Cond || child == n.Post || (child == n.Body && !leavesLoopAfter(info, parents, n, call)) {
				return false
			}
		case *ast.RangeStmt:
			if child == n.Body && !leavesLoopAfter(info, parents, n, call) {
				return false
			}
		}
	}
	return true
}

// leavesLoopAfter reports a call in the body of loop after which every path
// leaves it: at some statement list between the call and the loop, the rest
// of the list from the call ends in a return, a break of the loop or a call
// that never returns, with no continue of the loop and no goto or labeled
// branch on the way.
func leavesLoopAfter(info *types.Info, parents map[ast.Node]ast.Node, loop ast.Stmt, call *ast.CallExpr) bool {
	for child, node := ast.Node(call), parents[call]; node != nil && node != loop; child, node = node, parents[node] {
		var list []ast.Stmt
		switch n := node.(type) {
		case *ast.BlockStmt:
			list = n.List
		case *ast.CaseClause:
			list = n.Body
		case *ast.CommClause:
			list = n.Body
		default:
			continue
		}
		k := slices.IndexFunc(list, func(stmt ast.Stmt) bool { return stmt == child })
		if k < 0 {
			continue
		}
		rest := list[k:]
		if repeatsLoop(parents, loop, rest) {
			return false
		}
		if leavesLoopBy(info, parents, loop, rest[len(rest)-1]) {
			return true
		}
	}
	return false
}

// repeatsLoop reports a continue of loop, a goto or a labeled branch in the
// statements.
func repeatsLoop(parents map[ast.Node]ast.Node, loop ast.Stmt, stmts []ast.Stmt) bool {
	found := false
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			switch b := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.BranchStmt:
				found = found || b.Tok == token.GOTO || b.Label != nil || (b.Tok == token.CONTINUE && branchTarget(parents, b) == loop)
			}
			return !found
		})
	}
	return found
}

// leavesLoopBy reports a statement that leaves loop: a return, a break of the
// loop, a call that never returns.
func leavesLoopBy(info *types.Info, parents map[ast.Node]ast.Node, loop, stmt ast.Stmt) bool {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return s.Tok == token.BREAK && s.Label == nil && branchTarget(parents, s) == loop
	}
	return patternkit.StmtNoReturn(stmt, info, nil) != patternkit.CallReturns
}

// branchTarget returns the statement an unlabeled break or continue applies
// to: the innermost loop, or for a break also a switch or a select.
func branchTarget(parents map[ast.Node]ast.Node, branch *ast.BranchStmt) ast.Node {
	for node := parents[branch]; node != nil; node = parents[node] {
		switch node.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			return node
		case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			if branch.Tok == token.BREAK {
				return node
			}
		case *ast.FuncLit:
			return nil
		}
	}
	return nil
}

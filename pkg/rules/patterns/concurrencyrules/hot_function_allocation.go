package concurrencyrules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewAllocationInHotFunctionRule())
}

// allocatingPackageFuncs are the library functions that return a new slice,
// map or string on every call.
var allocatingPackageFuncs = []struct {
	pkg   string
	names []string
}{
	{"slices", []string{"Clone", "Concat", "Collect", "Repeat", "Sorted", "SortedFunc", "SortedStableFunc"}},
	{"maps", []string{"Clone", "Collect"}},
	{"bytes", []string{"Clone"}},
	{"strings", []string{"Clone"}},
}

// NewAllocationInHotFunctionRule creates allocation-in-hot-function: a heap
// allocation in the body of a function its author marked hot with
// //glint:hot - make, new, a slice or map literal, &T{...}, slices.Clone and
// its kin, and append to a slice that starts empty in the function. A
// function run every tick that allocates leaves garbage every tick, and the
// collector's work grows with it; the hot form keeps its buffers on the
// receiver or takes them as parameters and refills them with
// append(buf[:0], ...). An allocation under a check of its own lasting target
// (get-or-create, a buffer that grows) is kept for the next call and is not
// reported.
//
// With escape: true the rule also reads the compiler's escape analysis (go
// build -gcflags=-m over the packages with hot functions): it reports what
// the syntax does not show - a value boxed into an interface, a variable
// moved to the heap, a closure that escapes - and drops a fixed-size make or
// literal the compiler keeps on the stack. The build is replayed from the go
// build cache for unchanged packages, and the compiler's wording is not a
// stable interface: a toolchain that words it differently reports less, not
// more.
func NewAllocationInHotFunctionRule() *hotFuncRule {
	return &hotFuncRule{
		BaseRule: rules.NewBaseRule(
			"allocation-in-hot-function",
			"patterns",
			"Detects an allocation in a function marked //glint:hot: make, new, a slice or map literal, &T{...}, slices.Clone and the like, append to a slice that starts empty in the function — the hot path leaves garbage on every call; reuse a buffer with append(buf[:0], ...)",
			core.SeverityMedium,
		),
		suggestion:  "Keep the buffer on the receiver or take it as a parameter and refill it with append(buf[:0], ...); a deliberate allocation outside the loop takes // allocation-in-hot-function: safe — <reason>",
		check:       hotAllocations,
		takesEscape: true,
	}
}

// hotAllocations returns the allocations of the function body, closures
// included. With the compiler's escape analysis, a make, new or literal the
// compiler keeps on the stack is not reported, and what it puts on the heap
// beyond the syntax - boxing into an interface, a variable moved to the
// heap, a closure - is.
func hotAllocations(scope hotScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
	file, info, in := scope.file, scope.info, scope.in
	fresh := freshSlices(info, fn)
	guarded := guardedAllocations(info, fn)
	var escapes *funcEscapes
	if scope.escapes != nil {
		escapes = scope.escapes.forFunc(fn)
	}
	var findings []patternkit.FuncFinding
	reported := map[ast.Node]bool{}
	report := func(node ast.Node, what string) {
		reported[node] = true
		if patternkit.InsideNodes(guarded, node) {
			return
		}
		if escapes != nil && escapes.stays(info, node) {
			return
		}
		findings = append(findings, patternkit.FuncFinding{Node: node, Message: what + " allocates" + in})
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if what, ok := allocatingCall(file, info, node, fresh); ok {
				report(node, what)
			}
		case *ast.CompositeLit:
			switch info.TypeOf(node).Underlying().(type) {
			case *types.Slice:
				report(node, "a slice literal")
			case *types.Map:
				report(node, "a map literal")
			}
		case *ast.UnaryExpr:
			if lit, ok := ast.Unparen(node.X).(*ast.CompositeLit); ok && node.Op == token.AND {
				report(node, fmt.Sprintf("&%s{...}", types.ExprString(lit.Type)))
			}
		}
		return true
	})
	if escapes != nil {
		for _, f := range escapes.heapFindings(info, reported, in) {
			if !patternkit.InsideNodes(guarded, f.Node) {
				findings = append(findings, f)
			}
		}
	}
	return findings
}

// guardedAllocations returns the values the function assigns to a lasting
// target - a field, *p, m[k], or a local loaded from one - in the body of an
// if whose condition reads the same target:
//
//	w := s.walkers[tag]
//	if w == nil { w = &Walker{}; s.walkers[tag] = w } // get-or-create
//	if cap(t.verts) < n { t.verts = make([]V, 0, n) } // a buffer that grows
//
// The allocation runs when the old value is missing or too small and is kept
// for the next call, so it is not garbage of every call.
func guardedAllocations(info *types.Info, fn *ast.FuncDecl) []ast.Node {
	loaded := loadedLocals(info, fn)
	var guarded []ast.Node
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		for _, s := range stmt.Body.List {
			assign, ok := s.(*ast.AssignStmt)
			if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != len(assign.Rhs) {
				continue
			}
			for i, lhs := range assign.Lhs {
				if lastingTarget(info, lhs, loaded) && readsExpr(stmt.Cond, lhs) {
					guarded = append(guarded, assign.Rhs[i])
				}
			}
		}
		return true
	})
	return guarded
}

// lastingTarget reports a target whose value outlives the call: a field, a
// dereference, an index, or a local loaded from one of those.
func lastingTarget(info *types.Info, target ast.Expr, loaded map[types.Object]bool) bool {
	switch t := ast.Unparen(target).(type) {
	case *ast.SelectorExpr, *ast.StarExpr, *ast.IndexExpr:
		return true
	case *ast.Ident:
		return loaded[info.Uses[t]]
	}
	return false
}

// loadedLocals returns the locals the function defines from a field, a
// dereference or an index: w := s.walkers[tag].
func loadedLocals(info *types.Info, fn *ast.FuncDecl) map[types.Object]bool {
	loaded := map[types.Object]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			ident, isIdent := lhs.(*ast.Ident)
			if !isIdent || info.Defs[ident] == nil {
				continue
			}
			switch ast.Unparen(assign.Rhs[i]).(type) {
			case *ast.SelectorExpr, *ast.StarExpr, *ast.IndexExpr:
				loaded[info.Defs[ident]] = true
			}
		}
		return true
	})
	return loaded
}

// readsExpr reports whether expr appears in cond.
func readsExpr(cond, expr ast.Expr) bool {
	want := types.ExprString(ast.Unparen(expr))
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok && !found && types.ExprString(e) == want {
			found = true
		}
		return !found
	})
	return found
}

// allocatingCall describes a call that allocates: make, new, a library clone,
// append to nil or to a slice the function starts empty.
func allocatingCall(file *ast.File, info *types.Info, call *ast.CallExpr, fresh map[types.Object]bool) (string, bool) {
	switch name := patternkit.BuiltinCallName(info, call); name {
	case "make", "new":
		return name, true
	case "append":
		return appendToFresh(info, call, fresh)
	case "":
	default:
		return "", false
	}
	for _, lib := range allocatingPackageFuncs {
		if name, ok := patternkit.PackageFuncName(file, info, call, lib.pkg); ok && slices.Contains(lib.names, name) {
			return lib.pkg + "." + name, true
		}
	}
	return "", false
}

// appendToFresh describes an append whose slice has no capacity to reuse:
// nil, or a local slice that every assignment leaves empty.
func appendToFresh(info *types.Info, call *ast.CallExpr, fresh map[types.Object]bool) (string, bool) {
	if len(call.Args) == 0 {
		return "", false
	}
	switch first := ast.Unparen(call.Args[0]).(type) {
	case *ast.CallExpr:
		if isNilConversion(info, first) {
			return "append to nil", true
		}
	case *ast.Ident:
		if obj := info.Uses[first]; obj != nil && fresh[obj] {
			return "append to " + first.Name + ", which starts empty in the function,", true
		}
	}
	return "", false
}

// isNilConversion reports []T(nil).
func isNilConversion(info *types.Info, call *ast.CallExpr) bool {
	if len(call.Args) != 1 || !helpers.IsNilIdent(ast.Unparen(call.Args[0])) {
		return false
	}
	tv, ok := info.Types[call.Fun]
	return ok && tv.IsType()
}

// freshSlices returns the slice variables of the function - locals and named
// results - that start without capacity and are only ever assigned an empty
// value (nil, a literal) or an append to themselves. A slice assigned from a
// buffer, a parameter or a call result, or whose address is taken, has
// capacity the function cannot see and is not fresh. A make has its own
// report, so a slice made in the function is not fresh either.
func freshSlices(info *types.Info, fn *ast.FuncDecl) map[types.Object]bool {
	scan := freshSliceScan{info: info, candidate: map[types.Object]bool{}, spoiled: map[types.Object]bool{}}
	if fn.Type.Results != nil {
		for _, field := range fn.Type.Results.List {
			for _, name := range field.Names {
				scan.assign(name, nil)
			}
		}
	}
	ast.Inspect(fn.Body, scan.visit)

	fresh := map[types.Object]bool{}
	for obj := range scan.candidate {
		if !scan.spoiled[obj] {
			fresh[obj] = true
		}
	}
	return fresh
}

// freshSliceScan collects the assignments of a function's slice variables.
type freshSliceScan struct {
	info      *types.Info
	candidate map[types.Object]bool
	spoiled   map[types.Object]bool
}

// objOf returns the variable an identifier defines or uses.
func (s freshSliceScan) objOf(expr ast.Expr) types.Object {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	if obj := s.info.Defs[ident]; obj != nil {
		return obj
	}
	return s.info.Uses[ident]
}

// spoil marks the variable of expr as holding capacity the scan cannot see.
func (s freshSliceScan) spoil(expr ast.Expr) {
	if obj := s.objOf(expr); obj != nil {
		s.spoiled[obj] = true
	}
}

// assign records lhs = rhs; a nil rhs is a declaration without a value.
func (s freshSliceScan) assign(lhs, rhs ast.Expr) {
	obj := s.objOf(lhs)
	if obj == nil {
		return
	}
	if _, isSlice := obj.Type().Underlying().(*types.Slice); !isSlice {
		return
	}
	if rhs == nil || emptySliceValue(s.info, rhs) {
		s.candidate[obj] = true
		return
	}
	if call, ok := ast.Unparen(rhs).(*ast.CallExpr); ok && patternkit.BuiltinCallName(s.info, call) == "append" && len(call.Args) > 0 && s.objOf(call.Args[0]) == obj {
		return
	}
	s.spoiled[obj] = true
}

// visit records the assignments of one node.
func (s freshSliceScan) visit(n ast.Node) bool {
	switch node := n.(type) {
	case *ast.ValueSpec:
		for i, name := range node.Names {
			switch {
			case i < len(node.Values):
				s.assign(name, node.Values[i])
			case len(node.Values) > 0:
				s.spoil(name)
			default:
				s.assign(name, nil)
			}
		}
	case *ast.AssignStmt:
		if len(node.Lhs) != len(node.Rhs) {
			for _, lhs := range node.Lhs {
				s.spoil(lhs)
			}
			return true
		}
		for i := range node.Lhs {
			s.assign(node.Lhs[i], node.Rhs[i])
		}
	case *ast.RangeStmt:
		s.spoil(node.Key)
		s.spoil(node.Value)
	case *ast.UnaryExpr:
		if node.Op == token.AND {
			s.spoil(node.X)
		}
	}
	return true
}

// emptySliceValue reports a value with no capacity of its own to reuse: nil,
// []T(nil), a slice literal.
func emptySliceValue(info *types.Info, expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return helpers.IsNilIdent(e)
	case *ast.CallExpr:
		return isNilConversion(info, e)
	case *ast.CompositeLit:
		return true
	}
	return false
}

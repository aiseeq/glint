package patterns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMemoIgnoresParameterRule())
	rules.Register(NewAssertionsOnlyInScanLoopRule())
	rules.Register(NewReturnedIDReplacedByLiteralRule())
	rules.Register(NewFlatGridNeighborCrossesRowRule())
	rules.Register(NewFileNameUniqueOnlyByRoundedTimeRule())
	rules.Register(NewDefaultAppliedOnOnePathOnlyRule())
	rules.Register(NewConstFamilyDuplicateValueRule())
	rules.Register(NewThrottleStateSharedByMessagesRule())
	rules.Register(NewMapCompareMissingKeyAsZeroRule())
	rules.Register(NewLiteralBypassesConstructorRule())
}

// paramDeps maps every variable of the function to the parameters its value
// depends on: through assignments, and through the conditions of the ifs and
// loops it is assigned under.
func paramDeps(fn *ast.FuncDecl, info *types.Info) map[types.Object]map[types.Object]bool {
	g := &depGraph{info: info, deps: map[types.Object]map[types.Object]bool{}}
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if obj := info.ObjectOf(name); obj != nil && !isContextType(obj.Type()) {
				g.deps[obj] = map[types.Object]bool{obj: true}
			}
		}
	}
	if len(g.deps) == 0 {
		return g.deps
	}
	g.changed = true
	for rounds := 0; g.changed && rounds < 8; rounds++ {
		g.changed = false
		g.list(fn.Body.List, nil)
	}
	return g.deps
}

// depGraph propagates parameter dependencies over the statements of one
// function until nothing changes.
type depGraph struct {
	info    *types.Info
	deps    map[types.Object]map[types.Object]bool
	changed bool
}

func (g *depGraph) reads(expr ast.Expr) map[types.Object]bool {
	return depsOf(expr, g.deps, g.info)
}

// add records that target depends on the parameters of every set.
func (g *depGraph) add(target ast.Expr, from ...map[types.Object]bool) {
	ident, ok := ast.Unparen(target).(*ast.Ident)
	if !ok {
		return
	}
	obj := g.info.ObjectOf(ident)
	if obj == nil {
		return
	}
	if g.deps[obj] == nil {
		g.deps[obj] = map[types.Object]bool{}
	}
	for _, set := range from {
		for p := range set {
			if !g.deps[obj][p] {
				g.deps[obj][p] = true
				g.changed = true
			}
		}
	}
}

func (g *depGraph) list(stmts []ast.Stmt, ctrl map[types.Object]bool) {
	for _, s := range stmts {
		g.stmt(s, ctrl)
	}
}

func (g *depGraph) stmt(s ast.Stmt, ctrl map[types.Object]bool) {
	switch node := s.(type) {
	case *ast.AssignStmt:
		for i, lhs := range node.Lhs {
			rhs := node.Rhs[0]
			if len(node.Rhs) == len(node.Lhs) {
				rhs = node.Rhs[i]
			}
			g.add(lhs, g.reads(rhs), ctrl)
		}
	case *ast.DeclStmt:
		g.decl(node, ctrl)
	case *ast.IfStmt:
		if node.Init != nil {
			g.stmt(node.Init, ctrl)
		}
		inner := unionDeps(ctrl, g.reads(node.Cond))
		g.list(node.Body.List, inner)
		if node.Else != nil {
			g.stmt(node.Else, inner)
		}
	case *ast.ForStmt:
		if node.Init != nil {
			g.stmt(node.Init, ctrl)
		}
		g.list(node.Body.List, unionDeps(ctrl, g.reads(node.Cond)))
	case *ast.RangeStmt:
		from := g.reads(node.X)
		if node.Key != nil {
			g.add(node.Key, from, ctrl)
		}
		if node.Value != nil {
			g.add(node.Value, from, ctrl)
		}
		g.list(node.Body.List, unionDeps(ctrl, from))
	case *ast.BlockStmt:
		g.list(node.List, ctrl)
	case *ast.SwitchStmt:
		if node.Init != nil {
			g.stmt(node.Init, ctrl)
		}
		inner := unionDeps(ctrl, g.reads(node.Tag))
		for _, clause := range node.Body.List {
			if cc, ok := clause.(*ast.CaseClause); ok {
				g.list(cc.Body, inner)
			}
		}
	}
}

// decl records var x = e like an assignment.
func (g *depGraph) decl(node *ast.DeclStmt, ctrl map[types.Object]bool) {
	gen, ok := node.Decl.(*ast.GenDecl)
	if !ok {
		return
	}
	for _, spec := range gen.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range value.Names {
			var rhs ast.Expr
			if i < len(value.Values) {
				rhs = value.Values[i]
			}
			g.add(name, g.reads(rhs), ctrl)
		}
	}
}

func unionDeps(a, b map[types.Object]bool) map[types.Object]bool {
	out := map[types.Object]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func isContextType(t types.Type) bool {
	named, ok := t.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "context" && named.Obj().Name() == "Context"
}

// depsOf returns the parameters an expression reads, directly or through
// variables.
func depsOf(expr ast.Expr, deps map[types.Object]map[types.Object]bool, info *types.Info) map[types.Object]bool {
	out := map[types.Object]bool{}
	if expr == nil {
		return out
	}
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			for p := range deps[info.ObjectOf(ident)] {
				out[p] = true
			}
		}
		return true
	})
	return out
}

// NewMemoIgnoresParameterRule reports a cached result returned without
// looking at a parameter the cached value was computed from:
//
//	if p, ok := c.points[u.Tag]; ok { return p, true }
//	p, ok := next(u, to, r)
//	c.points[u.Tag] = p        // computed for to and r, served for any
//
// The second call with another destination gets the first call's answer.
func NewMemoIgnoresParameterRule() *typedFuncRule {
	return &typedFuncRule{
		BaseRule: rules.NewBaseRule("memo-ignores-parameter", "patterns",
			"Detects a cached result returned early under a key and a guard that leave out a parameter the cached value is computed from — a call with another value of that parameter gets the first call's answer",
			core.SeverityHigh),
		suggestion: "Put the parameter into the key, or store it next to the value and compare it in the guard",
		check:      memoIgnoresParameter,
	}
}

func memoIgnoresParameter(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return nil
	}
	deps := paramDeps(fn, info)
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || len(ifStmt.Body.List) == 0 {
			return true
		}
		ret, ok := ifStmt.Body.List[len(ifStmt.Body.List)-1].(*ast.ReturnStmt)
		if !ok {
			return true
		}
		cache, key, ok := memoGuard(ifStmt, ret)
		if !ok || cacheIsParam(fn, cache) {
			return true // a cache the caller passes in lives as long as the caller decides
		}
		known := depsOf(ifStmt.Cond, deps, info)
		for p := range depsOf(key, deps, info) {
			known[p] = true
		}
		var missing []string
		for _, value := range memoFills(fn.Body, cache, ifStmt.End()) {
			for p := range depsOf(value.value, deps, info) {
				if !known[p] && !depsOf(value.key, deps, info)[p] && !sharedStateParam(scope, fn, p) {
					missing = append(missing, p.Name())
				}
			}
		}
		if len(missing) == 0 {
			return true
		}
		slices.Sort(missing)
		missing = slices.Compact(missing)
		found = append(found, funcFinding{ifStmt, fmt.Sprintf("Cached %s is returned without looking at %s, which the cached value is computed from — a call with another %s gets the first call's answer",
			cache, strings.Join(missing, ", "), strings.Join(missing, "/"))})
		return true
	})
	return found
}

// sharedStateParam reports a parameter that does not vary between calls the
// way a key does: a loader or a handle (func, pointer, interface, channel),
// or a value every caller takes from the same field of a long-lived object
// (g.Start, c.G.Start).
func sharedStateParam(scope funcScope, fn *ast.FuncDecl, param types.Object) bool {
	switch param.Type().Underlying().(type) {
	case *types.Signature, *types.Pointer, *types.Interface, *types.Chan:
		return true
	}
	if passesStep(fn.Body, param, scope.info) {
		return true // a recursion budget: depth+1 bounds the walk, not the answer
	}
	obj, ok := scope.info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	index := -1
	params := obj.Signature().Params()
	for i := 0; i < params.Len(); i++ {
		if params.At(i) == param {
			index = i
		}
	}
	sites := scope.callers[obj]
	if index < 0 || len(sites) == 0 {
		return false
	}
	field := ""
	for _, site := range sites {
		if index >= len(site.call.Args) {
			return false
		}
		name, ok := fieldChainEnd(site.call.Args[index])
		if !ok || (field != "" && name != field) {
			return false
		}
		field = name
	}
	return true
}

// cacheIsParam reports a cache rooted at a parameter of the function.
func cacheIsParam(fn *ast.FuncDecl, cache string) bool {
	root, _, _ := strings.Cut(cache, ".")
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if name.Name == root {
				return true
			}
		}
	}
	return false
}

// passesStep reports a parameter passed on as p+1 or p-1.
func passesStep(body *ast.BlockStmt, param types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !found
		}
		for _, arg := range call.Args {
			binary, ok := ast.Unparen(arg).(*ast.BinaryExpr)
			if !ok || (binary.Op != token.ADD && binary.Op != token.SUB) || !isIntLiteral(ast.Unparen(binary.Y), 1) {
				continue
			}
			if ident, ok := ast.Unparen(binary.X).(*ast.Ident); ok && info.Uses[ident] == param {
				found = true
			}
		}
		return !found
	})
	return found
}

// fieldChainEnd returns the last field of x.A.B, a read of stored state with
// no call or index on the way.
func fieldChainEnd(expr ast.Expr) (string, bool) {
	selector, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	for x := ast.Unparen(selector.X); ; {
		switch node := x.(type) {
		case *ast.Ident:
			return selector.Sel.Name, true
		case *ast.SelectorExpr:
			x = ast.Unparen(node.X)
		default:
			return "", false
		}
	}
}

// memoGuard reads an early return of a cache: if v, ok := m[k]; ok { return v }
// (the cache is m, the key k) or if c.f != nil { return c.f } (the cache is
// the field, no key).
func memoGuard(ifStmt *ast.IfStmt, ret *ast.ReturnStmt) (string, ast.Expr, bool) {
	if init, ok := ifStmt.Init.(*ast.AssignStmt); ok && init.Tok == token.DEFINE && len(init.Lhs) == 2 && len(init.Rhs) == 1 {
		index, ok := ast.Unparen(init.Rhs[0]).(*ast.IndexExpr)
		value, isIdent := init.Lhs[0].(*ast.Ident)
		if ok && isIdent && returnsName(ret, value.Name) {
			return types.ExprString(index.X), index.Index, true
		}
		return "", nil, false
	}
	for _, result := range ret.Results {
		selector, ok := ast.Unparen(result).(*ast.SelectorExpr)
		if !ok {
			continue
		}
		cache := types.ExprString(selector)
		if strings.Contains(types.ExprString(ifStmt.Cond), cache) {
			return cache, nil, true
		}
	}
	return "", nil, false
}

func returnsName(ret *ast.ReturnStmt, name string) bool {
	for _, result := range ret.Results {
		if isIdent(result, name) {
			return true
		}
	}
	return false
}

type memoFill struct {
	key   ast.Expr
	value ast.Expr
}

// memoFills returns the values stored into the cache after the guard.
func memoFills(body *ast.BlockStmt, cache string, after token.Pos) []memoFill {
	var fills []memoFill
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Pos() < after || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			switch target := ast.Unparen(lhs).(type) {
			case *ast.IndexExpr:
				if types.ExprString(target.X) == cache {
					fills = append(fills, memoFill{target.Index, assign.Rhs[i]})
				}
			case *ast.SelectorExpr:
				if types.ExprString(target) == cache && !isNilIdent(assign.Rhs[i]) {
					fills = append(fills, memoFill{nil, assign.Rhs[i]})
				}
			}
		}
		return true
	})
	return fills
}

// AssertionsOnlyInScanLoopRule reports a test whose checks of a scan sit only
// inside the loop over the scan's matches:
//
//	for _, m := range re.FindAllStringSubmatch(src, -1) {
//	    if !known[m[1]] { t.Errorf(...) }
//	}
//
// When the pattern stops matching - the code it scans was renamed - the loop
// runs zero times and the test passes without checking anything.
type AssertionsOnlyInScanLoopRule struct {
	*rules.BaseRule
}

// NewAssertionsOnlyInScanLoopRule creates the rule
func NewAssertionsOnlyInScanLoopRule() *AssertionsOnlyInScanLoopRule {
	return &AssertionsOnlyInScanLoopRule{rules.NewBaseRule("test-assertions-only-in-scan-loop", "patterns",
		"Detects a test whose assertions sit only inside a loop over regexp matches, with no check that anything matched — a pattern that stops matching makes the test pass without checking",
		core.SeverityMedium)}
}

// scanCalls are regexp scans: a pattern that stops matching renamed code
// finds nothing without an error, unlike a directory listing.
var scanCalls = regexp.MustCompile(`^FindAll\w*$`)

// AnalyzeFile checks the test functions of a test file.
func (r *AssertionsOnlyInScanLoopRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || !ctx.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if !ok || !scanLoop(loop, fn.Body) || !assertsIn(loop.Body) || countedAfter(loop, fn.Body) {
				return true
			}
			line := ctx.LineFor(loop)
			if ctx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(ctx.RelPath, line, "The test's checks run only for the matches of this scan, and nothing checks that it matched — when the pattern stops matching the test passes without checking anything")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Fail when the scan finds nothing (len(matches) == 0), or check the other way too: every expected name is found")
			violations = append(violations, v)
			return true
		})
	}
	return violations
}

// scanLoop reports a range over the matches of a regexp, a glob or a split,
// called in place or stored in a variable of the function.
func scanLoop(loop *ast.RangeStmt, body *ast.BlockStmt) bool {
	if call, ok := ast.Unparen(loop.X).(*ast.CallExpr); ok {
		return isScanCall(call)
	}
	ident, ok := ast.Unparen(loop.X).(*ast.Ident)
	if !ok {
		return false
	}
	scan := false
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 || !isIdent(assign.Lhs[0], ident.Name) {
			return !scan
		}
		if call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); ok && isScanCall(call) {
			scan = true
		}
		return !scan
	})
	return scan
}

func isScanCall(call *ast.CallExpr) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return ok && scanCalls.MatchString(selector.Sel.Name)
}

func assertsIn(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok &&
				(strings.HasPrefix(selector.Sel.Name, "Error") || strings.HasPrefix(selector.Sel.Name, "Fatal") || selector.Sel.Name == "Fail") {
				found = true
			}
		}
		return !found
	})
	return found
}

// countedAfter reports a loop whose result is checked: len of the scanned
// collection compared anywhere in the test, or a variable from outside the
// loop that the loop writes and the test reads after it.
func countedAfter(loop *ast.RangeStmt, body *ast.BlockStmt) bool {
	if ident, ok := ast.Unparen(loop.X).(*ast.Ident); ok {
		measured := false
		ast.Inspect(body, func(n ast.Node) bool {
			if binary, ok := n.(*ast.BinaryExpr); ok && isComparison(binary.Op) {
				for _, side := range []ast.Expr{binary.X, binary.Y} {
					if arg := lenArgument(side); arg != nil && isIdent(arg, ident.Name) {
						measured = true
					}
				}
			}
			return !measured
		})
		if measured {
			return true
		}
	}
	written := map[string]bool{}
	ast.Inspect(loop.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				return true
			}
			for _, lhs := range node.Lhs {
				if root := rootIdent(indexRoot(lhs)); root != nil {
					written[root.Name] = true
				}
			}
		case *ast.IncDecStmt:
			if root := rootIdent(indexRoot(node.X)); root != nil {
				written[root.Name] = true
			}
		}
		return true
	})
	read := false
	ast.Inspect(body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Pos() > loop.End() && written[ident.Name] {
			read = true
		}
		return !read
	})
	return read
}

func indexRoot(expr ast.Expr) ast.Expr {
	for {
		index, ok := ast.Unparen(expr).(*ast.IndexExpr)
		if !ok {
			return expr
		}
		expr = index.X
	}
}

// NewReturnedIDReplacedByLiteralRule reports an id a call returns that the
// function only logs, while it passes a literal to a parameter of the same
// role:
//
//	playerID, err := c.Join(...)
//	slog.Info("joined", "player_id", playerID)
//	scan(out, 2, "them")   // player 2 - right only when we joined as 1
func NewReturnedIDReplacedByLiteralRule() *typedFuncRule {
	return &typedFuncRule{
		BaseRule: rules.NewBaseRule("returned-id-replaced-by-literal", "patterns",
			"Detects an id a call returns that the function only logs, while it passes integer literals to a parameter of the same role — the literal is right only for one outcome of the call",
			core.SeverityMedium),
		suggestion: "Pass the id the call returned (and what follows from it) instead of the literal",
		check:      returnedIDReplacedByLiteral,
	}
}

var idName = regexp.MustCompile(`^([a-z][A-Za-z]{2,}?)(ID|Id)$`)

func returnedIDReplacedByLiteral(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Rhs) != 1 {
			return true
		}
		if _, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			match := idName.FindStringSubmatch(ident.Name)
			obj := info.ObjectOf(ident)
			if match == nil || obj == nil || !onlyLogged(fn.Body, obj, info) {
				continue
			}
			found = append(found, literalForRole(fn.Body, strings.ToLower(match[1]), ident.Name, assign.End(), info)...)
		}
		return true
	})
	return found
}

// onlyLogged reports whether every use of the variable is an argument of a
// log call.
func onlyLogged(body *ast.BlockStmt, obj types.Object, info *types.Info) bool {
	uses, logged := 0, 0
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && isLogCallExpr(call) {
			for _, arg := range call.Args {
				ast.Inspect(arg, func(m ast.Node) bool {
					if ident, ok := m.(*ast.Ident); ok && info.Uses[ident] == obj {
						logged++
					}
					return true
				})
			}
		}
		if ident, ok := n.(*ast.Ident); ok && info.Uses[ident] == obj {
			uses++
		}
		return true
	})
	return uses > 0 && uses == logged
}

func isLogCallExpr(call *ast.CallExpr) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch selector.Sel.Name {
	case "Info", "Infof", "Debug", "Debugf", "Warn", "Warnf", "Error", "Errorf", "Print", "Printf", "Println", "Log", "Logf":
		return types.ExprString(selector.X) != "fmt" || selector.Sel.Name != "Errorf"
	}
	return false
}

// literalForRole returns the calls after pos that pass an integer literal to
// a parameter whose name holds the role.
func literalForRole(body *ast.BlockStmt, role, idVar string, pos token.Pos, info *types.Info) []funcFinding {
	var found []funcFinding
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || call.Pos() < pos {
			return true
		}
		callee := staticFunc(info, call)
		if callee == nil {
			return true
		}
		params := callee.Signature().Params()
		for i := 0; i < params.Len() && i < len(call.Args); i++ {
			if !strings.Contains(strings.ToLower(params.At(i).Name()), role) {
				continue
			}
			if lit, ok := ast.Unparen(call.Args[i]).(*ast.BasicLit); ok && lit.Kind == token.INT {
				found = append(found, funcFinding{call, fmt.Sprintf("%s gets %s %s as a literal while the %s the call returned is only logged — the literal is right only for one outcome", callee.Name(), params.At(i).Name(), lit.Value, idVar)})
			}
		}
		return true
	})
	return found
}

// FlatGridNeighborCrossesRowRule reports pos-1 or pos+1 in a loop over a
// flattened grid with no guard on the column:
//
//	for pos, cell := range dst { dst[pos-1] = cell }   // column 0 writes into the previous row
type FlatGridNeighborCrossesRowRule struct {
	*rules.BaseRule
}

// NewFlatGridNeighborCrossesRowRule creates the rule
func NewFlatGridNeighborCrossesRowRule() *FlatGridNeighborCrossesRowRule {
	return &FlatGridNeighborCrossesRowRule{rules.NewBaseRule("flat-grid-neighbor-crosses-row", "patterns",
		"Detects pos-1 or pos+1 over a flattened grid (the file reads pos%W and pos/W) with no guard on pos%W — the first or last column reaches into another row or out of the slice",
		core.SeverityMedium)}
}

// AnalyzeFile checks the loops of a file that indexes a grid by pos%W.
func (r *FlatGridNeighborCrossesRowRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	widths := gridWidths(ctx.GoAST)
	if len(widths) == 0 {
		return nil
	}
	cells := gridIndexNames(ctx.GoAST, widths)
	var violations []*core.Violation
	forEachFunction(ctx.GoAST, func(_ string, _ *ast.FuncType, body *ast.BlockStmt) {
		ast.Inspect(body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			key, ok := loop.Key.(*ast.Ident)
			if !ok || !cells[key.Name] || guardsColumn(body, key.Name, widths) {
				return true
			}
			ast.Inspect(loop.Body, func(m ast.Node) bool {
				// An index under a test of the cell index is an edge the
				// author already handled.
				if branch, ok := m.(*ast.IfStmt); ok && mentions(branch.Cond, key.Name) {
					return false
				}
				index, ok := m.(*ast.IndexExpr)
				if !ok || !neighborOf(index.Index, key.Name) {
					return true
				}
				line := ctx.LineFor(index)
				if ctx.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(ctx.RelPath, line, "Neighbor index "+types.ExprString(index.Index)+" over a flattened grid with no check of the column — in the first or last column it reaches into another row or out of the slice")
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Skip the edge column first: if " + key.Name + "%W == 0 { continue } before " + key.Name + "-1")
				violations = append(violations, v)
				return true
			})
			return true
		})
	})
	return violations
}

// gridWidths returns the widths the file divides and takes the remainder by:
// x%W and x/W with the same W.
func gridWidths(file *ast.File) map[string]bool {
	rem, quo := map[string]bool{}, map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		binary, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		width := types.ExprString(binary.Y)
		if width == "2" || width == "10" {
			return true
		}
		switch binary.Op {
		case token.REM:
			rem[width] = true
		case token.QUO:
			quo[width] = true
		}
		return true
	})
	widths := map[string]bool{}
	for width := range rem {
		if quo[width] {
			widths[width] = true
		}
	}
	return widths
}

// gridIndexNames returns the names the file takes a column of: pos in pos%W.
// A loop over the grid uses the same name for the cell index.
func gridIndexNames(file *ast.File, widths map[string]bool) map[string]bool {
	names := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if binary, ok := n.(*ast.BinaryExpr); ok && binary.Op == token.REM && widths[types.ExprString(binary.Y)] {
			if ident, ok := ast.Unparen(binary.X).(*ast.Ident); ok {
				names[ident.Name] = true
			}
		}
		return true
	})
	return names
}

func guardsColumn(body *ast.BlockStmt, pos string, widths map[string]bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if binary, ok := n.(*ast.BinaryExpr); ok && binary.Op == token.REM && isIdent(binary.X, pos) && widths[types.ExprString(binary.Y)] {
			found = true
		}
		return !found
	})
	return found
}

func neighborOf(expr ast.Expr, pos string) bool {
	binary, ok := ast.Unparen(expr).(*ast.BinaryExpr)
	if !ok || (binary.Op != token.SUB && binary.Op != token.ADD) {
		return false
	}
	return isIdent(binary.X, pos) && isIntLiteral(ast.Unparen(binary.Y), 1)
}

// NewFileNameUniqueOnlyByRoundedTimeRule reports files written in a loop
// under names that differ only by a rounded time:
//
//	out := fmt.Sprintf("%s-%03.0fs.png", name, secs)   // two images in one second share it
func NewFileNameUniqueOnlyByRoundedTimeRule() *typedFuncRule {
	return &typedFuncRule{
		BaseRule: rules.NewBaseRule("file-name-unique-only-by-rounded-time", "patterns",
			"Detects files written in a loop under names built from a time rounded to seconds — two files within one second get the same name and the second overwrites the first",
			core.SeverityMedium),
		suggestion: "Put an exact counter into the name (the frame number, the loop index), or check the name is free before writing",
		check:      fileNameUniqueOnlyByRoundedTime,
	}
}

var (
	roundedFloatVerb = regexp.MustCompile(`%[-+ #0]*\d*\.0f`)
	exactCounterVerb = regexp.MustCompile(`%[-+ #0]*\d*d`)
	secondsLayout    = regexp.MustCompile(`05`)
	fractionLayout   = regexp.MustCompile(`05[.,]0`)
)

var fileWriters = []string{"WriteFile", "Create", "OpenFile", "Write", "Save", "Encode"}

func fileNameUniqueOnlyByRoundedTime(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch loop := n.(type) {
		case *ast.ForStmt:
			body = loop.Body
		case *ast.RangeStmt:
			body = loop.Body
		default:
			return true
		}
		for _, stmt := range body.List {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || !roundedTimeName(assign.Rhs[0], info) {
				continue
			}
			name, ok := assign.Lhs[0].(*ast.Ident)
			if ok && writtenTo(body, info.ObjectOf(name), info) {
				found = append(found, funcFinding{assign, "File name " + name.Name + " differs between iterations only by a time rounded to seconds — two files within one second share it and the second overwrites the first"})
			}
		}
		return true
	})
	return found
}

// roundedTimeName reports a name built with %.0f or a time layout ending at
// seconds.
func roundedTimeName(expr ast.Expr, info *types.Info) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return !found
		}
		tv, ok := info.Types[lit]
		if !ok || tv.Value == nil {
			return !found
		}
		text := constant.StringVal(tv.Value)
		if exactCounterVerb.MatchString(text) {
			return false // an exact counter next to the time keeps the names apart
		}
		if roundedFloatVerb.MatchString(text) || (strings.Contains(text, "15") && secondsLayout.MatchString(text) && !fractionLayout.MatchString(text) && strings.Contains(text, "04")) {
			found = true
		}
		return !found
	})
	return found
}

func writtenTo(body *ast.BlockStmt, obj types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return !found
		}
		first, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
		if !ok || info.Uses[first] != obj {
			return !found
		}
		name := ""
		switch fun := ast.Unparen(call.Fun).(type) {
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		case *ast.Ident:
			name = fun.Name
		}
		for _, writer := range fileWriters {
			if strings.Contains(name, writer) {
				found = true
			}
		}
		return !found
	})
	return found
}

// NewDefaultAppliedOnOnePathOnlyRule reports a value given a default on one
// path of a function and passed raw to the same callee on another:
//
//	if *info { profiles.Load(*profileName) }               // raw: "" fails here
//	name := *profileName
//	if name == "" { name = fromArgv0() }
//	profiles.Load(name)
func NewDefaultAppliedOnOnePathOnlyRule() *typedFuncRule {
	return &typedFuncRule{
		BaseRule: rules.NewBaseRule("default-applied-on-one-path-only", "patterns",
			"Detects a value that one path of a function fills with a default when empty before calling a function, while another path passes the raw value to the same function — that path fails or behaves differently on the empty value",
			core.SeverityMedium),
		suggestion: "Resolve the default once, before the paths split, or in one helper both paths call",
		check:      defaultAppliedOnOnePathOnly,
	}
}

func defaultAppliedOnOnePathOnly(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	type defaulted struct {
		raw    string
		local  types.Object
		callee *types.Func
	}
	var defaults []defaulted
	forEachStmtList(fn.Body, func(stmts []ast.Stmt) {
		for i := 0; i+1 < len(stmts); i++ {
			assign, ok := stmts[i].(*ast.AssignStmt)
			if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				continue
			}
			local, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				continue
			}
			check, ok := stmts[i+1].(*ast.IfStmt)
			if !ok || !emptyTestOf(check.Cond, local.Name) || !bodyAssignsName(check.Body, local.Name) {
				continue
			}
			obj := info.ObjectOf(local)
			for _, call := range callsWith(stmts[i+2:], obj, info) {
				if callee := staticFunc(info, call); callee != nil && scope.decls[callee].decl != nil {
					defaults = append(defaults, defaulted{types.ExprString(assign.Rhs[0]), obj, callee})
				}
			}
		}
	})
	var found []funcFinding
	for _, d := range defaults {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || staticFunc(info, call) != d.callee {
				return true
			}
			for _, arg := range call.Args {
				if types.ExprString(arg) == d.raw {
					found = append(found, funcFinding{call, fmt.Sprintf("%s gets %s raw here, while another path of the function fills it with a default when empty before the same call — on this path the empty value goes through", d.callee.Name(), d.raw)})
				}
			}
			return true
		})
	}
	return found
}

func emptyTestOf(cond ast.Expr, name string) bool {
	binary, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || binary.Op != token.EQL || !isIdent(binary.X, name) {
		return false
	}
	if lit, ok := ast.Unparen(binary.Y).(*ast.BasicLit); ok {
		return lit.Value == `""` || lit.Value == "0"
	}
	return isNilIdent(binary.Y)
}

func bodyAssignsName(body *ast.BlockStmt, name string) bool {
	for _, stmt := range body.List {
		if assign, ok := stmt.(*ast.AssignStmt); ok && assign.Tok == token.ASSIGN && len(assign.Lhs) == 1 && isIdent(assign.Lhs[0], name) {
			return true
		}
	}
	return false
}

func callsWith(stmts []ast.Stmt, obj types.Object, info *types.Info) []*ast.CallExpr {
	var calls []*ast.CallExpr
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, arg := range call.Args {
				if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && info.Uses[ident] == obj {
					calls = append(calls, call)
				}
			}
			return true
		})
	}
	return calls
}

// ConstFamilyDuplicateValueRule reports two constants of one naming family
// that hold the same value:
//
//	RuleScoutHome  = "B4"
//	RuleRushStage = "B4"   // the summary by rule adds both together
type ConstFamilyDuplicateValueRule struct {
	*rules.BaseRule
}

// NewConstFamilyDuplicateValueRule creates the rule
func NewConstFamilyDuplicateValueRule() *ConstFamilyDuplicateValueRule {
	return &ConstFamilyDuplicateValueRule{rules.NewBaseRule("const-family-duplicate-value", "patterns",
		"Detects two string constants of one naming family (Rule*, Event*, Code*) in a package of otherwise distinct values that hold the same value — whatever keys on the value mixes the two up",
		core.SeverityMedium)}
}

// AnalyzeFile is a no-op: a family spans the files of a package.
func (r *ConstFamilyDuplicateValueRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *ConstFamilyDuplicateValueRule) RequiresSSA() bool { return false }

// familyMinimum is how many constants a family needs before its values read
// as identifiers that must differ.
const familyMinimum = 4

// looseFamilies name constants whose equal values are usual: defaults and
// limits repeat one another on purpose.
var looseFamilies = map[string]bool{"Default": true, "Max": true, "Min": true, "Env": true, "Flag": true}

var idValue = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,40}$`)

type familyConst struct {
	file  *core.FileContext
	name  *ast.Ident
	value string
}

// AnalyzeGoProject groups the string constants of each package by family.
func (r *ConstFamilyDuplicateValueRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		families := map[string][]familyConst{}
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() {
				continue
			}
			collectFamilyConsts(file, pkg.Package.TypesInfo, families)
		}
		for _, family := range slices.Sorted(mapsKeys(families)) {
			violations = append(violations, r.duplicates(families[family])...)
		}
	}
	return violations, nil
}

func mapsKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func collectFamilyConsts(file *core.FileContext, info *types.Info, families map[string][]familyConst) {
	for _, decl := range file.GoAST.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if i >= len(value.Values) {
					continue
				}
				lit, ok := ast.Unparen(value.Values[i]).(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				tv, ok := info.Types[lit]
				if !ok || tv.Value == nil {
					continue
				}
				family := familyOf(name.Name)
				if family == "" || looseFamilies[family] {
					continue
				}
				// Typed constants of different enums share values on purpose:
				// a family is one name prefix and one type.
				key := family + " " + tv.Type.String()
				families[key] = append(families[key], familyConst{file, name, constant.StringVal(tv.Value)})
			}
		}
	}
}

// familyOf returns the first word of a camel-case exported name.
func familyOf(name string) string {
	runes := []rune(name)
	if len(runes) < 2 || !unicode.IsUpper(runes[0]) {
		return ""
	}
	for i := 1; i < len(runes); i++ {
		if unicode.IsUpper(runes[i]) || runes[i] == '_' {
			if i < 2 {
				return ""
			}
			return string(runes[:i])
		}
	}
	return ""
}

func (r *ConstFamilyDuplicateValueRule) duplicates(members []familyConst) []*core.Violation {
	if len(members) < familyMinimum {
		return nil
	}
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].file.RelPath != members[j].file.RelPath {
			return members[i].file.RelPath < members[j].file.RelPath
		}
		return members[i].name.Pos() < members[j].name.Pos()
	})
	first := map[string]familyConst{}
	var pairs [][2]familyConst
	for _, member := range members {
		if !idValue.MatchString(member.value) {
			continue
		}
		if earlier, ok := first[member.value]; ok {
			pairs = append(pairs, [2]familyConst{earlier, member})
			continue
		}
		first[member.value] = member
	}
	// A family that repeats many values is a set of aliases, not identifiers.
	if len(pairs) == 0 || len(pairs)*4 > len(members) {
		return nil
	}
	var violations []*core.Violation
	for _, pair := range pairs {
		later := pair[1]
		line := later.file.LineFor(later.name)
		if later.file.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(later.file.RelPath, line, fmt.Sprintf("%s holds %q, the value of %s (%s:%d) — whatever keys on the value mixes the two up",
			later.name.Name, later.value, pair[0].name.Name, pair[0].file.RelPath, pair[0].file.LineFor(pair[0].name)))
		v.WithCode(strings.TrimSpace(later.file.GetLine(line)))
		v.WithSuggestion("Give one of them its own value")
		violations = append(violations, v)
	}
	return violations
}

// ThrottleStateSharedByMessagesRule reports a log throttle whose state - the
// time a message was last written, per key - is shared by different messages:
//
//	if c.loop-c.last[id] < every { return }
//	c.last[id] = c.loop
//	log("no supplier")        // and elsewhere, the same c.last for "order rejected"
//
// The first message written silences the other for the window.
type ThrottleStateSharedByMessagesRule struct {
	*rules.BaseRule
}

// NewThrottleStateSharedByMessagesRule creates the rule
func NewThrottleStateSharedByMessagesRule() *ThrottleStateSharedByMessagesRule {
	return &ThrottleStateSharedByMessagesRule{rules.NewBaseRule("throttle-state-shared-by-messages", "patterns",
		"Detects a log throttle (if now-last[k] < every { return }; last[k] = now) whose state is shared by functions writing different messages — the first message written silences the others for the window",
		core.SeverityLow)}
}

// AnalyzeFile is a no-op: the throttles of a package are compared.
func (r *ThrottleStateSharedByMessagesRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *ThrottleStateSharedByMessagesRule) RequiresSSA() bool { return false }

type throttle struct {
	file    *core.FileContext
	guard   *ast.IfStmt
	message string
}

// AnalyzeGoProject groups the throttles of each package by their state.
func (r *ThrottleStateSharedByMessagesRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		byState := map[types.Object][]throttle{}
		var order []types.Object
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() {
				continue
			}
			for _, decl := range file.GoAST.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				state, guard, message := throttleOf(fn.Body, info)
				if state == nil {
					continue
				}
				if _, seen := byState[state]; !seen {
					order = append(order, state)
				}
				byState[state] = append(byState[state], throttle{file, guard, message})
			}
		}
		for _, state := range order {
			violations = append(violations, r.shared(state, byState[state])...)
		}
	}
	return violations, nil
}

func (r *ThrottleStateSharedByMessagesRule) shared(state types.Object, group []throttle) []*core.Violation {
	messages := map[string]bool{}
	for _, t := range group {
		messages[t.message] = true
	}
	if len(messages) < 2 {
		return nil
	}
	var violations []*core.Violation
	for _, t := range group {
		line := t.file.LineFor(t.guard)
		if t.file.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(t.file.RelPath, line, fmt.Sprintf("Throttle of %q keeps its state in %s, which %d other messages share — the first message written silences the others for the window",
			t.message, state.Name(), len(messages)-1))
		v.WithCode(strings.TrimSpace(t.file.GetLine(line)))
		v.WithSuggestion("Give each message its own throttle state")
		violations = append(violations, v)
	}
	return violations
}

// throttleOf reads the throttle at the top level of a function: the state
// field or variable, the guard and the first log message after it.
func throttleOf(body *ast.BlockStmt, info *types.Info) (types.Object, *ast.IfStmt, string) {
	for i := 0; i+1 < len(body.List); i++ {
		guard, ok := body.List[i].(*ast.IfStmt)
		if !ok || len(guard.Body.List) != 1 {
			continue
		}
		if _, ok := guard.Body.List[0].(*ast.ReturnStmt); !ok {
			continue
		}
		state := throttleState(guard.Cond, info)
		if state == nil || !storesState(body.List[i+1], state, info) {
			continue
		}
		for _, stmt := range body.List[i+2:] {
			if message := logMessage(stmt, info); message != "" {
				return state, guard, message
			}
		}
	}
	return nil, nil, ""
}

// throttleState reads now-last[k] < every and returns the object of last.
func throttleState(cond ast.Expr, info *types.Info) types.Object {
	binary, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || (binary.Op != token.LSS && binary.Op != token.LEQ) {
		return nil
	}
	diff, ok := ast.Unparen(binary.X).(*ast.BinaryExpr)
	if !ok || diff.Op != token.SUB {
		return nil
	}
	index, ok := ast.Unparen(diff.Y).(*ast.IndexExpr)
	if !ok {
		return nil
	}
	return stateObject(index.X, info)
}

func stateObject(expr ast.Expr, info *types.Info) types.Object {
	switch node := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		return info.Uses[node.Sel]
	case *ast.Ident:
		return info.ObjectOf(node)
	}
	return nil
}

func storesState(stmt ast.Stmt, state types.Object, info *types.Info) bool {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 {
		return false
	}
	index, ok := ast.Unparen(assign.Lhs[0]).(*ast.IndexExpr)
	return ok && stateObject(index.X, info) == state
}

// logMessage returns the constant message of a log call statement.
func logMessage(stmt ast.Stmt, info *types.Info) string {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return ""
	}
	call, ok := ast.Unparen(expr.X).(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return ""
	}
	for _, arg := range call.Args {
		if tv, ok := info.Types[arg]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
			return constant.StringVal(tv.Value)
		}
	}
	return ""
}

// NewMapCompareMissingKeyAsZeroRule reports two maps compared entry by entry
// over a list of keys that is not taken from the maps, with no check that
// the key is there:
//
//	for _, k := range fields { if want.Fields[k] != got.Fields[k] { ... } }
//
// A key missing from one map reads as the zero value and compares as a
// difference (or a missing key in both as equal).
func NewMapCompareMissingKeyAsZeroRule() *typedFuncRule {
	return &typedFuncRule{
		BaseRule: rules.NewBaseRule("map-compare-missing-key-as-zero", "patterns",
			"Detects two maps compared over a key list not taken from them, with no comma-ok lookup — a key one map lacks reads as the zero value and counts as a difference",
			core.SeverityMedium),
		suggestion: "Look the key up with v, ok := m[k] in both maps and decide what a missing key means",
		check:      mapCompareMissingKeyAsZero,
	}
}

func mapCompareMissingKeyAsZero(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	info := scope.info
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		loop, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		if _, isMap := typeOrNil(info, loop.X).Underlying().(*types.Map); isMap {
			return true
		}
		key, ok := loop.Value.(*ast.Ident)
		if !ok || key.Name == "_" {
			return true
		}
		checked := commaOkMaps(loop.Body, key.Name)
		ast.Inspect(loop.Body, func(m ast.Node) bool {
			binary, ok := m.(*ast.BinaryExpr)
			if !ok || (binary.Op != token.NEQ && binary.Op != token.EQL) {
				return true
			}
			left, lok := ast.Unparen(binary.X).(*ast.IndexExpr)
			right, rok := ast.Unparen(binary.Y).(*ast.IndexExpr)
			if !lok || !rok || !isIdent(left.Index, key.Name) || !isIdent(right.Index, key.Name) {
				return true
			}
			leftMap, lm := typeOrNil(info, left.X).Underlying().(*types.Map)
			_, rm := typeOrNil(info, right.X).Underlying().(*types.Map)
			if !lm || !rm || !types.Identical(info.TypeOf(left.X), info.TypeOf(right.X)) || isBooleanType(leftMap.Elem()) {
				return true
			}
			if checked[types.ExprString(left.X)] || checked[types.ExprString(right.X)] {
				return true
			}
			found = append(found, funcFinding{binary, fmt.Sprintf("%s and %s are compared over keys not taken from them, with no check the key is there — a key one of them lacks reads as the zero value and counts as a difference",
				types.ExprString(left.X), types.ExprString(right.X))})
			return true
		})
		return true
	})
	return found
}

// commaOkMaps returns the maps the loop body looks the key up in with the
// comma-ok form.
func commaOkMaps(body *ast.BlockStmt, key string) map[string]bool {
	checked := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
			return true
		}
		if index, ok := ast.Unparen(assign.Rhs[0]).(*ast.IndexExpr); ok && isIdent(index.Index, key) {
			checked[types.ExprString(index.X)] = true
		}
		return true
	})
	return checked
}

// NewLiteralBypassesConstructorRule reports a struct literal that sets a part
// of the fields a constructor of the project without parameters sets:
//
//	func Options() *api.Options { return &api.Options{Raw: true, Score: true, Cloaked: true} }
//	...
//	Options: &api.Options{Raw: true, Score: true}   // misses Cloaked the rest of the code has
func NewLiteralBypassesConstructorRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule("literal-bypasses-constructor", "patterns",
			"Detects a struct literal that sets only part of the fields a parameterless constructor of the project sets — this place runs with settings the rest of the code does not have",
			core.SeverityMedium),
		suggestion: "Call the constructor, or set every field it sets",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		constructors := literalConstructors(decls)
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			return bypassedConstructors(scope.info, fn, constructors)
		}
	}
	return r
}

type literalConstructor struct {
	fn     *types.Func
	decl   *ast.FuncDecl
	fields map[string]bool
}

// literalConstructors returns the parameterless functions that return one
// keyed literal of a named struct, by the struct's type.
func literalConstructors(decls map[*types.Func]typedFuncDecl) map[*types.TypeName]literalConstructor {
	out := map[*types.TypeName]literalConstructor{}
	ambiguous := map[*types.TypeName]bool{}
	for fn, decl := range decls {
		sig := fn.Signature()
		if sig.Recv() != nil || sig.Params().Len() != 0 || sig.Results().Len() != 1 || len(decl.decl.Body.List) != 1 {
			continue
		}
		ret, ok := decl.decl.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			continue
		}
		lit := configLiteral(ret.Results[0])
		if lit == nil {
			continue
		}
		named := structNamedOf(decl.info.TypeOf(lit))
		if named == nil || len(lit.Elts) < 2 {
			continue
		}
		if !namesType(fn.Name(), named.Obj().Name()) {
			continue
		}
		if _, ok := out[named.Obj()]; ok {
			ambiguous[named.Obj()] = true
			continue
		}
		out[named.Obj()] = literalConstructor{fn, decl.decl, keyedFields(lit)}
	}
	// Two constructors of one type are two configurations; neither is the
	// one a literal should have called.
	for name := range ambiguous {
		delete(out, name)
	}
	return out
}

// namesType reports a constructor named for its type: NewOptions, Options or
// DefaultConfig for Config, Options for InterfaceOptions.
func namesType(fn, typ string) bool {
	fn, typ = strings.ToLower(fn), strings.ToLower(typ)
	return strings.HasSuffix(fn, typ) || strings.HasSuffix(typ, fn)
}

func structNamedOf(t types.Type) *types.Named {
	if pointer, ok := t.(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, _ := t.(*types.Named)
	if named == nil {
		return nil
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return nil
	}
	return named
}

func keyedFields(lit *ast.CompositeLit) map[string]bool {
	fields := map[string]bool{}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok {
				fields[key.Name] = true
			}
		}
	}
	return fields
}

func bypassedConstructors(info *types.Info, fn *ast.FuncDecl, constructors map[*types.TypeName]literalConstructor) []funcFinding {
	if len(constructors) == 0 {
		return nil
	}
	var found []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || len(lit.Elts) == 0 {
			return true
		}
		if _, keyed := lit.Elts[0].(*ast.KeyValueExpr); !keyed {
			return true
		}
		named := structNamedOf(info.TypeOf(lit))
		if named == nil {
			return true
		}
		ctor, ok := constructors[named.Obj()]
		if !ok || ctor.decl == fn {
			return true
		}
		fields := keyedFields(lit)
		var missing []string
		for field := range ctor.fields {
			if !fields[field] {
				missing = append(missing, field)
			}
		}
		for field := range fields {
			if !ctor.fields[field] {
				return true // sets something the constructor does not: a different configuration
			}
		}
		if len(missing) == 0 {
			return true
		}
		slices.Sort(missing)
		found = append(found, funcFinding{lit, fmt.Sprintf("%s is built in place with part of the fields %s sets — it lacks %s, which the rest of the code gets from %s",
			named.Obj().Name(), ctor.fn.Name(), strings.Join(missing, ", "), ctor.fn.Name())})
		return true
	})
	return found
}

package gorules

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() { rules.Register(NewDeepEqualShallowCopyRule()) }

// NewDeepEqualShallowCopyRule creates the shallow-copy comparison rule.
func NewDeepEqualShallowCopyRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{BaseRule: rules.NewBaseRule(
		"deep-equal-shallow-copy", "patterns",
		"Detects reflect.DeepEqual comparing a struct copy with its original when reference fields are shared",
		core.SeverityMedium,
	), Suggestion: "Use a deep copy (Clone), or compare the relevant fields before changing them"}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		if fn.Body == nil || scope.Info == nil {
			return nil
		}
		analyzer := &deepEqualFlow{info: scope.Info}
		(&patternkit.FlowWalker[[]deepEqualPath, struct{}]{Rule: analyzer}).Walk(fn.Body, []deepEqualPath{{copies: map[types.Object]deepEqualCopy{}, conditions: map[types.Object]bool{}, switches: map[string]string{}, aliases: map[types.Object]string{}}}, struct{}{})
		return analyzer.findings
	}
	return r
}

type deepEqualCopy struct {
	original     string
	originalType types.Type
	originalRoot types.Object
	valid        bool
	mutated      bool
}

type deepEqualPath struct {
	copies     map[types.Object]deepEqualCopy
	conditions map[types.Object]bool
	switches   map[string]string
	aliases    map[types.Object]string
}

type deepEqualFlow struct {
	info     *types.Info
	findings []patternkit.FuncFinding
	seen     map[token.Pos]bool
	closures map[types.Object]*ast.FuncLit
}

func (a *deepEqualFlow) CloneState(paths []deepEqualPath) []deepEqualPath {
	return cloneDeepEqualPaths(paths)
}

func (a *deepEqualFlow) JoinStates(left, right []deepEqualPath) []deepEqualPath {
	return patternkit.JoinFlowPaths(left, right, deepEqualPathKey)
}

func (*deepEqualFlow) LiveState(paths []deepEqualPath) bool { return len(paths) > 0 }
func (*deepEqualFlow) DeadState() []deepEqualPath           { return nil }
func (*deepEqualFlow) EnterScope(_ patternkit.FlowScopeKind, _ ast.Node, parent struct{}, state []deepEqualPath) (struct{}, []deepEqualPath) {
	return parent, state
}
func (*deepEqualFlow) LeaveScope(_ patternkit.FlowScopeKind, _ struct{}, _ *patternkit.FlowEdges[[]deepEqualPath]) {
}

func (a *deepEqualFlow) SimpleStmt(stmt ast.Stmt, paths []deepEqualPath, _ struct{}) ([]deepEqualPath, bool) {
	switch n := stmt.(type) {
	case *ast.AssignStmt:
		for _, rhs := range n.Rhs {
			a.inspectCalls(rhs, paths)
		}
		a.assign(n.Lhs, n.Rhs, paths)
	case *ast.DeclStmt:
		if decl, ok := n.Decl.(*ast.GenDecl); ok {
			for _, spec := range decl.Specs {
				if value, ok := spec.(*ast.ValueSpec); ok {
					for _, rhs := range value.Values {
						a.inspectCalls(rhs, paths)
					}
					lhs := make([]ast.Expr, len(value.Names))
					for i, id := range value.Names {
						lhs[i] = id
					}
					a.assign(lhs, value.Values, paths)
				}
			}
		}
	case *ast.ExprStmt:
		a.inspectCalls(n.X, paths)
	case *ast.ReturnStmt:
		for _, expr := range n.Results {
			a.inspectCalls(expr, paths)
		}
		return nil, true
	case *ast.DeferStmt:
		a.inspectDeferred(n.Call, paths)
	case *ast.GoStmt:
		a.inspectCalls(n.Call, paths)
	case *ast.SendStmt:
		a.markMutation(n.Chan, paths)
	case *ast.IncDecStmt:
		a.markMutation(n.X, paths)
	}
	return paths, false
}

func (a *deepEqualFlow) IfCondition(stmt *ast.IfStmt, paths []deepEqualPath, _ struct{}) ([]deepEqualPath, []deepEqualPath) {
	return a.condition(stmt.Cond, paths)
}

func (a *deepEqualFlow) FlowExpr(expr ast.Expr, paths []deepEqualPath, _ struct{}) []deepEqualPath {
	a.inspectCalls(expr, paths)
	return paths
}
func (*deepEqualFlow) RangeVars(_ *ast.RangeStmt, paths []deepEqualPath, _ struct{}) []deepEqualPath {
	return paths
}
func (a *deepEqualFlow) TypeSwitchGuard(stmt ast.Stmt, paths []deepEqualPath, scope struct{}) []deepEqualPath {
	next, _ := a.SimpleStmt(stmt, paths, scope)
	return next
}
func (a *deepEqualFlow) CaseClause(sw ast.Stmt, clause *ast.CaseClause, paths []deepEqualPath, parent struct{}) ([]deepEqualPath, struct{}) {
	for _, expr := range clause.List {
		a.inspectCalls(expr, paths)
	}
	switchStmt, ok := sw.(*ast.SwitchStmt)
	if !ok {
		return paths, parent
	}
	if switchStmt.Tag == nil {
		if len(clause.List) == 0 {
			remaining := cloneDeepEqualPaths(paths)
			for _, item := range switchStmt.Body.List {
				caseClause, ok := item.(*ast.CaseClause)
				if !ok || len(caseClause.List) == 0 {
					continue
				}
				for _, expr := range caseClause.List {
					_, remaining = a.condition(expr, remaining)
				}
			}
			return remaining, parent
		}
		remaining := cloneDeepEqualPaths(paths)
		var matching []deepEqualPath
		for _, expr := range clause.List {
			matched, unmatched := a.condition(expr, remaining)
			matching = a.JoinStates(matching, matched)
			remaining = unmatched
		}
		return matching, parent
	}
	key := a.exprKey(switchStmt.Tag)
	if key == "" {
		return paths, parent
	}
	values := make([]string, 0)
	for _, expr := range clause.List {
		value := a.info.Types[expr].Value
		if value == nil {
			return paths, parent
		}
		values = append(values, value.ExactString())
	}
	if len(clause.List) == 0 {
		for _, item := range switchStmt.Body.List {
			caseClause, ok := item.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range caseClause.List {
				value := a.info.Types[expr].Value
				if value == nil {
					return paths, parent
				}
				values = append(values, value.ExactString())
			}
		}
		return constrainSwitch(paths, key, values, true), parent
	}
	return constrainSwitch(paths, key, values, false), parent
}

func constrainSwitch(paths []deepEqualPath, key string, values []string, isDefault bool) []deepEqualPath {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	var out []deepEqualPath
	for _, p := range paths {
		old := p.switches[key]
		if value, ok := strings.CutPrefix(old, "="); ok {
			if set[value] == isDefault {
				continue
			}
			out = append(out, cloneDeepEqualPath(p))
			continue
		}
		excluded := map[string]bool{}
		if values, ok := strings.CutPrefix(old, "!"); ok {
			for value := range strings.SplitSeq(values, "\x00") {
				excluded[value] = true
			}
		}
		if isDefault {
			for value := range set {
				excluded[value] = true
			}
			values := slices.Sorted(maps.Keys(excluded))
			q := cloneDeepEqualPath(p)
			q.switches[key] = "!" + strings.Join(values, "\x00")
			out = append(out, q)
			continue
		}
		for _, value := range slices.Sorted(maps.Keys(set)) {
			if excluded[value] {
				continue
			}
			q := cloneDeepEqualPath(p)
			q.switches[key] = "=" + value
			out = append(out, q)
		}
	}
	return patternkit.JoinFlowPaths(nil, out, deepEqualPathKey)
}
func (*deepEqualFlow) CommClause(_ *ast.CommClause, paths []deepEqualPath, parent struct{}) ([]deepEqualPath, struct{}) {
	return paths, parent
}
func (*deepEqualFlow) Normalize(edges *patternkit.FlowEdges[[]deepEqualPath]) {
	edges.Next = patternkit.JoinFlowPaths(nil, edges.Next, deepEqualPathKey)
	edges.Breaks = patternkit.JoinFlowPaths(nil, edges.Breaks, deepEqualPathKey)
	edges.Continues = patternkit.JoinFlowPaths(nil, edges.Continues, deepEqualPathKey)
}

func (a *deepEqualFlow) condition(expr ast.Expr, paths []deepEqualPath) ([]deepEqualPath, []deepEqualPath) {
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return a.condition(paren.X, paths)
	}
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.NOT {
		no, yes := a.condition(unary.X, paths)
		return yes, no
	}
	if binary, ok := expr.(*ast.BinaryExpr); ok {
		if binary.Op == token.LAND {
			yes, no := a.condition(binary.X, paths)
			yes2, no2 := a.condition(binary.Y, yes)
			return yes2, a.JoinStates(no, no2)
		}
		if binary.Op == token.LOR {
			yes, no := a.condition(binary.X, paths)
			yes2, no2 := a.condition(binary.Y, no)
			return a.JoinStates(yes, yes2), no2
		}
	}
	a.inspectCalls(expr, paths)
	if id, ok := ast.Unparen(expr).(*ast.Ident); ok {
		if obj := a.info.Uses[id]; obj != nil {
			return a.constrain(paths, obj, true), a.constrain(paths, obj, false)
		}
	}
	return cloneDeepEqualPaths(paths), cloneDeepEqualPaths(paths)
}

func (a *deepEqualFlow) constrain(paths []deepEqualPath, obj types.Object, value bool) []deepEqualPath {
	var out []deepEqualPath
	for _, p := range paths {
		if old, exists := p.conditions[obj]; exists && old != value {
			continue
		}
		q := cloneDeepEqualPath(p)
		q.conditions[obj] = value
		out = append(out, q)
	}
	return out
}

func (a *deepEqualFlow) assign(lhs, rhs []ast.Expr, paths []deepEqualPath) {
	for pathIndex := range paths {
		p := &paths[pathIndex]
		for _, target := range lhs {
			a.applyWrite(target, p)
		}
		for i, target := range lhs {
			id, ok := ast.Unparen(target).(*ast.Ident)
			if !ok {
				continue
			}
			obj := a.info.Defs[id]
			if obj == nil {
				obj = a.info.Uses[id]
			}
			if obj == nil {
				continue
			}
			if a.closures == nil {
				a.closures = make(map[types.Object]*ast.FuncLit)
			}
			delete(a.closures, obj)
			if i < len(rhs) {
				if literal, ok := ast.Unparen(rhs[i]).(*ast.FuncLit); ok {
					a.closures[obj] = literal
				} else if source, ok := ast.Unparen(rhs[i]).(*ast.Ident); ok {
					if sourceObj := a.info.Uses[source]; sourceObj != nil && a.closures[sourceObj] != nil {
						a.closures[obj] = a.closures[sourceObj]
					}
				}
			}
			delete(p.aliases, obj)
			if i >= len(rhs) {
				continue
			}
			if alias := a.sharedAlias(rhs[i], p); alias != "" {
				p.aliases[obj] = alias
			}
			original, typ, ok := a.copySource(rhs[i])
			root := a.exprRootObject(rhs[i])
			if !ok || !a.hasSharedReference(typ, root) {
				continue
			}
			p.copies[obj] = deepEqualCopy{original: original, originalType: typ, originalRoot: root, valid: true}
		}
	}
}

func (a *deepEqualFlow) applyWrite(lhs ast.Expr, p *deepEqualPath) {
	path := dereferenceRoot(a.exprKey(lhs))
	if _, reassignedAlias := ast.Unparen(lhs).(*ast.Ident); !reassignedAlias {
		if aliasPath := a.aliasPath(lhs, p); aliasPath != "" {
			path = aliasPath
		}
	}
	for obj, copy := range p.copies {
		if !copy.valid {
			continue
		}
		if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
			indexObj := a.info.Uses[id]
			if indexObj == nil {
				indexObj = a.info.Defs[id]
			}
			if indexObj != nil && strings.Contains(copy.original, "[var:"+objectKey(indexObj)+"]") {
				copy.valid = false
				p.copies[obj] = copy
				continue
			}
		}
		copyExpr := "var:" + objectKey(obj)
		originalRoot := dereferenceRoot(copy.original)
		if path == copyExpr || path == originalRoot || isDescendant(copyExpr, path) || isDescendant(originalRoot, path) {
			copy.valid = false
			p.copies[obj] = copy
			continue
		}
		if isDescendant(path, copyExpr) || isDescendant(path, originalRoot) {
			if a.referenceReplacement(lhs) {
				copy.valid = false
			} else if a.sharedReferentWrite(lhs, copyExpr, originalRoot, p) {
				copy.mutated = true
			}
			p.copies[obj] = copy
		}
	}
}

func (a *deepEqualFlow) invalidateEscapedIndexVariables(call *ast.CallExpr, paths []deepEqualPath) {
	if call == nil {
		return
	}
	for _, arg := range call.Args {
		ast.Inspect(arg, func(node ast.Node) bool {
			address, ok := node.(*ast.UnaryExpr)
			if !ok || address.Op != token.AND {
				return true
			}
			id, ok := ast.Unparen(address.X).(*ast.Ident)
			if !ok {
				return true
			}
			obj := a.info.Uses[id]
			if obj == nil {
				obj = a.info.Defs[id]
			}
			if obj == nil {
				return true
			}
			for i := range paths {
				for copyObj, copy := range paths[i].copies {
					if copy.valid && strings.Contains(copy.original, "[var:"+objectKey(obj)+"]") {
						copy.valid = false
						paths[i].copies[copyObj] = copy
					}
				}
			}
			return true
		})
	}
}

func (a *deepEqualFlow) inspectDeferred(expr ast.Expr, paths []deepEqualPath) {
	literal, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return
	}
	fn, ok := ast.Unparen(literal.Fun).(*ast.FuncLit)
	if !ok {
		return
	}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && isReflectDeepEqual(a.info, call) {
			a.checkCall(call, paths)
		}
		return true
	})
}

func (a *deepEqualFlow) markMutation(expr ast.Expr, paths []deepEqualPath) {
	for i := range paths {
		a.applyWrite(expr, &paths[i])
	}
}

func (a *deepEqualFlow) inspectCalls(expr ast.Expr, paths []deepEqualPath) {
	ast.Inspect(expr, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.FuncLit:
			ast.Inspect(n.Body, func(inner ast.Node) bool {
				if call, ok := inner.(*ast.CallExpr); ok && isReflectDeepEqual(a.info, call) {
					a.checkCall(call, paths)
				}
				return true
			})
			return false
		case *ast.CallExpr:
			a.checkCall(n, paths)
		}
		return true
	})
}

func (a *deepEqualFlow) checkCall(call *ast.CallExpr, paths []deepEqualPath) {
	a.invalidateEscapedIndexVariables(call, paths)
	if !isReflectDeepEqual(a.info, call) {
		a.markCallAccess(call, paths)
		return
	}
	if len(call.Args) != 2 {
		return
	}
	if a.seen == nil {
		a.seen = map[token.Pos]bool{}
	}
	if a.seen[call.Pos()] {
		return
	}
	for _, p := range paths {
		for obj, copy := range p.copies {
			if !copy.valid || !copy.mutated {
				continue
			}
			if (a.exprKey(call.Args[0]) == "var:"+objectKey(obj) && a.exprKey(call.Args[1]) == copy.original) || (a.exprKey(call.Args[1]) == "var:"+objectKey(obj) && a.exprKey(call.Args[0]) == copy.original) {
				a.findings = append(a.findings, patternkit.FuncFinding{Node: call, Message: "the struct copy shares reference fields with the original, so changes through them are invisible to this comparison"})
				a.seen[call.Pos()] = true
				return
			}
		}
	}
}

func (a *deepEqualFlow) markCallAccess(call *ast.CallExpr, paths []deepEqualPath) {
	for i := range paths {
		for obj, copy := range paths[i].copies {
			if !copy.valid || !a.callCanAccessOriginal(call, obj, copy, &paths[i]) {
				continue
			}
			copy.mutated = true
			paths[i].copies[obj] = copy
		}
	}
}

func (a *deepEqualFlow) callCanAccessOriginal(call *ast.CallExpr, copyObj types.Object, copy deepEqualCopy, path *deepEqualPath) bool {
	if call == nil || copy.originalRoot == nil {
		return false
	}
	if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if a.exprCanAccessOriginal(selector.X, copy, path) || a.exprCanAccessCopy(selector.X, copyObj, copy, path) {
			return true
		}
		if a.exprKey(selector.X) == "var:"+objectKey(copyObj) && a.hasSharedReference(copy.originalType, copy.originalRoot) {
			return true
		}
	}
	for _, arg := range call.Args {
		if a.exprCanAccessOriginal(arg, copy, path) || a.exprCanAccessCopy(arg, copyObj, copy, path) {
			return true
		}
		if a.closureCapturesOriginal(arg, copy.originalRoot) {
			return true
		}
	}
	if literal, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
		return a.closureCapturesOriginal(literal, copy.originalRoot)
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if obj := a.info.Uses[id]; obj != nil && a.closureCapturesOriginal(a.closures[obj], copy.originalRoot) {
			return true
		}
	}
	return false
}

func (a *deepEqualFlow) closureCapturesOriginal(expr ast.Expr, root types.Object) bool {
	literal, ok := ast.Unparen(expr).(*ast.FuncLit)
	if !ok || literal == nil || root == nil {
		return false
	}
	captured := false
	ast.Inspect(literal.Body, func(node ast.Node) bool {
		id, ok := node.(*ast.Ident)
		if ok && a.info.Uses[id] == root {
			captured = true
			return false
		}
		return !captured
	})
	return captured
}

func (a *deepEqualFlow) exprCanAccessOriginal(expr ast.Expr, copy deepEqualCopy, path *deepEqualPath) bool {
	key := a.exprKey(expr)
	if alias := a.aliasPath(expr, path); alias != "" {
		key = alias
	}
	for len(key) > len("addr()") && key[:len("addr(")] == "addr(" && key[len(key)-1] == ')' {
		key = key[len("addr(") : len(key)-1]
	}
	root := "var:" + objectKey(copy.originalRoot)
	if key == root {
		return a.hasSharedReference(copy.originalType, copy.originalRoot)
	}
	if isDescendant(key, root) {
		return a.hasSharedReference(a.info.TypeOf(expr), copy.originalRoot)
	}
	return false
}

func (a *deepEqualFlow) exprCanAccessCopy(expr ast.Expr, copyObj types.Object, copy deepEqualCopy, path *deepEqualPath) bool {
	key := a.exprKey(expr)
	if alias := a.aliasPath(expr, path); alias != "" {
		key = alias
	}
	root := "var:" + objectKey(copyObj)
	if key == root {
		return a.hasSharedReference(copy.originalType, copy.originalRoot)
	}
	if isDescendant(key, root) {
		return a.hasSharedReference(a.info.TypeOf(expr), copy.originalRoot)
	}
	return false
}

func (a *deepEqualFlow) exprRootObject(expr ast.Expr) types.Object {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if obj := a.info.Uses[e]; obj != nil {
			return obj
		}
		return a.info.Defs[e]
	case *ast.StarExpr:
		return a.exprRootObject(e.X)
	case *ast.SelectorExpr:
		return a.exprRootObject(e.X)
	case *ast.IndexExpr:
		return a.exprRootObject(e.X)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return a.exprRootObject(e.X)
		}
	}
	return nil
}

func isReflectDeepEqual(info *types.Info, call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "DeepEqual" {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "reflect"
}

func (a *deepEqualFlow) copySource(expr ast.Expr) (string, types.Type, bool) {
	expr = ast.Unparen(expr)
	var typ types.Type
	switch e := expr.(type) {
	case *ast.Ident:
		typ = a.info.TypeOf(e)
	case *ast.SelectorExpr:
		typ = a.info.TypeOf(e)
	case *ast.StarExpr:
		typ = a.info.TypeOf(e)
	case *ast.IndexExpr:
		typ = a.info.TypeOf(e)
	default:
		return "", nil, false
	}
	if typ == nil {
		return "", nil, false
	}
	if _, ok := types.Unalias(typ).Underlying().(*types.Struct); !ok {
		return "", nil, false
	}
	key := a.exprKey(expr)
	if key == "" {
		return "", nil, false
	}
	return key, typ, true
}

func (a *deepEqualFlow) exprKey(expr ast.Expr) string {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		obj := a.info.Uses[e]
		if obj == nil {
			obj = a.info.Defs[e]
		}
		if obj == nil {
			return ""
		}
		return "var:" + objectKey(obj)
	case *ast.StarExpr:
		return "deref(" + a.exprKey(e.X) + ")"
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return "addr(" + a.exprKey(e.X) + ")"
		}
	case *ast.SelectorExpr:
		field := a.info.Selections[e]
		if field == nil {
			return ""
		}
		return a.exprKey(e.X) + ".field:" + objectKey(field.Obj())
	case *ast.IndexExpr:
		key := a.exprKey(e.X)
		if key == "" {
			return ""
		}
		if value := a.info.Types[e.Index].Value; value != nil {
			return key + "[const:" + strconv.Quote(value.ExactString()) + "]"
		}
		if id, ok := ast.Unparen(e.Index).(*ast.Ident); ok {
			if obj := a.info.Uses[id]; obj != nil {
				return key + "[var:" + objectKey(obj) + "]"
			}
		}
		return key + "[unknown:" + patternkit.FlowPosKey(e.Index.Pos()) + "]"
	}
	return ""
}

func objectKey(obj types.Object) string {
	pkg := ""
	if obj.Pkg() != nil {
		pkg = obj.Pkg().Path()
	}
	return pkg + ":" + obj.Name() + ":" + patternkit.FlowPosKey(obj.Pos())
}
func isDescendant(path, root string) bool {
	return len(path) > len(root) && path[:len(root)] == root && (path[len(root)] == '.' || path[len(root)] == '[' || path[len(root)] == '(')
}
func dereferenceRoot(path string) string {
	for len(path) > len("deref()") && path[:len("deref(")] == "deref(" && path[len(path)-1] == ')' {
		path = path[len("deref(") : len(path)-1]
	}
	return path
}

func (a *deepEqualFlow) sharedReferentWrite(lhs ast.Expr, copyRoot, originalRoot string, p *deepEqualPath) bool {
	sharedBase := func(expr ast.Expr) bool {
		key := dereferenceRoot(a.exprKey(expr))
		if alias := a.aliasPath(expr, p); alias != "" {
			key = alias
		}
		return isDescendant(key, copyRoot) || isDescendant(key, originalRoot)
	}
	switch e := ast.Unparen(lhs).(type) {
	case *ast.IndexExpr:
		t := a.info.TypeOf(e.X)
		if t == nil || !sharedBase(e.X) {
			return false
		}
		switch types.Unalias(t).Underlying().(type) {
		case *types.Map, *types.Slice:
			return true
		}
	case *ast.StarExpr:
		return sharedBase(e.X)
	case *ast.SelectorExpr:
		if receiver := a.info.TypeOf(e.X); receiver != nil && sharedBase(e.X) {
			if _, ok := types.Unalias(receiver).Underlying().(*types.Pointer); ok {
				return true
			}
		}
	}
	if typ := a.info.TypeOf(lhs); typ != nil && sharedBase(lhs) {
		if _, ok := types.Unalias(typ).Underlying().(*types.Chan); ok {
			return true
		}
	}
	return false
}

func (a *deepEqualFlow) sharedAlias(expr ast.Expr, p *deepEqualPath) string {
	if expr == nil || !isReferenceType(a.info.TypeOf(expr)) {
		return ""
	}
	key := dereferenceRoot(a.exprKey(expr))
	if id, ok := ast.Unparen(expr).(*ast.Ident); ok {
		if source := a.info.Uses[id]; source != nil {
			if alias := p.aliases[source]; alias != "" {
				return alias
			}
		}
	}
	for obj, copy := range p.copies {
		if !copy.valid {
			continue
		}
		if isDescendant(key, "var:"+objectKey(obj)) || isDescendant(key, dereferenceRoot(copy.original)) {
			return key
		}
	}
	return key
}

func (a *deepEqualFlow) aliasPath(expr ast.Expr, p *deepEqualPath) string {
	key := a.exprKey(expr)
	objects := make([]types.Object, 0, len(p.aliases))
	for obj := range p.aliases {
		objects = append(objects, obj)
	}
	sort.Slice(objects, func(i, j int) bool { return objectKey(objects[i]) < objectKey(objects[j]) })
	for _, obj := range objects {
		alias := p.aliases[obj]
		prefix := "var:" + objectKey(obj)
		if key == prefix {
			return alias
		}
		if isDescendant(key, prefix) {
			return alias + key[len(prefix):]
		}
	}
	return ""
}

func isReferenceType(typ types.Type) bool {
	if typ == nil {
		return false
	}
	switch types.Unalias(typ).Underlying().(type) {
	case *types.Map, *types.Slice, *types.Pointer, *types.Chan, *types.Interface:
		return true
	}
	return false
}

func (a *deepEqualFlow) referenceReplacement(lhs ast.Expr) bool {
	t := a.info.TypeOf(lhs)
	if t == nil {
		return false
	}
	switch types.Unalias(t).Underlying().(type) {
	case *types.Map, *types.Slice, *types.Pointer, *types.Chan, *types.Interface:
		return true
	}
	return false
}

func (a *deepEqualFlow) hasSharedReference(typ types.Type, root types.Object) bool {
	pkg := (*types.Package)(nil)
	if root != nil {
		pkg = root.Pkg()
	}
	return hasSharedReference(typ, pkg, map[types.Type]bool{})
}

func hasSharedReference(typ types.Type, pkg *types.Package, seen map[types.Type]bool) bool {
	if typ == nil {
		return false
	}
	typ = types.Unalias(typ)
	if seen[typ] {
		return false
	}
	seen[typ] = true
	switch t := typ.Underlying().(type) {
	case *types.Struct:
		for field := range t.Fields() {
			if !field.Exported() && field.Pkg() != pkg {
				continue
			}
			if hasSharedReference(field.Type(), pkg, seen) {
				return true
			}
		}
	case *types.Array:
		return hasSharedReference(t.Elem(), pkg, seen)
	case *types.Map, *types.Slice, *types.Pointer, *types.Chan, *types.Interface:
		return true
	}
	return false
}

func cloneDeepEqualPaths(paths []deepEqualPath) []deepEqualPath {
	out := make([]deepEqualPath, len(paths))
	for i, p := range paths {
		out[i] = cloneDeepEqualPath(p)
	}
	return out
}
func cloneDeepEqualPath(p deepEqualPath) deepEqualPath {
	q := deepEqualPath{copies: make(map[types.Object]deepEqualCopy, len(p.copies)), conditions: make(map[types.Object]bool, len(p.conditions)), switches: make(map[string]string, len(p.switches)), aliases: make(map[types.Object]string, len(p.aliases))}
	maps.Copy(q.copies, p.copies)
	maps.Copy(q.conditions, p.conditions)
	maps.Copy(q.switches, p.switches)
	maps.Copy(q.aliases, p.aliases)
	return q
}
func deepEqualPathKey(p deepEqualPath) string {
	parts := make([]string, 0, len(p.copies)+len(p.conditions)+len(p.switches)+len(p.aliases))
	for obj, c := range p.copies {
		parts = append(parts, objectKey(obj)+"="+c.original+":"+boolKey(c.valid)+":"+boolKey(c.mutated))
	}
	for obj, v := range p.conditions {
		parts = append(parts, "if:"+objectKey(obj)+"="+boolKey(v))
	}
	for key, value := range p.switches {
		parts = append(parts, "switch:"+key+"="+value)
	}
	for obj, alias := range p.aliases {
		parts = append(parts, "alias:"+objectKey(obj)+"="+alias)
	}
	sort.Strings(parts)
	return patternkit.FlowPathKey(parts...)
}
func boolKey(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

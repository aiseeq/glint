package errrules

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() { rules.Register(NewPartialFlagUnreadRule()) }

// PartialFlagUnreadRule detects a function reading a result field without
// checking the result's incompleteness flag:
//
//	type Breakdown struct { TotalUsd int; VaultIncomplete bool }
//	func total() int { b, _ := loadBreakdown(); return b.TotalUsd }
//
// Not flagged: functions that check or pass on the flag, return or pass the
// whole structure, set the flag, accept the structure as a parameter, or are
// methods or constructors of the structure itself.
type PartialFlagUnreadRule struct{ *rules.BaseRule }

// NewPartialFlagUnreadRule creates the rule.
func NewPartialFlagUnreadRule() *PartialFlagUnreadRule {
	return &PartialFlagUnreadRule{BaseRule: rules.NewBaseRule(
		"partial-flag-unread", "patterns",
		"Detects a result field read without checking its incompleteness flag",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op because the result type and its flag may be declared
// in another package.
func (r *PartialFlagUnreadRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *PartialFlagUnreadRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports reads from call results whose partial flag is unread.
func (r *PartialFlagUnreadRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	functions := indexPartialFunctions(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		return patternkit.AnalyzeGoFunctions(file, func(fn *ast.FuncDecl) []*core.Violation {
			return r.checkFunction(file, info, fn, functions)
		})
	})
}

var partialFlagParts = []string{"incomplete", "partial", "truncated", "stale", "approximate", "degraded"}

func (r *PartialFlagUnreadRule) checkFunction(file *core.FileContext, info *types.Info, fn *ast.FuncDecl, functions map[*types.Func]partialTypedFunction) []*core.Violation {
	if fn.Body == nil || isPartialStructMethodOrConstructor(info, fn) {
		return nil
	}
	candidates := partialFlagCandidates(info, fn)
	if len(candidates) == 0 {
		return nil
	}
	usage := inspectPartialUsage(info, fn, candidates)
	return r.firstUnreadFlagFinding(file, info, fn, usage, functions)
}

type partialTypedFunction struct {
	decl *ast.FuncDecl
	info *types.Info
}

func indexPartialFunctions(ctx *core.GoProjectContext) map[*types.Func]partialTypedFunction {
	functions := make(map[*types.Func]partialTypedFunction)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name == nil || fn.Body == nil {
					continue
				}
				if obj, ok := pkg.Package.TypesInfo.Defs[fn.Name].(*types.Func); ok {
					functions[obj] = partialTypedFunction{decl: fn, info: pkg.Package.TypesInfo}
				}
			}
		}
	}
	return functions
}

type partialFlag struct {
	field  *types.Var
	scope  []*types.Var
	prefix string
}

func partialFlagCandidates(info *types.Info, fn *ast.FuncDecl) map[types.Object]types.Type {
	params := make(map[types.Object]bool)
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			for _, name := range field.Names {
				if obj := info.ObjectOf(name); obj != nil {
					params[obj] = true
				}
			}
		}
	}
	candidates := make(map[types.Object]types.Type)
	cache := make(map[types.Type]bool)
	add := func(id *ast.Ident, resultType types.Type) {
		obj := info.ObjectOf(id)
		if obj == nil || params[obj] {
			return
		}
		if resultType == nil {
			resultType = obj.Type()
		}
		if containsPartialFlag(resultType, cache, make(map[types.Type]bool)) {
			candidates[obj] = resultType
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			if call, ok := callExpression(stmt.Rhs); ok {
				for i, lhs := range stmt.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						add(id, callResultType(info, call, i))
					}
				}
			}
		case *ast.ValueSpec:
			if call, ok := callExpression(stmt.Values); ok {
				for i, id := range stmt.Names {
					add(id, callResultType(info, call, i))
				}
			}
		}
		return true
	})
	return candidates
}

func callExpression(exprs []ast.Expr) (*ast.CallExpr, bool) {
	if len(exprs) != 1 {
		return nil, false
	}
	call, ok := ast.Unparen(exprs[0]).(*ast.CallExpr)
	return call, ok
}

func callResultType(info *types.Info, call *ast.CallExpr, index int) types.Type {
	t := info.TypeOf(call)
	if tuple, ok := t.(*types.Tuple); ok {
		if index >= tuple.Len() {
			return nil
		}
		return tuple.At(index).Type()
	}
	if index == 0 {
		return t
	}
	return nil
}

func candidateCall(info *types.Info, fn *ast.FuncDecl, target types.Object) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			if call, ok := callExpression(stmt.Rhs); ok {
				for i, lhs := range stmt.Lhs {
					id, ok := lhs.(*ast.Ident)
					if ok && info.ObjectOf(id) == target && callResultType(info, call, i) != nil {
						found = call
						return false
					}
				}
			}
		case *ast.ValueSpec:
			if call, ok := callExpression(stmt.Values); ok {
				for i, id := range stmt.Names {
					if info.ObjectOf(id) == target && callResultType(info, call, i) != nil {
						found = call
						return false
					}
				}
			}
		}
		return true
	})
	return found
}

type budgetGuard struct {
	parameter int
	field     string
}

func budgetDisabledAtCall(info *types.Info, call *ast.CallExpr, flags []partialFlag, functions map[*types.Func]partialTypedFunction) bool {
	if call == nil {
		return false
	}
	fn := calledPartialFunction(info, call)
	typed, ok := functions[fn]
	if !ok {
		return false
	}
	guards, unsafe := partialFlagBudgetWrites(typed)
	for _, flag := range flags {
		writes := guards[flag.field]
		if unsafe[flag.field] || len(writes) == 0 {
			return false
		}
		for _, guard := range writes {
			if guard.parameter >= len(call.Args) || !literalFieldIsZero(info, call.Args[guard.parameter], guard.field) {
				return false
			}
		}
	}
	return len(flags) > 0
}

func calledPartialFunction(info *types.Info, call *ast.CallExpr) *types.Func {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		obj, _ := info.Uses[fun].(*types.Func)
		return obj
	case *ast.SelectorExpr:
		if selection := info.Selections[fun]; selection != nil {
			obj, _ := selection.Obj().(*types.Func)
			return obj
		}
		obj, _ := info.Uses[fun.Sel].(*types.Func)
		return obj
	}
	return nil
}

func partialFlagBudgetWrites(typed partialTypedFunction) (map[*types.Var][]budgetGuard, map[*types.Var]bool) {
	guards := make(map[*types.Var][]budgetGuard)
	unsafe := make(map[*types.Var]bool)
	if typed.decl.Type.Params == nil {
		return guards, unsafe
	}
	params := make(map[types.Object]int)
	index := 0
	for _, field := range typed.decl.Type.Params.List {
		for _, name := range field.Names {
			params[typed.info.ObjectOf(name)] = index
			index++
		}
	}
	ast.Inspect(typed.decl.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
			if !ok {
				continue
			}
			root, path := selectorPath(typed.info, sel)
			id, ok := root.(*types.Var)
			if !ok || id.IsField() || len(path) == 0 {
				continue
			}
			flag := path[len(path)-1]
			if !isPartialFlag(flag) {
				continue
			}
			if i >= len(assign.Rhs) || !isTrueBoolean(typed.info, assign.Rhs[i]) {
				unsafe[flag] = true
				continue
			}
			guard, ok := enclosingBudgetGuard(typed, assign, params)
			if !ok {
				unsafe[flag] = true
				continue
			}
			guards[flag] = append(guards[flag], guard)
		}
		return true
	})
	return guards, unsafe
}

func enclosingBudgetGuard(typed partialTypedFunction, node ast.Node, params map[types.Object]int) (budgetGuard, bool) {
	var guard budgetGuard
	found := false
	var parents []ast.Node
	ast.Inspect(typed.decl.Body, func(n ast.Node) bool {
		if n == nil {
			if len(parents) > 0 {
				parents = parents[:len(parents)-1]
			}
			return false
		}
		if n == node {
			for i := len(parents) - 1; i >= 0; i-- {
				if conditional, ok := parents[i].(*ast.IfStmt); ok && nodeWithin(conditional.Body, node) {
					if candidate, ok := positiveBudgetGuard(typed.info, conditional.Cond, params); ok {
						guard, found = candidate, true
						return false
					}
				}
			}
			return false
		}
		parents = append(parents, n)
		return true
	})
	return guard, found
}

func nodeWithin(root ast.Node, target ast.Node) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if n == target {
			found = true
			return false
		}
		return !found
	})
	return found
}

func positiveBudgetGuard(info *types.Info, expr ast.Expr, params map[types.Object]int) (budgetGuard, bool) {
	if binary, ok := ast.Unparen(expr).(*ast.BinaryExpr); ok && binary.Op == token.LAND {
		if guard, ok := positiveBudgetGuard(info, binary.X, params); ok {
			return guard, true
		}
		return positiveBudgetGuard(info, binary.Y, params)
	}
	binary, ok := ast.Unparen(expr).(*ast.BinaryExpr)
	if !ok || (binary.Op != token.GTR && binary.Op != token.NEQ) || !isZeroBudgetConstant(info, binary.Y) {
		return budgetGuard{}, false
	}
	root, fields := selectorPath(info, selectorExpr(binary.X))
	parameter, ok := params[root]
	if !ok || len(fields) == 0 {
		return budgetGuard{}, false
	}
	return budgetGuard{parameter: parameter, field: fields[len(fields)-1].Name()}, true
}

func selectorExpr(expr ast.Expr) *ast.SelectorExpr {
	sel, _ := ast.Unparen(expr).(*ast.SelectorExpr)
	return sel
}

func isZeroBudgetConstant(info *types.Info, expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	value := info.Types[expr].Value
	return value != nil && constant.Sign(value) == 0
}

func isTrueBoolean(info *types.Info, expr ast.Expr) bool {
	value := info.Types[expr].Value
	return value != nil && value.Kind() == constant.Bool && constant.BoolVal(value)
}

func literalFieldIsZero(info *types.Info, expr ast.Expr, fieldName string) bool {
	expr = ast.Unparen(expr)
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = ast.Unparen(unary.X)
	}
	literal, ok := expr.(*ast.CompositeLit)
	if !ok {
		return false
	}
	t := types.Unalias(info.TypeOf(literal))
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	if named, ok := t.(*types.Named); ok {
		t = named.Underlying()
	}
	structure, ok := t.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	fieldIndex := -1
	for i := 0; i < structure.NumFields(); i++ {
		if structure.Field(i).Name() == fieldName {
			fieldIndex = i
			break
		}
	}
	if fieldIndex < 0 {
		return false
	}
	for i, elt := range literal.Elts {
		if keyed, ok := elt.(*ast.KeyValueExpr); ok {
			key, ok := keyed.Key.(*ast.Ident)
			if ok && key.Name == fieldName {
				return isZeroBudgetConstant(info, keyed.Value)
			}
			continue
		}
		if i == fieldIndex {
			return isZeroBudgetConstant(info, elt)
		}
	}
	return true
}

type partialUsage struct {
	flagRead    map[types.Object]map[string]bool
	written     map[types.Object]map[string]bool
	passedWhole map[types.Object]bool
	fieldReads  map[types.Object]map[string]partialFieldRead
	readOrder   []partialReadEvent
}

type partialFieldRead struct {
	selector *ast.SelectorExpr
	flag     partialFlag
}

type partialReadEvent struct {
	root types.Object
	key  string
}

type partialReadGroup struct {
	root     types.Object
	selector *ast.SelectorExpr
}

func inspectPartialUsage(info *types.Info, fn *ast.FuncDecl, candidates map[types.Object]types.Type) *partialUsage {
	u := &partialUsage{
		flagRead: make(map[types.Object]map[string]bool), written: make(map[types.Object]map[string]bool),
		passedWhole: make(map[types.Object]bool), fieldReads: make(map[types.Object]map[string]partialFieldRead),
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool { return u.visit(info, fn.Body, n, candidates) })
	return u
}

func (u *partialUsage) visit(info *types.Info, body *ast.BlockStmt, n ast.Node, candidates map[types.Object]types.Type) bool {
	switch node := n.(type) {
	case *ast.AssignStmt:
		for _, lhs := range node.Lhs {
			markFlagWrite(info, lhs, candidates, u.written)
		}
	case *ast.IncDecStmt:
		markFlagWrite(info, node.X, candidates, u.written)
	case *ast.CallExpr:
		u.markWholeValues(info, node.Args, candidates)
	case *ast.ReturnStmt:
		u.markWholeValues(info, node.Results, candidates)
	case *ast.SelectorExpr:
		u.markFieldRead(info, body, node, candidates)
	}
	return true
}

func (u *partialUsage) markWholeValues(info *types.Info, exprs []ast.Expr, candidates map[types.Object]types.Type) {
	for _, expr := range exprs {
		id, ok := ast.Unparen(expr).(*ast.Ident)
		if ok {
			if obj := info.ObjectOf(id); candidates[obj] != nil {
				u.passedWhole[obj] = true
			}
		}
	}
}

func (u *partialUsage) markFieldRead(info *types.Info, body *ast.BlockStmt, sel *ast.SelectorExpr, candidates map[types.Object]types.Type) {
	selection := info.Selections[sel]
	if selection == nil {
		return
	}
	if _, isField := selection.Obj().(*types.Var); !isField {
		return
	}
	root, fields := selectorPath(info, sel)
	resultType, ok := candidates[root]
	if !ok || len(fields) == 0 {
		return
	}
	flags := partialFlagsAlongPath(resultType, fields[:len(fields)-1])
	readFlag := fields[len(fields)-1]
	if isPartialFlag(readFlag) {
		for _, flag := range flags {
			if flag.field == readFlag {
				u.markFlagRead(root, flag)
			}
		}
		return
	}
	if isPartialIndicatorList(readFlag) {
		for _, flag := range flags {
			if samePartialPath(flag.scope, fields[:len(fields)-1]) {
				u.markFlagRead(root, flag)
			}
		}
		return
	}
	applicable := make([]partialFlag, 0, len(flags))
	for _, flag := range flags {
		if partialFieldMatchesPrefix(readFlag.Name(), flag.prefix) {
			applicable = append(applicable, flag)
		}
	}
	if len(applicable) > 0 && !selectorIsAssignmentLHS(body, sel) && !selectorIsNestedReceiver(body, sel) {
		if u.fieldReads[root] == nil {
			u.fieldReads[root] = make(map[string]partialFieldRead)
		}
		for _, flag := range applicable {
			key := partialFlagKey(flag)
			if _, exists := u.fieldReads[root][key]; exists {
				continue
			}
			u.fieldReads[root][key] = partialFieldRead{selector: sel, flag: flag}
			u.readOrder = append(u.readOrder, partialReadEvent{root: root, key: key})
		}
	}
}

func (u *partialUsage) markFlagRead(root types.Object, flag partialFlag) {
	if u.flagRead[root] == nil {
		u.flagRead[root] = make(map[string]bool)
	}
	u.flagRead[root][partialFlagKey(flag)] = true
}

func (r *PartialFlagUnreadRule) firstUnreadFlagFinding(file *core.FileContext, info *types.Info, fn *ast.FuncDecl, usage *partialUsage, functions map[*types.Func]partialTypedFunction) []*core.Violation {
	var findings []*core.Violation
	groups := make(map[partialReadGroup][]partialFlag)
	var groupOrder []partialReadGroup
	for _, event := range usage.readOrder {
		read := usage.fieldReads[event.root][event.key]
		group := partialReadGroup{root: event.root, selector: read.selector}
		if _, exists := groups[group]; !exists {
			groupOrder = append(groupOrder, group)
		}
		groups[group] = append(groups[group], read.flag)
	}
	for _, group := range groupOrder {
		obj := group.root
		if usage.passedWhole[obj] {
			continue
		}
		var unread []partialFlag
		for _, flag := range groups[group] {
			key := partialFlagKey(flag)
			if !usage.written[obj][key] && !usage.flagRead[obj][key] {
				unread = append(unread, flag)
			}
		}
		if len(unread) == 0 {
			continue
		}
		call := candidateCall(info, fn, obj)
		if budgetDisabledAtCall(info, call, unread, functions) {
			continue
		}
		flags := make([]string, 0, len(unread))
		for _, flag := range unread {
			flags = append(flags, flag.field.Name())
		}
		sort.Strings(flags)
		findings = append(findings, r.finding(file, info, group.selector, flags[0])...)
	}
	return findings
}

func (r *PartialFlagUnreadRule) finding(file *core.FileContext, info *types.Info, fieldRead *ast.SelectorExpr, flagName string) []*core.Violation {
	line := file.LineFor(fieldRead)
	if file.IsSuppressed(line, r.Name()) {
		return nil
	}
	v := r.CreateViolation(file.RelPath, line, fmt.Sprintf("Field %s is read from a result with unread incompleteness flag %s", selectorFieldName(info, fieldRead), flagName))
	v.WithCode(strings.TrimSpace(file.GetLine(line)))
	v.WithSuggestion("Check or propagate " + flagName + " before using fields from this result")
	return []*core.Violation{v}
}

func isPartialFlag(field *types.Var) bool {
	return field != nil && types.Unalias(field.Type()).Underlying() == types.Typ[types.Bool] && containsPartialFlagPart(field.Name())
}

func structType(t types.Type) *types.Struct {
	t = types.Unalias(t)
	for {
		switch value := t.(type) {
		case *types.Pointer:
			t = types.Unalias(value.Elem())
		case *types.Named:
			t = types.Unalias(value.Underlying())
		default:
			structure, _ := t.(*types.Struct)
			return structure
		}
	}
}

func containsPartialFlag(t types.Type, cache, active map[types.Type]bool) bool {
	result, _ := containsPartialFlagVisit(t, cache, active)
	return result
}

func containsPartialFlagVisit(t types.Type, cache, active map[types.Type]bool) (bool, bool) {
	t = types.Unalias(t)
	if result, ok := cache[t]; ok {
		return result, false
	}
	if active[t] {
		return false, true
	}
	active[t] = true
	defer delete(active, t)
	cycleCut := false
	if structure := structType(t); structure != nil {
		for field := range structure.Fields() {
			if isPartialFlag(field) {
				cache[t] = true
				cache[structure] = true
				return true, cycleCut
			}
			found, cut := containsPartialFlagVisit(field.Type(), cache, active)
			cycleCut = cycleCut || cut
			if found {
				cache[t] = true
				cache[structure] = true
				return true, cycleCut
			}
		}
	}
	if !cycleCut {
		cache[t] = false
	}
	return false, cycleCut
}

// partialFlagsAlongPath visits only structures selected by the expression.
func partialFlagsAlongPath(t types.Type, path []*types.Var) []partialFlag {
	if t == nil {
		return nil
	}
	var flags []partialFlag
	scope := make([]*types.Var, 0, len(path))
	for depth := 0; ; depth++ {
		structure := structType(t)
		if structure == nil {
			break
		}
		for field := range structure.Fields() {
			if isPartialFlag(field) {
				flags = append(flags, partialFlag{field: field, scope: append([]*types.Var(nil), scope...), prefix: partialFlagPrefix(field.Name())})
			}
		}
		if depth == len(path) {
			break
		}
		selected := path[depth]
		var next types.Type
		for field := range structure.Fields() {
			if field == selected || field.Name() == selected.Name() {
				next = field.Type()
				break
			}
		}
		if next == nil {
			break
		}
		scope = append(scope, selected)
		t = next
	}
	return flags
}

func partialFlagKey(flag partialFlag) string {
	var key strings.Builder
	for _, field := range flag.scope {
		fmt.Fprintf(&key, "%p/", field)
	}
	fmt.Fprintf(&key, "%p", flag.field)
	return key.String()
}

func isPartialIndicatorList(field *types.Var) bool {
	name := strings.ToLower(field.Name())
	for _, prefix := range []string{"missing", "failed", "unavailable", "skipped", "stale", "warnings", "errors"} {
		if strings.HasPrefix(name, prefix) {
			t := types.Unalias(field.Type())
			for {
				named, ok := t.(*types.Named)
				if !ok {
					break
				}
				t = types.Unalias(named.Underlying())
			}
			switch t.Underlying().(type) {
			case *types.Slice, *types.Map:
				return true
			}
		}
	}
	return false
}

func partialFlagPrefix(name string) string {
	lower := strings.ToLower(name)
	for _, part := range partialFlagParts {
		if index := strings.Index(lower, part); index >= 0 {
			prefix := name[:index]
			if strings.EqualFold(prefix, "Is") || strings.EqualFold(prefix, "Has") {
				return ""
			}
			return prefix
		}
	}
	return ""
}

func partialFieldMatchesPrefix(name, prefix string) bool {
	if prefix == "" {
		return true
	}
	lowerName, lowerPrefix := strings.ToLower(name), strings.ToLower(prefix)
	if strings.HasPrefix(lowerName, lowerPrefix) {
		return true
	}
	for _, aggregate := range []string{"total", "net", "sum", "grand"} {
		if strings.HasPrefix(lowerName, aggregate) {
			return true
		}
	}
	return false
}

func samePartialPath(left, right []*types.Var) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func containsPartialFlagPart(name string) bool {
	name = strings.ToLower(name)
	for _, part := range partialFlagParts {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

func selectorPath(info *types.Info, sel *ast.SelectorExpr) (types.Object, []*types.Var) {
	var fields []*types.Var
	var walk func(ast.Expr) types.Object
	walk = func(expr ast.Expr) types.Object {
		switch e := ast.Unparen(expr).(type) {
		case *ast.Ident:
			return info.ObjectOf(e)
		case *ast.StarExpr:
			return walk(e.X)
		case *ast.SelectorExpr:
			root := walk(e.X)
			if selection := info.Selections[e]; selection != nil {
				if field, ok := selection.Obj().(*types.Var); ok {
					fields = append(fields, field)
				}
			}
			return root
		}
		return nil
	}
	return walk(sel), fields
}

func markFlagWrite(info *types.Info, expr ast.Expr, candidates map[types.Object]types.Type, written map[types.Object]map[string]bool) {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return
	}
	root, fields := selectorPath(info, sel)
	if len(fields) == 0 {
		return
	}
	for _, flag := range partialFlagsAlongPath(candidates[root], fields[:len(fields)-1]) {
		if flag.field == fields[len(fields)-1] {
			if written[root] == nil {
				written[root] = make(map[string]bool)
			}
			written[root][partialFlagKey(flag)] = true
		}
	}
}

func selectorIsAssignmentLHS(body *ast.BlockStmt, selector *ast.SelectorExpr) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range stmt.Lhs {
				if lhs == selector {
					found = true
				}
			}
		case *ast.IncDecStmt:
			if stmt.X == selector {
				found = true
			}
		}
		return !found
	})
	return found
}

func selectorIsNestedReceiver(body *ast.BlockStmt, selector *ast.SelectorExpr) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		parent, ok := n.(*ast.SelectorExpr)
		if ok && parent.X == selector {
			found = true
			return false
		}
		return !found
	})
	return found
}

func selectorFieldName(info *types.Info, sel *ast.SelectorExpr) string {
	if selection := info.Selections[sel]; selection != nil {
		if field, ok := selection.Obj().(*types.Var); ok {
			return field.Name()
		}
	}
	return sel.Sel.Name
}

func isPartialStructMethodOrConstructor(info *types.Info, fn *ast.FuncDecl) bool {
	if fn.Recv != nil && len(fn.Recv.List) > 0 && hasPartialFlagInValueStruct(info.TypeOf(fn.Recv.List[0].Type)) {
		return true
	}
	if fn.Name != nil && strings.HasPrefix(fn.Name.Name, "New") && fn.Type.Results != nil {
		for _, result := range fn.Type.Results.List {
			if hasPartialFlagInValueStruct(info.TypeOf(result.Type)) {
				return true
			}
		}
	}
	return false
}

func hasPartialFlagInValueStruct(t types.Type) bool {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	active := make(map[*types.Struct]bool)
	var walk func(types.Type) bool
	walk = func(t types.Type) bool {
		structure := structType(t)
		if structure == nil || active[structure] {
			return false
		}
		active[structure] = true
		defer delete(active, structure)
		for field := range structure.Fields() {
			if isPartialFlag(field) {
				return true
			}
			if _, pointer := types.Unalias(field.Type()).(*types.Pointer); !pointer && walk(field.Type()) {
				return true
			}
		}
		return false
	}
	return walk(t)
}

package errrules

import (
	"fmt"
	"go/ast"
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
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		return patternkit.AnalyzeGoFunctions(file, func(fn *ast.FuncDecl) []*core.Violation {
			return r.checkFunction(file, info, fn)
		})
	})
}

var partialFlagParts = []string{"incomplete", "partial", "truncated", "stale", "approximate", "degraded"}

func (r *PartialFlagUnreadRule) checkFunction(file *core.FileContext, info *types.Info, fn *ast.FuncDecl) []*core.Violation {
	if fn.Body == nil || isPartialStructMethodOrConstructor(info, fn) {
		return nil
	}
	candidates := partialFlagCandidates(info, fn)
	if len(candidates) == 0 {
		return nil
	}
	usage := inspectPartialUsage(info, fn, candidates)
	return r.firstUnreadFlagFinding(file, info, candidates, usage)
}

type partialFlag struct {
	field  *types.Var
	scope  []*types.Var
	prefix string
}

func partialFlagCandidates(info *types.Info, fn *ast.FuncDecl) map[types.Object][]partialFlag {
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
	candidates := make(map[types.Object][]partialFlag)
	add := func(id *ast.Ident, resultType types.Type) {
		obj := info.ObjectOf(id)
		if obj == nil || params[obj] {
			return
		}
		if resultType == nil {
			resultType = obj.Type()
		}
		if flags := partialFlagFields(resultType); len(flags) > 0 {
			candidates[obj] = flags
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

type partialUsage struct {
	flagRead    map[types.Object]bool
	written     map[types.Object]bool
	passedWhole map[types.Object]bool
	fieldReads  map[types.Object]*ast.SelectorExpr
	readOrder   []types.Object
}

func inspectPartialUsage(info *types.Info, fn *ast.FuncDecl, candidates map[types.Object][]partialFlag) *partialUsage {
	u := &partialUsage{
		flagRead: make(map[types.Object]bool), written: make(map[types.Object]bool),
		passedWhole: make(map[types.Object]bool), fieldReads: make(map[types.Object]*ast.SelectorExpr),
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool { return u.visit(info, fn.Body, n, candidates) })
	return u
}

func (u *partialUsage) visit(info *types.Info, body *ast.BlockStmt, n ast.Node, candidates map[types.Object][]partialFlag) bool {
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

func (u *partialUsage) markWholeValues(info *types.Info, exprs []ast.Expr, candidates map[types.Object][]partialFlag) {
	for _, expr := range exprs {
		id, ok := ast.Unparen(expr).(*ast.Ident)
		if ok {
			if obj := info.ObjectOf(id); candidates[obj] != nil {
				u.passedWhole[obj] = true
			}
		}
	}
}

func (u *partialUsage) markFieldRead(info *types.Info, body *ast.BlockStmt, sel *ast.SelectorExpr, candidates map[types.Object][]partialFlag) {
	selection := info.Selections[sel]
	if selection == nil {
		return
	}
	if _, isField := selection.Obj().(*types.Var); !isField {
		return
	}
	root, fields := selectorPath(info, sel)
	flags := candidates[root]
	if len(flags) == 0 {
		return
	}
	if partialFlagPath(flags, fields) || partialIndicatorPath(flags, fields) {
		u.flagRead[root] = true
		return
	}
	if partialFieldPath(flags, fields) && u.fieldReads[root] == nil && !selectorIsAssignmentLHS(body, sel) {
		u.fieldReads[root] = sel
		u.readOrder = append(u.readOrder, root)
	}
}

func (r *PartialFlagUnreadRule) firstUnreadFlagFinding(file *core.FileContext, info *types.Info, candidates map[types.Object][]partialFlag, usage *partialUsage) []*core.Violation {
	for _, obj := range usage.readOrder {
		if usage.written[obj] || usage.flagRead[obj] || usage.passedWhole[obj] {
			continue
		}
		flags := make([]string, 0, len(candidates[obj]))
		for _, flag := range candidates[obj] {
			flags = append(flags, flag.field.Name())
		}
		sort.Strings(flags)
		return r.finding(file, info, usage.fieldReads[obj], flags[0])
	}
	return nil
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

func partialFlagFields(t types.Type) []partialFlag {
	var out []partialFlag
	active := make(map[types.Type]bool)
	var walk func(types.Type, []*types.Var)
	walk = func(t types.Type, path []*types.Var) {
		t = types.Unalias(t)
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		if named, ok := t.(*types.Named); ok {
			t = named.Underlying()
		}
		st, ok := t.(*types.Struct)
		if !ok || active[st] {
			return
		}
		active[st] = true
		defer delete(active, st)
		for field := range st.Fields() {
			if field.Type().Underlying() == types.Typ[types.Bool] && containsPartialFlagPart(field.Name()) {
				out = append(out, partialFlag{
					field: field, scope: append([]*types.Var(nil), path...),
					prefix: partialFlagPrefix(field.Name()),
				})
				continue
			}
			walk(field.Type(), append(path, field))
		}
	}
	walk(t, nil)
	return out
}

func partialFlagPath(flags []partialFlag, fields []*types.Var) bool {
	if len(fields) == 0 {
		return false
	}
	for _, flag := range flags {
		if fields[len(fields)-1] == flag.field && samePartialPath(fields[:len(fields)-1], flag.scope) {
			return true
		}
	}
	return false
}

func partialFieldPath(flags []partialFlag, fields []*types.Var) bool {
	if len(fields) == 0 {
		return false
	}
	parent := fields[:len(fields)-1]
	for _, flag := range flags {
		if len(parent) >= len(flag.scope) &&
			samePartialPath(parent[:len(flag.scope)], flag.scope) &&
			partialFieldMatchesPrefix(fields[len(fields)-1].Name(), flag.prefix) {
			return true
		}
	}
	return false
}

func partialIndicatorPath(flags []partialFlag, fields []*types.Var) bool {
	if len(fields) == 0 || !isPartialIndicatorList(fields[len(fields)-1]) {
		return false
	}
	parent := fields[:len(fields)-1]
	for _, flag := range flags {
		if samePartialPath(parent, flag.scope) {
			return true
		}
	}
	return false
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

func markFlagWrite(info *types.Info, expr ast.Expr, candidates map[types.Object][]partialFlag, written map[types.Object]bool) {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return
	}
	root, fields := selectorPath(info, sel)
	if partialFlagPath(candidates[root], fields) {
		written[root] = true
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
	active := make(map[*types.Struct]bool)
	var walk func(types.Type) bool
	walk = func(t types.Type) bool {
		t = types.Unalias(t)
		if named, ok := t.(*types.Named); ok {
			t = named.Underlying()
		}
		st, ok := t.(*types.Struct)
		if !ok || active[st] {
			return false
		}
		active[st] = true
		defer delete(active, st)
		for field := range st.Fields() {
			if field.Type().Underlying() == types.Typ[types.Bool] && containsPartialFlagPart(field.Name()) {
				return true
			}
			if _, pointer := types.Unalias(field.Type()).(*types.Pointer); !pointer && walk(field.Type()) {
				return true
			}
		}
		return false
	}
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	return walk(t)
}

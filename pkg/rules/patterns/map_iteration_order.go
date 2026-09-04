package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMapIterationOrderRule())
}

// MapIterationOrderRule detects values whose order comes from walking a map and
// then leaves the function:
//
//	for area := range detected {
//	    areas = append(areas, area)   // order is random
//	}
//	return areas
//
// Go randomizes map iteration deliberately, so the same input produces a
// different order on every run. Once such a slice or string reaches a message,
// a report or a caller, the output stops being reproducible: golden tests flap,
// CI diffs show phantom changes, and findings swap places between runs.
//
// Not flagged: order-independent aggregation (sums, counters), collecting into
// another map, values that never leave the function, and slices sorted before
// they are used.
type MapIterationOrderRule struct {
	*rules.BaseRule
}

// NewMapIterationOrderRule creates the rule
func NewMapIterationOrderRule() *MapIterationOrderRule {
	return &MapIterationOrderRule{
		BaseRule: rules.NewBaseRule(
			"map-iteration-order",
			"patterns",
			"Detects output whose order comes from map iteration — the same input then produces different output on every run",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op because this rule needs the package's type information
// to tell a map range from a slice range.
func (r *MapIterationOrderRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *MapIterationOrderRule) RequiresSSA() bool { return false }

// AnalyzeGoProject inspects every function of the loaded packages.
func (r *MapIterationOrderRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("map iteration order: nil Go project context")
	}
	if ctx.FileSet == nil {
		return nil, errors.New("map iteration order: project has no file set for source positions")
	}

	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("map iteration order: package has no typed syntax")
		}
		// pkg.Files holds exactly the walker-selected files of this package,
		// each with the syntax tree the type checker used.
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			violations = append(violations, r.analyzeFile(fileCtx, fileCtx.GoAST, pkg.Package.TypesInfo)...)
		}
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

func (r *MapIterationOrderRule) analyzeFile(fileCtx *core.FileContext, file *ast.File, info *types.Info) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		violations = append(violations, r.analyzeBody(fileCtx, fn, info)...)
		return true
	})

	return violations
}

func (r *MapIterationOrderRule) analyzeBody(fileCtx *core.FileContext, fn *ast.FuncDecl, info *types.Info) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		rangeStmt, ok := n.(*ast.RangeStmt)
		if !ok || !isMapRange(rangeStmt, info) {
			return true
		}
		for _, name := range orderedTargets(rangeStmt) {
			if !escapesFunction(fn, name) || isSortedBefore(fn, name, rangeStmt.End()) {
				continue
			}
			violations = append(violations, r.report(fileCtx, rangeStmt, name))
		}
		if picked, ok := firstMatchSelection(fn, rangeStmt); ok {
			violations = append(violations, r.reportSelection(fileCtx, rangeStmt, picked))
		}
		return true
	})

	return violations
}

func (r *MapIterationOrderRule) report(fileCtx *core.FileContext, rangeStmt *ast.RangeStmt, name string) *core.Violation {
	line := fileCtx.LineFor(rangeStmt)
	v := r.CreateViolation(fileCtx.RelPath, line,
		fmt.Sprintf("Order of %q comes from map iteration, which Go randomizes — the same input produces different output on every run", name))
	v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Sort %s before it leaves the function (sort.Strings/slices.SortFunc), or collect the keys in a defined order", name))
	v.WithContext("pattern", "map_iteration_order")
	v.WithContext("variable", name)
	return v
}

func (r *MapIterationOrderRule) reportSelection(fileCtx *core.FileContext, rangeStmt *ast.RangeStmt, picked string) *core.Violation {
	line := fileCtx.LineFor(rangeStmt)
	v := r.CreateViolation(fileCtx.RelPath, line,
		fmt.Sprintf("Which entry this loop picks for %q comes from map iteration, which Go randomizes — the loop stops at the first match, and the same input picks a different entry on every run", picked))
	v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
	v.WithSuggestion("Walk the keys in a defined order (slices.Sorted(maps.Keys(m))), or make the choice by a comparison that has one winner")
	v.WithContext("pattern", "map_iteration_first_match")
	v.WithContext("variable", picked)
	return v
}

// firstMatchSelection reports a loop that picks one entry out of a map and
// stops: it returns something built from the key or the value, or it hands one
// of them to a variable outside the loop and breaks. Which entry wins is then
// the walk order, which Go randomizes.
//
// Three shapes are not such a choice: a lookup narrowed by an equality test
// (the key of a map is unique, and an identity field of the value is treated as
// one), an accumulation without a break, where a comparison and not the walk
// decides the winner, and a walk over a map the function already proved to hold
// a single entry.
func firstMatchSelection(fn *ast.FuncDecl, rangeStmt *ast.RangeStmt) (string, bool) {
	key, value := rangeTargetNames(rangeStmt)
	if key == "" && value == "" {
		return "", false
	}
	if holdsSingleEntry(fn, types.ExprString(rangeStmt.X)) {
		return "", false
	}
	scanner := &firstMatchScanner{key: key, value: value}
	scanner.block(rangeStmt.Body.List, selectionPath{breakBinds: true})
	return scanner.picked, scanner.picked != ""
}

// rangeTargetNames returns the loop's key and value names, blanks excluded.
func rangeTargetNames(rangeStmt *ast.RangeStmt) (key, value string) {
	if ident, ok := rangeStmt.Key.(*ast.Ident); ok && ident.Name != "_" {
		key = ident.Name
	}
	if ident, ok := rangeStmt.Value.(*ast.Ident); ok && ident.Name != "_" {
		value = ident.Name
	}
	return key, value
}

// selectionPath is what the walk knows about the branch it is in.
type selectionPath struct {
	// keyNarrowed: an equality test on the key already picked out one entry.
	keyNarrowed bool
	// assigned: the key or the value has been handed to a variable that
	// outlives the loop, so a break now freezes this entry as the answer.
	assigned string
	// breakBinds: a break here belongs to the map loop, not to a nested loop
	// or switch.
	breakBinds bool
}

// firstMatchScanner walks the loop body remembering what the current branch
// already decided.
type firstMatchScanner struct {
	key, value string
	picked     string
}

func (s *firstMatchScanner) block(stmts []ast.Stmt, path selectionPath) {
	for _, stmt := range stmts {
		path = s.stmt(stmt, path)
	}
}

// stmt walks one statement and returns the path as it leaves it.
func (s *firstMatchScanner) stmt(stmt ast.Stmt, path selectionPath) selectionPath {
	switch node := stmt.(type) {
	case *ast.ReturnStmt:
		if !path.keyNarrowed {
			for _, result := range node.Results {
				if name := s.loopVarIn(result); name != "" {
					s.record(name)
				}
			}
		}
	case *ast.BranchStmt:
		if node.Tok == token.BREAK && node.Label == nil && path.breakBinds && !path.keyNarrowed && path.assigned != "" {
			s.record(path.assigned)
		}
	case *ast.AssignStmt:
		if target := s.outerTarget(node); target != "" {
			path.assigned = target
		}
	case *ast.BlockStmt:
		s.block(node.List, path)
	case *ast.IfStmt:
		thenPath := path
		thenPath.keyNarrowed = path.keyNarrowed || s.narrowsChoice(node.Cond)
		s.block(node.Body.List, thenPath)
		if node.Else != nil {
			s.stmt(node.Else, path)
		}
	case *ast.ForStmt:
		s.nested(node.Body, path)
	case *ast.RangeStmt:
		s.nested(node.Body, path)
	case *ast.SwitchStmt:
		s.switchClauses(node.Body, path, isIdent(node.Tag, s.key))
	case *ast.TypeSwitchStmt:
		s.switchClauses(node.Body, path, false)
	case *ast.SelectStmt:
		s.switchClauses(node.Body, path, false)
	case *ast.LabeledStmt:
		return s.stmt(node.Stmt, path)
	}
	return path
}

// nested walks a body where a break belongs to the inner construct.
func (s *firstMatchScanner) nested(body *ast.BlockStmt, path selectionPath) {
	if body == nil {
		return
	}
	path.breakBinds = false
	s.block(body.List, path)
}

// switchClauses walks the clauses of a switch or select; a switch on the key
// narrows the choice the same way an equality test does.
func (s *firstMatchScanner) switchClauses(body *ast.BlockStmt, path selectionPath, onKey bool) {
	if body == nil {
		return
	}
	path.breakBinds = false
	path.keyNarrowed = path.keyNarrowed || onKey
	for _, item := range body.List {
		switch clause := item.(type) {
		case *ast.CaseClause:
			s.block(clause.Body, path)
		case *ast.CommClause:
			s.block(clause.Body, path)
		}
	}
}

// outerTarget returns the name of a variable outside the loop that just took
// the key or the value. A short declaration makes a variable of the loop's own
// scope, which no later iteration can read.
func (s *firstMatchScanner) outerTarget(assign *ast.AssignStmt) string {
	if assign.Tok != token.ASSIGN || len(assign.Lhs) != len(assign.Rhs) {
		return ""
	}
	for i, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || ident.Name == "_" || ident.Name == s.key || ident.Name == s.value {
			continue
		}
		if s.loopVarIn(assign.Rhs[i]) != "" {
			return ident.Name
		}
	}
	return ""
}

// loopVarIn returns the loop variable the expression carries out, if any.
func (s *firstMatchScanner) loopVarIn(expr ast.Expr) string {
	if s.value != "" && carriesLoopVar(expr, s.value) {
		return s.value
	}
	if s.key != "" && carriesLoopVar(expr, s.key) {
		return s.key
	}
	return ""
}

// carriesLoopVar reports whether the expression hands the loop variable on as
// the answer. A name that only appears inside a constructed error does not
// count: a validation loop reports the first offending entry it meets, and
// which one that is says nothing about the answer the function computes.
func carriesLoopVar(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if isErrorConstruction(call) {
				return false
			}
			if fun, ok := call.Fun.(*ast.Ident); ok && (fun.Name == "len" || fun.Name == "cap") {
				return false
			}
		}
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// isErrorConstruction recognizes the calls that build an error value.
func isErrorConstruction(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "errors" {
		return true
	}
	switch selector.Sel.Name {
	case "Errorf", "Error", "Wrap", "Wrapf":
		return true
	}
	return strings.HasPrefix(selector.Sel.Name, "Err")
}

func (s *firstMatchScanner) record(name string) {
	if s.picked == "" {
		s.picked = name
	}
}

// narrowsChoice reports whether the condition is a lookup rather than a filter:
// an equality test against the key, which a map holds once, or against a field
// of the value, which the code treats as its identity. A test that can hold for
// several entries — a prefix, a substring, a similarity — is not one.
func (s *firstMatchScanner) narrowsChoice(cond ast.Expr) bool {
	if cond == nil {
		return false
	}
	narrowed := false
	ast.Inspect(cond, func(n ast.Node) bool {
		if narrowed {
			return false
		}
		binary, ok := n.(*ast.BinaryExpr)
		if !ok || binary.Op != token.EQL {
			return true
		}
		if s.identityOperand(binary.X) || s.identityOperand(binary.Y) {
			narrowed = true
			return false
		}
		return true
	})
	return narrowed
}

// identityOperand reports whether the operand is the loop key or a field read
// off the loop value.
func (s *firstMatchScanner) identityOperand(expr ast.Expr) bool {
	if isIdent(expr, s.key) {
		return true
	}
	if s.value == "" {
		return false
	}
	if selector, ok := ast.Unparen(expr).(*ast.SelectorExpr); ok {
		return rootIdent(selector) == s.value
	}
	return false
}

// rootIdent returns the identifier a selector chain starts from.
func rootIdent(expr ast.Expr) string {
	for {
		switch node := ast.Unparen(expr).(type) {
		case *ast.SelectorExpr:
			expr = node.X
		case *ast.Ident:
			return node.Name
		default:
			return ""
		}
	}
}

// holdsSingleEntry reports whether the function already compared the size of
// the collection with one: `if len(matches) > 1 { … }` before the loop leaves
// exactly one entry to pick, and picking it is not a choice at all.
func holdsSingleEntry(fn *ast.FuncDecl, collection string) bool {
	if fn == nil || fn.Body == nil || collection == "" {
		return false
	}
	single := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if single {
			return false
		}
		binary, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if lengthOfCollection(binary.X, collection) && isIntLiteral(binary.Y, 1) {
			single = true
		}
		if lengthOfCollection(binary.Y, collection) && isIntLiteral(binary.X, 1) {
			single = true
		}
		return !single
	})
	return single
}

// lengthOfCollection reports whether the expression is len(collection).
func lengthOfCollection(expr ast.Expr, collection string) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	name, ok := call.Fun.(*ast.Ident)
	return ok && name.Name == "len" && types.ExprString(call.Args[0]) == collection
}

// isMapRange reports whether the range expression has a map type.
func isMapRange(rangeStmt *ast.RangeStmt, info *types.Info) bool {
	rangeType := info.TypeOf(rangeStmt.X)
	if rangeType == nil {
		return false
	}
	_, ok := rangeType.Underlying().(*types.Map)
	return ok
}

// orderedTargets returns the names of the variables the loop body builds in
// iteration order: slices grown with append and strings grown by concatenation.
// Order-independent updates (sums, counters, writes into another map) are not
// reported, because their result does not depend on the walk order.
func orderedTargets(rangeStmt *ast.RangeStmt) []string {
	seen := make(map[string]bool)
	var names []string

	add := func(name string) {
		if name == "" || name == "_" || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}

	ast.Inspect(rangeStmt.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 {
			return true
		}
		target, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}

		switch assign.Tok {
		case token.ASSIGN, token.DEFINE:
			// x = append(x, ...)
			if call, ok := assign.Rhs[0].(*ast.CallExpr); ok && isAppendTo(call, target.Name) {
				add(target.Name)
			}
		case token.ADD_ASSIGN:
			// message += ... — only string concatenation keeps an order;
			// numeric accumulation is order-independent.
			if isStringConcat(assign.Rhs[0]) {
				add(target.Name)
			}
		}
		return true
	})

	return names
}

// isAppendTo reports whether the call is append(name, ...).
func isAppendTo(call *ast.CallExpr, name string) bool {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "append" || len(call.Args) == 0 {
		return false
	}
	first, ok := call.Args[0].(*ast.Ident)
	return ok && first.Name == name
}

// isStringConcat reports whether the expression looks like text rather than a
// number: a string literal, or a concatenation involving one.
func isStringConcat(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Kind == token.STRING
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (isStringConcat(e.X) || isStringConcat(e.Y))
	case *ast.CallExpr:
		// fmt.Sprintf(...), strconv.Itoa(...) and friends.
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			return strings.HasPrefix(sel.Sel.Name, "Sprint") || sel.Sel.Name == "Itoa" || sel.Sel.Name == "String"
		}
	}
	return false
}

// escapesFunction reports whether the value reaches the caller: it is returned,
// or stored into a field or an argument.
func escapesFunction(fn *ast.FuncDecl, name string) bool {
	escapes := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if escapes {
			return false
		}
		switch stmt := n.(type) {
		case *ast.ReturnStmt:
			for _, result := range stmt.Results {
				if mentionsOrderSensitive(result, name) {
					escapes = true
					return false
				}
			}
		case *ast.AssignStmt:
			// receiver.field = name — the order outlives this call.
			for _, lhs := range stmt.Lhs {
				if _, ok := lhs.(*ast.SelectorExpr); !ok {
					continue
				}
				for _, rhs := range stmt.Rhs {
					if mentionsOrderSensitive(rhs, name) {
						escapes = true
						return false
					}
				}
			}
		}
		return true
	})

	return escapes
}

// mentionsOrderSensitive reports whether the expression carries the variable's
// order outwards. Aggregates that discard the order — len, cap — do not count,
// so `return len(areas)` is not a leak while `return areas` and
// `return strings.Join(areas, ",")` are.
func mentionsOrderSensitive(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if fun, ok := call.Fun.(*ast.Ident); ok && (fun.Name == "len" || fun.Name == "cap") {
				return false
			}
		}
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// mentions reports whether the expression reads the named variable.
func mentions(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// isSortedBefore reports whether the value is put in a defined order after the
// loop that filled it. Any sort of the variable counts, wherever it happens.
func isSortedBefore(fn *ast.FuncDecl, name string, loopEnd token.Pos) bool {
	sorted := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if sorted {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || call.Pos() < loopEnd {
			return true
		}
		if !isSortingCall(call.Fun) {
			return true
		}
		for _, arg := range call.Args {
			if mentions(arg, name) {
				sorted = true
				return false
			}
		}
		return true
	})

	return sorted
}

// isSortingCall recognizes both the standard sorters and a project's own helper
// around them. A wrapper named sortXEPairs orders the slice exactly as
// sort.Slice does, and refusing to see it would push callers into inlining the
// sort just to satisfy the rule.
func isSortingCall(fun ast.Expr) bool {
	switch callee := fun.(type) {
	case *ast.SelectorExpr:
		if pkg, ok := callee.X.(*ast.Ident); ok && (pkg.Name == "sort" || pkg.Name == "slices") {
			return true
		}
		return strings.HasPrefix(strings.ToLower(callee.Sel.Name), "sort")
	case *ast.Ident:
		return strings.HasPrefix(strings.ToLower(callee.Name), "sort")
	}
	return false
}

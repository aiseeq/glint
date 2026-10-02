package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"golang.org/x/tools/go/types/typeutil"
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
// another map, values that never leave the function, slices sorted before
// they are used, and slices handed to a call other than a writer - a batch
// lookup or a query over a set of ids answers the same in any order.
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
	versions := helpers.NewGoVersions(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyzeFile(fileCtx, info, versions)
	})
}

func (r *MapIterationOrderRule) analyzeFile(fileCtx *core.FileContext, info *types.Info, versions *helpers.GoVersions) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		violations = append(violations, r.analyzeBody(fileCtx, fn, info, versions)...)
		return true
	})

	return violations
}

func (r *MapIterationOrderRule) analyzeBody(fileCtx *core.FileContext, fn *ast.FuncDecl, info *types.Info, versions *helpers.GoVersions) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		rangeStmt, ok := n.(*ast.RangeStmt)
		if !ok || !isMapRange(rangeStmt, info) {
			return true
		}
		var found []*core.Violation
		for _, name := range orderedTargets(rangeStmt, info) {
			if !escapesFunction(fn, name, info) || isSortedBefore(fn, name, rangeStmt.End()) {
				continue
			}
			found = append(found, r.report(fileCtx, rangeStmt, name))
		}
		if picked, ok := firstMatchSelection(fn, rangeStmt); ok {
			found = append(found, r.reportSelection(fileCtx, rangeStmt, picked))
		}
		if writer, ok := outputInLoop(fn, rangeStmt, info); ok {
			found = append(found, r.reportOutput(fileCtx, rangeStmt, writer))
		}
		if len(found) == 0 {
			return true
		}
		sortable := keysSortable(fileCtx, rangeStmt, info, versions)
		column := fileCtx.PositionFor(rangeStmt).Column
		for _, v := range found {
			v.WithColumn(column)
			if sortable {
				// The fixer rewrites the loop into a walk over sorted keys
				// only where that compiles and keeps the loop's meaning.
				v.WithContext("sortable_keys", true)
			}
		}
		violations = append(violations, found...)
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

func (r *MapIterationOrderRule) reportOutput(fileCtx *core.FileContext, rangeStmt *ast.RangeStmt, writer string) *core.Violation {
	line := fileCtx.LineFor(rangeStmt)
	v := r.CreateViolation(fileCtx.RelPath, line,
		fmt.Sprintf("Output written to %s inside this loop comes out in map iteration order, which Go randomizes — the same input produces different output on every run", writer))
	v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
	v.WithSuggestion("Walk the keys in a defined order (slices.Sorted(maps.Keys(m))) before writing the entries")
	v.WithContext("pattern", "map_iteration_output")
	v.WithContext("variable", writer)
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
		root := rootIdent(selector)
		return root != nil && root.Name == s.value
	}
	return false
}

// rootIdent returns the identifier a selector chain starts from: entry in
// entry.ID, nil for anything that is not a chain of selectors.
func rootIdent(expr ast.Expr) *ast.Ident {
	for {
		switch node := ast.Unparen(expr).(type) {
		case *ast.SelectorExpr:
			expr = node.X
		case *ast.Ident:
			return node
		default:
			return nil
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
func orderedTargets(rangeStmt *ast.RangeStmt, info *types.Info) []string {
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
			if isStringType(info.TypeOf(target)) {
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

// isStringType reports whether t is a string type, named or not.
func isStringType(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsString != 0
}

// escapesFunction reports whether the value reaches the caller or the outside
// world: it is returned, stored into a field, or written out - printed, or
// handed to a writer that is visible outside the function.
//
// Handing the value to any other call is not an escape. The callee's answer
// may not depend on the order at all - a batch lookup keyed by id, a query
// with `= ANY($1)`, a membership test - and the rule cannot see inside it.
func escapesFunction(fn *ast.FuncDecl, name string, info *types.Info) bool {
	return escapesWithin(fn, name, info, 0)
}

// maxWriterChain bounds how many local writers the escape check follows: a
// builder written into another builder that is written out, and so on.
const maxWriterChain = 4

func escapesWithin(fn *ast.FuncDecl, name string, info *types.Info, depth int) bool {
	escapes := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if escapes {
			return false
		}
		switch stmt := n.(type) {
		case *ast.ReturnStmt:
			for _, result := range stmt.Results {
				if mentionsOrderSensitive(result, name, info) {
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
					if mentionsOrderSensitive(rhs, name, info) {
						escapes = true
						return false
					}
				}
			}
		case *ast.CallExpr:
			if writesOut(fn, stmt, name, info, depth) {
				escapes = true
				return false
			}
		}
		return true
	})

	return escapes
}

// writesOut reports whether the call writes the value out: print and println,
// the fmt printers, or a Write method of a writer seen outside the function.
func writesOut(fn *ast.FuncDecl, call *ast.CallExpr, name string, info *types.Info, depth int) bool {
	if builtin, ok := typeutil.Callee(info, call).(*types.Builtin); ok {
		if builtin.Name() != "print" && builtin.Name() != "println" {
			return false
		}
		return argsMentionOrderSensitive(call.Args, name, info)
	}
	writer, args, ok := outputCall(call, info)
	if !ok || !argsMentionOrderSensitive(args, name, info) {
		return false
	}
	return writer == nil || writerLeavesWithin(fn, writer, info, depth+1)
}

// argsMentionOrderSensitive reports whether any of the arguments carries the
// variable's order.
func argsMentionOrderSensitive(args []ast.Expr, name string, info *types.Info) bool {
	for _, arg := range args {
		if mentionsOrderSensitive(arg, name, info) {
			return true
		}
	}
	return false
}

// orderInsensitiveSlicesFuncs are the slices functions whose result is the
// same whatever order the elements come in.
var orderInsensitiveSlicesFuncs = map[string]bool{
	"Contains": true, "ContainsFunc": true,
	"Max": true, "MaxFunc": true, "Min": true, "MinFunc": true,
}

// discardsOrder reports whether the call's result is the same whatever order
// its arguments come in: an order-insensitive slices function, or a call whose
// results cannot hold an order - bools, maps and errors. A predicate answers
// yes or no, and a lookup that returns a map keyed by the ids it was given
// has no walk order left in it.
func discardsOrder(call *ast.CallExpr, info *types.Info) bool {
	if fn, ok := typeutil.Callee(info, call).(*types.Func); ok && fn.Pkg() != nil &&
		fn.Pkg().Path() == "slices" && orderInsensitiveSlicesFuncs[fn.Name()] {
		return true
	}
	signature, ok := info.TypeOf(call.Fun).(*types.Signature)
	if !ok || signature.Results().Len() == 0 {
		return false
	}
	orderless := false
	for result := range signature.Results().Variables() {
		switch {
		case isBooleanType(result.Type()):
			orderless = true
		case isMapType(result.Type()):
			orderless = true
		case isErrorType(result.Type()):
		default:
			return false
		}
	}
	return orderless
}

// isMapType reports whether t is a map type, named or not.
func isMapType(t types.Type) bool {
	_, ok := t.Underlying().(*types.Map)
	return ok
}

// outputInLoop reports a loop over a map that writes its entries out as it
// walks: printing to standard output, or writing to a writer or builder that
// is visible outside the function. The entries then appear in walk order.
// It returns how the destination is spelled.
func outputInLoop(fn *ast.FuncDecl, rangeStmt *ast.RangeStmt, info *types.Info) (string, bool) {
	key, value := rangeTargetNames(rangeStmt)
	if key == "" && value == "" {
		return "", false
	}

	destination := ""
	ast.Inspect(rangeStmt.Body, func(n ast.Node) bool {
		if destination != "" {
			return false
		}
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		writer, args, ok := outputCall(call, info)
		if !ok || !argsCarryEntry(args, key, value) {
			return true
		}
		if writer == nil {
			destination = "standard output"
			return false
		}
		if writerLeaves(fn, writer, info) {
			destination = types.ExprString(writer)
			return false
		}
		return true
	})
	return destination, destination != ""
}

// outputCall recognizes the calls that write text out: fmt.Print* (writer
// nil, standard output), fmt.Fprint* (the writer is the first argument) and
// the Write* methods of writers and builders (the writer is the receiver).
func outputCall(call *ast.CallExpr, info *types.Info) (writer ast.Expr, args []ast.Expr, ok bool) {
	selector, isSelector := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSelector {
		return nil, nil, false
	}
	if fn, isFunc := info.Uses[selector.Sel].(*types.Func); isFunc && fn.Pkg() != nil && fn.Pkg().Path() == "fmt" {
		switch fn.Name() {
		case "Print", "Printf", "Println":
			return nil, call.Args, true
		case "Fprint", "Fprintf", "Fprintln":
			if len(call.Args) > 0 {
				return call.Args[0], call.Args[1:], true
			}
		}
		return nil, nil, false
	}
	selection, isMethod := info.Selections[selector]
	if !isMethod || selection.Kind() != types.MethodVal {
		return nil, nil, false
	}
	switch selector.Sel.Name {
	case "Write", "WriteString", "WriteByte", "WriteRune":
		return selector.X, call.Args, true
	}
	return nil, nil, false
}

// argsCarryEntry reports whether the written arguments depend on the entry
// the loop is at: writing the same text on every iteration has no order.
func argsCarryEntry(args []ast.Expr, key, value string) bool {
	for _, arg := range args {
		if (key != "" && mentions(arg, key)) || (value != "" && mentions(arg, value)) {
			return true
		}
	}
	return false
}

// writerLeaves reports whether what is written to the writer can be seen
// outside the function: a package-level writer (os.Stdout), a parameter,
// receiver or named result, or a local one that itself escapes. A writer the
// expression does not name plainly is unknown and not reported.
func writerLeaves(fn *ast.FuncDecl, writer ast.Expr, info *types.Info) bool {
	return writerLeavesWithin(fn, writer, info, 0)
}

func writerLeavesWithin(fn *ast.FuncDecl, writer ast.Expr, info *types.Info, depth int) bool {
	root := writerRoot(writer)
	if root == nil || depth > maxWriterChain {
		return false
	}
	switch obj := info.Uses[root].(type) {
	case *types.PkgName:
		return true
	case *types.Var:
		if obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() {
			return true
		}
		if obj.Pos() >= fn.Pos() && obj.Pos() < fn.Body.Lbrace {
			return true // declared in the signature
		}
		return escapesWithin(fn, root.Name, info, depth)
	}
	return false
}

// writerRoot returns the variable a writer expression starts from: sb for
// &sb, sb.inner or (*sb).
func writerRoot(expr ast.Expr) *ast.Ident {
	for {
		switch node := ast.Unparen(expr).(type) {
		case *ast.Ident:
			return node
		case *ast.SelectorExpr:
			expr = node.X
		case *ast.UnaryExpr:
			if node.Op != token.AND {
				return nil
			}
			expr = node.X
		case *ast.StarExpr:
			expr = node.X
		default:
			return nil
		}
	}
}

// keysSortable reports whether the fixer may rewrite the loop into
// `for _, k := range slices.Sorted(maps.Keys(m))` with `v := m[k]` as the first
// statement of the body. That needs a cmp.Ordered key, Go 1.23 for
// slices.Sorted over an iterator, a map expression that can be evaluated twice,
// a body that neither edits the map nor declares the value name again, and
// maps and slices that name those packages where the loop is.
func keysSortable(fileCtx *core.FileContext, rangeStmt *ast.RangeStmt, info *types.Info, versions *helpers.GoVersions) bool {
	if rangeStmt.Tok != token.DEFINE {
		return false
	}
	key, ok := rangeStmt.Key.(*ast.Ident)
	if !ok || key.Name == "_" {
		return false
	}
	if rangeStmt.Value != nil {
		value, ok := rangeStmt.Value.(*ast.Ident)
		if !ok || (value.Name != "_" && redeclaresInBody(rangeStmt.Body, value.Name)) {
			return false
		}
	}
	if !isPlainOperand(rangeStmt.X) {
		return false
	}
	mapType, ok := info.TypeOf(rangeStmt.X).Underlying().(*types.Map)
	if !ok {
		return false
	}
	keyType, ok := mapType.Key().Underlying().(*types.Basic)
	if !ok || keyType.Info()&types.IsOrdered == 0 {
		return false
	}
	if !versions.AtLeast(fileCtx, info, "go1.23") {
		return false
	}
	if editsMap(rangeStmt.Body, types.ExprString(rangeStmt.X), info) {
		return false
	}
	return namesStdlibPackages(fileCtx.GoAST, rangeStmt.Pos(), info, "maps", "slices")
}

// namesStdlibPackages reports whether each of the standard packages, spelled by
// its name at pos, would refer to that package: the name is free or already
// imports it. A variable or another package of that name in any enclosing
// scope - including a package-level declaration in another file - would
// capture the call the fixer writes.
func namesStdlibPackages(file *ast.File, pos token.Pos, info *types.Info, packages ...string) bool {
	fileScope := info.Scopes[file]
	if fileScope == nil {
		return false
	}
	scope := fileScope.Innermost(pos)
	if scope == nil {
		return false
	}
	for _, pkg := range packages {
		_, obj := scope.LookupParent(pkg, pos)
		if obj == nil {
			continue
		}
		pkgName, ok := obj.(*types.PkgName)
		if !ok || pkgName.Imported().Path() != pkg {
			return false
		}
	}
	return true
}

// isPlainOperand reports whether the expression is a name or a chain of field
// selections: evaluating it twice gives the same map.
func isPlainOperand(expr ast.Expr) bool {
	switch node := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return true
	case *ast.SelectorExpr:
		return isPlainOperand(node.X)
	}
	return false
}

// redeclaresInBody reports whether a top-level statement of the body declares
// the name, which the inserted `v := m[k]` would then clash with.
func redeclaresInBody(body *ast.BlockStmt, name string) bool {
	for _, stmt := range body.List {
		for _, declared := range declaredNames(stmt) {
			if declared == name {
				return true
			}
		}
	}
	return false
}

// declaredNames returns the names a statement declares in its own block.
func declaredNames(stmt ast.Stmt) []string {
	var names []string
	switch node := stmt.(type) {
	case *ast.AssignStmt:
		if node.Tok != token.DEFINE {
			return nil
		}
		for _, lhs := range node.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok {
				names = append(names, ident.Name)
			}
		}
	case *ast.DeclStmt:
		gen, ok := node.Decl.(*ast.GenDecl)
		if !ok {
			return nil
		}
		for _, spec := range gen.Specs {
			names = append(names, specNames(spec)...)
		}
	}
	return names
}

// specNames returns the names a var, const or type spec declares.
func specNames(spec ast.Spec) []string {
	switch s := spec.(type) {
	case *ast.ValueSpec:
		names := make([]string, 0, len(s.Names))
		for _, ident := range s.Names {
			names = append(names, ident.Name)
		}
		return names
	case *ast.TypeSpec:
		return []string{s.Name.Name}
	}
	return nil
}

// editsMap reports whether the body may change the map it walks: a delete or
// clear, a write to an entry, an assignment to the map itself, taking its
// address, or handing it to a call other than len. A walk over a snapshot of
// the keys would then see different entries than the walk over the map.
func editsMap(body *ast.BlockStmt, mapExpr string, info *types.Info) bool {
	isMap := func(expr ast.Expr) bool { return types.ExprString(ast.Unparen(expr)) == mapExpr }
	edits := false
	ast.Inspect(body, func(n ast.Node) bool {
		if edits {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				index, isIndex := lhs.(*ast.IndexExpr)
				if (isIndex && isMap(index.X)) || isMap(lhs) {
					edits = true
				}
			}
		case *ast.IncDecStmt:
			if index, ok := node.X.(*ast.IndexExpr); ok && isMap(index.X) {
				edits = true
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND && isMap(node.X) {
				edits = true
			}
		case *ast.CallExpr:
			if fun, ok := ast.Unparen(node.Fun).(*ast.Ident); ok {
				if builtin, ok := info.Uses[fun].(*types.Builtin); ok && builtin.Name() == "len" {
					return true
				}
			}
			for _, arg := range node.Args {
				if isMap(arg) {
					edits = true
				}
			}
		}
		return !edits
	})
	return edits
}

// mentionsOrderSensitive reports whether the expression carries the variable's
// order outwards. Aggregates that discard the order — len, cap, the Len and
// Cap methods of a builder or buffer, the calls discardsOrder names — do not
// count, so `return len(areas)` is not a leak while `return areas` and
// `return strings.Join(areas, ",")` are.
func mentionsOrderSensitive(expr ast.Expr, name string, info *types.Info) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if discardsOrder(call, info) {
				return false
			}
			if fun, ok := call.Fun.(*ast.Ident); ok && (fun.Name == "len" || fun.Name == "cap") {
				return false
			}
			if method, ok := call.Fun.(*ast.SelectorExpr); ok && len(call.Args) == 0 &&
				(method.Sel.Name == "Len" || method.Sel.Name == "Cap") {
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

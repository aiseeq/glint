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
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || (pkg.Name != "sort" && pkg.Name != "slices") {
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

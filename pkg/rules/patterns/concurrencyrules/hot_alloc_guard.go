package concurrencyrules

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewHotFunctionWithoutAllocGuardRule())
}

// HotFunctionWithoutAllocGuardRule detects a function marked //glint:hot
// that no checked testing.AllocsPerRun result reaches, directly or through
// the module's functions. A benchmark or an unchecked allocation result
// does not guard the hot path: allocations can grow unnoticed, one subsystem
// at a time:
//
//	got := testing.AllocsPerRun(100, func() { e.Step(frames[k]); k++ })
//	if got > stepAllocCeiling { t.Errorf("allocs per frame %.1f, ceiling %d", got, stepAllocCeiling) }
//
// The tests are read without types, so a call is matched by name: a test
// that calls Step reaches every function and method named Step, and a call
// through an interface reaches every method of that name. The rule errs on
// the side of a guard that may not measure the function, never of a report
// for a measured one.
type HotFunctionWithoutAllocGuardRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewHotFunctionWithoutAllocGuardRule creates the rule.
func NewHotFunctionWithoutAllocGuardRule() *HotFunctionWithoutAllocGuardRule {
	return &HotFunctionWithoutAllocGuardRule{
		BaseRule: rules.NewBaseRule(
			"hot-function-without-alloc-guard",
			"patterns",
			"Detects a function marked //glint:hot that no checked testing.AllocsPerRun result reaches — benchmarks and unchecked measurements let allocations grow unnoticed",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile is a no-op: the check needs the call graph.
func (r *HotFunctionWithoutAllocGuardRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *HotFunctionWithoutAllocGuardRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the hot functions no allocation measurement
// reaches.
func (r *HotFunctionWithoutAllocGuardRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	decls, err := patternkit.FuncDeclsByObject(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	checkedNames, uncheckedNames, benchmarkNames := measuredNames(ctx.Files)
	guarded := measuredFunctions(decls, checkedNames)
	unchecked := measuredFunctions(decls, unionNames(uncheckedNames, benchmarkNames))
	return rules.AnalyzeTypedRunFiles(ctx, r.Name(), func(file *core.FileContext, _ *types.Info) []*core.Violation {
		return patternkit.AnalyzeGoFunctions(file, func(fn *ast.FuncDecl) []*core.Violation {
			if !patternkit.HasDirective(fn.Doc, patternkit.HotFunctionDirective) || guarded[fn] {
				return nil
			}
			line := file.LineFor(fn.Name)
			if file.IsSuppressed(line, r.Name()) {
				return nil
			}
			message := "Hot function " + patternkit.QualifiedFuncName(fn) + " is not reached by any allocation measurement"
			if unchecked[fn] {
				message = "Hot function " + patternkit.QualifiedFuncName(fn) + " is reached only by a benchmark or testing.AllocsPerRun whose result is not checked"
			}
			v := r.CreateViolation(file.RelPath, line, message+" — its allocations have no checked ceiling")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Add a test that runs it under testing.AllocsPerRun and checks the result against an allocation ceiling")
			return []*core.Violation{v}
		})
	})
}

// measuredNames separates checked measurements from unchecked measurements
// and benchmarks, returning the names each of them reaches.
func measuredNames(files []*core.FileContext) (checked, unchecked, benchmarks map[string]bool) {
	checked, unchecked, benchmarks = map[string]bool{}, map[string]bool{}, map[string]bool{}
	collect := func(node ast.Node, names map[string]bool) {
		ast.Inspect(node, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if name := patternkit.CalledName(call); name != "" {
					names[name] = true
				}
			}
			return true
		})
	}
	for _, file := range files {
		if file == nil || file.GoAST == nil || !file.IsTestFile() {
			continue
		}
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if patternkit.CalledName(node) == "AllocsPerRun" && len(node.Args) == 2 {
					target := unchecked
					if allocationResultChecked(node, enclosingFunc(file.GoAST, node)) {
						target = checked
					}
					if name := patternkit.FuncExprName(node.Args[1]); name != "" {
						target[name] = true
					}
					collect(node.Args[1], target)
				}
			case *ast.FuncDecl:
				if node.Body != nil && strings.HasPrefix(node.Name.Name, "Benchmark") && callsName(node.Body, "ReportAllocs") {
					collect(node.Body, benchmarks)
				}
			}
			return true
		})
	}
	return checked, unchecked, benchmarks
}

func unionNames(groups ...map[string]bool) map[string]bool {
	joined := map[string]bool{}
	for _, group := range groups {
		for name := range group {
			joined[name] = true
		}
	}
	return joined
}

func enclosingFunc(root ast.Node, target ast.Node) *ast.FuncDecl {
	var result *ast.FuncDecl
	ast.Inspect(root, func(node ast.Node) bool {
		if fn, ok := node.(*ast.FuncDecl); ok && fn.Body != nil && target.Pos() >= fn.Body.Pos() && target.End() <= fn.Body.End() {
			result = fn
		}
		return result == nil
	})
	return result
}

func allocationResultChecked(call *ast.CallExpr, fn *ast.FuncDecl) bool {
	if fn == nil || fn.Body == nil {
		return false
	}
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	for parent := parents[call]; parent != nil; parent = parents[parent] {
		switch node := parent.(type) {
		case *ast.FuncLit:
			// Function literals belong to the enclosing function for checks.
		case *ast.BinaryExpr:
			if patternkit.IsComparisonOp(node.Op) {
				return true
			}
		case *ast.ReturnStmt:
			return true
		case *ast.CallExpr:
			if isIgnoredAllocationResultSink(patternkit.FuncExprName(node.Fun)) {
				return false
			}
			return true
		case *ast.AssignStmt:
			return assignedAllocationCompared(node, fn, call)
		case *ast.ValueSpec:
			return valueAllocationCompared(node, fn, call)
		case *ast.ExprStmt:
			return false
		}
	}
	return false
}

func assignedAllocationCompared(assign *ast.AssignStmt, fn *ast.FuncDecl, allocation *ast.CallExpr) bool {
	for i, rhs := range assign.Rhs {
		if !patternkit.ContainsNode(rhs, allocation) || i >= len(assign.Lhs) {
			continue
		}
		if ident, ok := assign.Lhs[i].(*ast.Ident); ok && ident.Name != "_" && comparedName(fn.Body, ident.Name) {
			return true
		}
	}
	return false
}

func valueAllocationCompared(spec *ast.ValueSpec, fn *ast.FuncDecl, allocation *ast.CallExpr) bool {
	for i, value := range spec.Values {
		if patternkit.ContainsNode(value, allocation) && i < len(spec.Names) && comparedName(fn.Body, spec.Names[i].Name) {
			return true
		}
	}
	return false
}

func comparedName(body ast.Node, name string) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		cmp, ok := node.(*ast.BinaryExpr)
		if !ok || !patternkit.IsComparisonOp(cmp.Op) {
			return true
		}
		for _, side := range []ast.Expr{cmp.X, cmp.Y} {
			ast.Inspect(side, func(child ast.Node) bool {
				if ident, ok := child.(*ast.Ident); ok && ident.Name == name {
					found = true
					return false
				}
				return !found
			})
		}
		return !found
	})
	return found
}

func isIgnoredAllocationResultSink(name string) bool {
	return name == "Log" || name == "Logf" || strings.HasPrefix(name, "Print") || strings.HasPrefix(name, "Sprint") || name == "println"
}

// callsName reports whether a body calls something of the name.
func callsName(body ast.Node, name string) bool {
	return helpers.ContainsNode[*ast.CallExpr](body, func(call *ast.CallExpr) bool {
		return patternkit.CalledName(call) == name
	})
}

// measuredFunctions returns the loaded functions an allocation measurement
// reaches: the ones of a measured name, and what they call - statically, or
// through an interface or a value, matched by the method's name.
func measuredFunctions(decls map[*types.Func]patternkit.TypedFuncDecl, names map[string]bool) map[*ast.FuncDecl]bool {
	byName := map[string][]patternkit.TypedFuncDecl{}
	for fn, decl := range decls {
		byName[fn.Name()] = append(byName[fn.Name()], decl)
	}
	reached := map[*ast.FuncDecl]bool{}
	var queue []patternkit.TypedFuncDecl
	visit := func(decl patternkit.TypedFuncDecl) {
		if !reached[decl.Decl] {
			reached[decl.Decl] = true
			queue = append(queue, decl)
		}
	}
	for name := range names {
		for _, decl := range byName[name] {
			visit(decl)
		}
	}
	for len(queue) > 0 {
		caller := queue[0]
		queue = queue[1:]
		ast.Inspect(caller.Decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if fn := patternkit.StaticFunc(caller.Info, call); fn != nil {
				if decl, loaded := decls[fn.Origin()]; loaded {
					visit(decl)
					return true
				}
			}
			for _, decl := range byName[patternkit.CalledName(call)] {
				visit(decl)
			}
			return true
		})
	}
	return reached
}

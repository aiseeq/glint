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
// that no allocation measurement of the module's tests reaches: no closure
// passed to testing.AllocsPerRun and no benchmark that calls b.ReportAllocs
// calls it, directly or through the module's functions. Without a measured
// ceiling the mark is a declaration only - the allocations of the hot path
// grow unnoticed, one subsystem at a time:
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
	*rules.BaseRule
}

// NewHotFunctionWithoutAllocGuardRule creates the rule.
func NewHotFunctionWithoutAllocGuardRule() *HotFunctionWithoutAllocGuardRule {
	return &HotFunctionWithoutAllocGuardRule{
		BaseRule: rules.NewBaseRule(
			"hot-function-without-alloc-guard",
			"patterns",
			"Detects a function marked //glint:hot that no testing.AllocsPerRun closure and no benchmark with b.ReportAllocs reaches — without a measured ceiling the mark is a declaration and the allocations grow unnoticed",
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
	guarded := measuredFunctions(decls, measuredNames(ctx.Files))
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, _ *types.Info) []*core.Violation {
		return patternkit.AnalyzeGoFunctions(file, func(fn *ast.FuncDecl) []*core.Violation {
			if !patternkit.HasDirective(fn.Doc, patternkit.HotFunctionDirective) || guarded[fn] {
				return nil
			}
			line := file.LineFor(fn.Name)
			if file.IsSuppressed(line, r.Name()) {
				return nil
			}
			v := r.CreateViolation(file.RelPath, line, "Hot function "+patternkit.QualifiedFuncName(fn)+" is not reached by any testing.AllocsPerRun closure or benchmark with b.ReportAllocs — its allocations are not measured")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Add a test that runs it under testing.AllocsPerRun and fails above a ceiling that only goes down, or a benchmark with b.ReportAllocs in the gate")
			return []*core.Violation{v}
		})
	})
}

// measuredNames returns the names the module's tests call inside an
// allocation measurement: the closure or function passed to
// testing.AllocsPerRun, and the body of a benchmark that calls ReportAllocs.
func measuredNames(files []*core.FileContext) map[string]bool {
	names := map[string]bool{}
	collect := func(node ast.Node) {
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
					if name := patternkit.FuncExprName(node.Args[1]); name != "" {
						names[name] = true
					}
					collect(node.Args[1])
				}
			case *ast.FuncDecl:
				if node.Body != nil && strings.HasPrefix(node.Name.Name, "Benchmark") && callsName(node.Body, "ReportAllocs") {
					collect(node.Body)
				}
			}
			return true
		})
	}
	return names
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

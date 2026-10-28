package concurrencyrules

import (
	"go/ast"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewRuntimeGCTuningRule())
}

// gcTuningEnvVars are the environment variables that set the collector up.
var gcTuningEnvVars = []string{"GOGC", "GOMEMLIMIT"}

// gcForcingFuncs force a collection: a measurement does it before reading the
// heap, anything else runs the collector by hand.
var gcForcingFuncs = []struct{ pkg, name string }{
	{"runtime", "GC"},
	{"runtime/debug", "FreeOSMemory"},
}

// NewRuntimeGCTuningRule creates runtime-gc-tuning: production code that sets
// the collector up - debug.SetGCPercent, debug.SetMemoryLimit, GOGC or
// GOMEMLIMIT through os.Setenv, a forced runtime.GC or debug.FreeOSMemory -
// hides where the garbage comes from. The collector runs less often and the
// program pays with memory, while the allocations stay:
//
//	if os.Getenv("GOGC") == "" {
//		debug.SetGCPercent(400) // GC was 19% of the profile
//	}
//
// The fix removes the allocations (buffers on the receiver, refilled in
// place). A collection forced right before a heap profile or a memory reading
// in the same function is measurement and is not reported; tests are not
// checked. A memory limit sized to a container is a deliberate setting and
// takes a suppression with the limit and the measured RSS as its reason.
func NewRuntimeGCTuningRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"runtime-gc-tuning",
			"patterns",
			"Detects the collector set up from production code — debug.SetGCPercent, debug.SetMemoryLimit, os.Setenv of GOGC or GOMEMLIMIT, a forced runtime.GC — it trades memory for CPU and hides where the garbage comes from; remove the allocations instead",
			core.SeverityMedium,
		),
		Suggestion: "Find the allocations in the profile (go tool pprof -sample_index=alloc_space) and remove them; a memory limit sized to a container takes // runtime-gc-tuning: safe — <limit, measured RSS>",
	}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		measures := measuresMemory(scope.Info, fn.Body)
		var findings []patternkit.FuncFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if what := gcTuningCall(scope.Info, call, measures); what != "" {
				findings = append(findings, patternkit.FuncFinding{Node: call, Message: what + " sets the collector up from code — it trades memory for CPU and leaves the allocations where they are"})
			}
			return true
		})
		return findings
	}
	return r
}

// gcTuningCall describes a call that sets the collector up, "" for any other
// call. A forced collection counts only outside a measurement.
func gcTuningCall(info *types.Info, call *ast.CallExpr, measures bool) string {
	if name, ok := patternkit.PackageFuncName(nil, info, call, "runtime/debug"); ok && (name == "SetGCPercent" || name == "SetMemoryLimit") {
		return "debug." + name
	}
	if name, ok := patternkit.PackageFuncName(nil, info, call, "os"); ok && name == "Setenv" && len(call.Args) == 2 {
		if key, isConst := patternkit.StringConstant(info, call.Args[0]); isConst && slices.Contains(gcTuningEnvVars, key) {
			return "os.Setenv(" + key + ")"
		}
	}
	if measures {
		return ""
	}
	for _, f := range gcForcingFuncs {
		if name, ok := patternkit.PackageFuncName(nil, info, call, f.pkg); ok && name == f.name {
			return "a forced " + types.ExprString(call.Fun)
		}
	}
	return ""
}

// measuresMemory reports a body that reads the heap after forcing a
// collection: it writes a runtime/pprof profile or reads runtime.MemStats or
// runtime/metrics.
func measuresMemory(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		fn := patternkit.StaticFunc(info, call)
		if fn == nil || fn.Pkg() == nil {
			return true
		}
		switch fn.Pkg().Path() {
		case "runtime/pprof", "runtime/metrics":
			found = true
		case "runtime":
			found = fn.Name() == "ReadMemStats"
		}
		return !found
	})
	return found
}

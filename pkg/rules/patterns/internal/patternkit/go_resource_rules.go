package patternkit

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/types/typeutil"
)

func NewFuncRule(name, description string, severity core.Severity, suggestion string, check func(scope FuncScope, fn *ast.FuncDecl) []FuncFinding) *TypedFuncRule {
	return &TypedFuncRule{
		BaseRule:   rules.NewBaseRule(name, "patterns", description, severity),
		Suggestion: suggestion,
		Check:      check,
	}
}

// ReturnsErrorResult reports whether the function's last result is an error.
func ReturnsErrorResult(info *types.Info, fn *ast.FuncDecl) bool {
	results := fn.Type.Results
	if results == nil || len(results.List) == 0 {
		return false
	}
	last := results.List[len(results.List)-1]
	return IsErrorType(info.TypeOf(last.Type))
}

// CalleeIn reports whether the call is to one of the named functions of the
// package path, a method of a type of that package included.
func CalleeIn(call *ast.CallExpr, info *types.Info, pkgPath string, names ...string) bool {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != pkgPath {
		return false
	}
	for _, name := range names {
		if fn.Name() == name {
			return true
		}
	}
	return false
}

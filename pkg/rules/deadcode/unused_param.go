package deadcode

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnusedParamRule())
}

// UnusedParamRule detects function parameters that are never used
type UnusedParamRule struct {
	*rules.BaseRule
}

// NewUnusedParamRule creates the rule
func NewUnusedParamRule() *UnusedParamRule {
	return &UnusedParamRule{
		BaseRule: rules.NewBaseRule(
			"unused-param",
			"deadcode",
			"Detects function parameters that are never used in the function body",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks for unused function parameters
func (r *UnusedParamRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Skip main/init functions
		if fn.Name.Name == "main" || fn.Name.Name == "init" {
			return true
		}

		// Collect parameter names
		params := r.collectParams(ctx, fn)
		if len(params) == 0 {
			return true
		}

		// Collect all identifiers used in the function body
		used := r.collectUsedIdents(fn.Body)

		// Find unused parameters
		for _, param := range params {
			if !used[param.name] {
				v := r.CreateViolation(ctx.RelPath, param.line,
					"Parameter '"+param.name+"' is never used")
				v.WithCode(ctx.GetLine(param.line))
				v.WithSuggestion("Remove parameter or use _ if required by interface")
				v.WithContext("param", param.name)
				violations = append(violations, v)
			}
		}

		return true
	})

	return violations
}

// declaredParam is one named parameter of a signature. Parameters are kept in
// declaration order: reporting them in map order made the findings of a
// function vary from run to run.
type declaredParam struct {
	name string
	line int
}

func (r *UnusedParamRule) collectParams(ctx *core.FileContext, fn *ast.FuncDecl) []declaredParam {
	if fn.Type.Params == nil {
		return nil
	}

	var params []declaredParam
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if name.Name != "" && name.Name != "_" {
				params = append(params, declaredParam{name: name.Name, line: ctx.PositionFor(name).Line})
			}
		}
	}

	return params
}

func (r *UnusedParamRule) collectUsedIdents(body *ast.BlockStmt) map[string]bool {
	used := make(map[string]bool)

	ast.Inspect(body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			used[ident.Name] = true
		}
		return true
	})

	return used
}

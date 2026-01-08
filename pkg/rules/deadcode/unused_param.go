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

		// Skip interface method implementations (may have unused params for signature matching)
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
		for name, line := range params {
			if name == "_" || name == "" {
				continue
			}
			if !used[name] {
				v := r.CreateViolation(ctx.RelPath, line,
					"Parameter '"+name+"' is never used")
				v.WithSuggestion("Remove parameter or use _ if required by interface")
				v.WithContext("param", name)
				violations = append(violations, v)
			}
		}

		return true
	})

	return violations
}

func (r *UnusedParamRule) collectParams(ctx *core.FileContext, fn *ast.FuncDecl) map[string]int {
	params := make(map[string]int)

	if fn.Type.Params == nil {
		return params
	}

	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if name.Name != "" && name.Name != "_" {
				pos := ctx.PositionFor(name)
				params[name.Name] = pos.Line
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

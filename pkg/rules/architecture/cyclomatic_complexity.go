package architecture

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

const (
	defaultMaxComplexity = 10
)

func init() {
	rules.Register(NewCyclomaticComplexityRule())
}

// CyclomaticComplexityRule detects functions with high cyclomatic complexity
type CyclomaticComplexityRule struct {
	*rules.BaseRule
	maxComplexity int
}

// NewCyclomaticComplexityRule creates the rule
func NewCyclomaticComplexityRule() *CyclomaticComplexityRule {
	return &CyclomaticComplexityRule{
		BaseRule: rules.NewBaseRule(
			"cyclomatic-complexity",
			"architecture",
			"Detects functions with high cyclomatic complexity that are hard to test and maintain",
			core.SeverityMedium,
		),
		maxComplexity: defaultMaxComplexity,
	}
}

// Configure allows setting rule options
func (r *CyclomaticComplexityRule) Configure(settings map[string]any) error {
	if v, ok := settings["max_complexity"]; ok {
		if maxComplexity, ok := v.(int); ok {
			r.maxComplexity = maxComplexity
		}
	}
	return nil
}

// AnalyzeFile checks for high cyclomatic complexity
func (r *CyclomaticComplexityRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}
	return helpers.AnalyzeFuncDecls(ctx, r.checkFunction)
}

func (r *CyclomaticComplexityRule) checkFunction(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	complexity := r.calculateComplexity(fn)

	if complexity > r.maxComplexity {
		pos := ctx.PositionFor(fn.Name)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			fmt.Sprintf("Function '%s' has cyclomatic complexity %d (max: %d)",
				fn.Name.Name, complexity, r.maxComplexity))
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Consider breaking this function into smaller, more focused functions")
		v.WithContext("complexity", fmt.Sprintf("%d", complexity))
		v.WithContext("function", fn.Name.Name)
		return []*core.Violation{v}
	}

	return nil
}

// calculateComplexity computes the cyclomatic complexity of a function
// Cyclomatic complexity = 1 + number of decision points
// Decision points: if, for, range, case, &&, ||
func (r *CyclomaticComplexityRule) calculateComplexity(fn *ast.FuncDecl) int {
	complexity := 1 // Base complexity

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			complexity++

		case *ast.ForStmt:
			complexity++

		case *ast.RangeStmt:
			complexity++

		case *ast.CaseClause:
			// Each case in switch adds complexity (except default)
			if node.List != nil {
				complexity++
			}

		case *ast.CommClause:
			// Each case in select adds complexity (except default)
			if node.Comm != nil {
				complexity++
			}

		case *ast.BinaryExpr:
			// && and || are short-circuit operators that add decision points
			if node.Op == token.LAND || node.Op == token.LOR {
				complexity++
			}
		}

		return true
	})

	return complexity
}

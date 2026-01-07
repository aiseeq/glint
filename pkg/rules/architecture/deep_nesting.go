package architecture

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDeepNestingRule())
}

// DeepNestingRule detects code with too many levels of nesting
type DeepNestingRule struct {
	*rules.BaseRule
	maxDepth int
}

// NewDeepNestingRule creates the rule
func NewDeepNestingRule() *DeepNestingRule {
	return &DeepNestingRule{
		BaseRule: rules.NewBaseRule(
			"deep-nesting",
			"architecture",
			"Detects deeply nested code that is hard to read and maintain",
			core.SeverityMedium,
		),
		maxDepth: 4, // Default maximum nesting depth
	}
}

// Configure allows setting rule options
func (r *DeepNestingRule) Configure(settings map[string]any) error {
	if v, ok := settings["max_depth"]; ok {
		if maxDepth, ok := v.(int); ok {
			r.maxDepth = maxDepth
		}
	}
	return nil
}

// AnalyzeFile checks for deeply nested code
func (r *DeepNestingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	// Analyze each function
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		if fn.Body == nil {
			return true
		}

		// Check nesting depth in function body
		fnViolations := r.checkNesting(ctx, fn.Body, 0, fn.Name.Name)
		violations = append(violations, fnViolations...)

		return true
	})

	return violations
}

func (r *DeepNestingRule) checkNesting(ctx *core.FileContext, node ast.Node, depth int, funcName string) []*core.Violation {
	var violations []*core.Violation

	switch n := node.(type) {
	case *ast.BlockStmt:
		for _, stmt := range n.List {
			violations = append(violations, r.checkNesting(ctx, stmt, depth, funcName)...)
		}

	case *ast.IfStmt:
		newDepth := depth + 1
		if newDepth > r.maxDepth {
			pos := ctx.PositionFor(n)
			v := r.CreateViolation(ctx.RelPath, pos.Line, r.getMessage(newDepth, funcName))
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion(r.getSuggestion())
			violations = append(violations, v)
		}
		// Check body
		violations = append(violations, r.checkNesting(ctx, n.Body, newDepth, funcName)...)
		// Check else
		if n.Else != nil {
			violations = append(violations, r.checkNesting(ctx, n.Else, depth, funcName)...)
		}

	case *ast.ForStmt:
		newDepth := depth + 1
		if newDepth > r.maxDepth {
			pos := ctx.PositionFor(n)
			v := r.CreateViolation(ctx.RelPath, pos.Line, r.getMessage(newDepth, funcName))
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion(r.getSuggestion())
			violations = append(violations, v)
		}
		violations = append(violations, r.checkNesting(ctx, n.Body, newDepth, funcName)...)

	case *ast.RangeStmt:
		newDepth := depth + 1
		if newDepth > r.maxDepth {
			pos := ctx.PositionFor(n)
			v := r.CreateViolation(ctx.RelPath, pos.Line, r.getMessage(newDepth, funcName))
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion(r.getSuggestion())
			violations = append(violations, v)
		}
		violations = append(violations, r.checkNesting(ctx, n.Body, newDepth, funcName)...)

	case *ast.SwitchStmt:
		newDepth := depth + 1
		if newDepth > r.maxDepth {
			pos := ctx.PositionFor(n)
			v := r.CreateViolation(ctx.RelPath, pos.Line, r.getMessage(newDepth, funcName))
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion(r.getSuggestion())
			violations = append(violations, v)
		}
		violations = append(violations, r.checkNesting(ctx, n.Body, newDepth, funcName)...)

	case *ast.TypeSwitchStmt:
		newDepth := depth + 1
		if newDepth > r.maxDepth {
			pos := ctx.PositionFor(n)
			v := r.CreateViolation(ctx.RelPath, pos.Line, r.getMessage(newDepth, funcName))
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion(r.getSuggestion())
			violations = append(violations, v)
		}
		violations = append(violations, r.checkNesting(ctx, n.Body, newDepth, funcName)...)

	case *ast.SelectStmt:
		newDepth := depth + 1
		if newDepth > r.maxDepth {
			pos := ctx.PositionFor(n)
			v := r.CreateViolation(ctx.RelPath, pos.Line, r.getMessage(newDepth, funcName))
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion(r.getSuggestion())
			violations = append(violations, v)
		}
		violations = append(violations, r.checkNesting(ctx, n.Body, newDepth, funcName)...)

	case *ast.CaseClause:
		// Don't increment depth for case clauses themselves, but check their body
		for _, stmt := range n.Body {
			violations = append(violations, r.checkNesting(ctx, stmt, depth, funcName)...)
		}

	case *ast.CommClause:
		for _, stmt := range n.Body {
			violations = append(violations, r.checkNesting(ctx, stmt, depth, funcName)...)
		}
	}

	return violations
}

func (r *DeepNestingRule) getMessage(depth int, funcName string) string {
	return "Nesting depth " + itoa(depth) + " exceeds maximum of " + itoa(r.maxDepth) + " in function " + funcName
}

func (r *DeepNestingRule) getSuggestion() string {
	return "Consider extracting nested logic into separate functions or using early returns"
}

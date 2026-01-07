package architecture

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

const (
	defaultMaxNestingDepth = 4
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
		maxDepth: defaultMaxNestingDepth,
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

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

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
		violations = r.checkBlockStatements(ctx, n.List, depth, funcName)

	case *ast.IfStmt:
		violations = r.checkNestedBlock(ctx, n, n.Body, depth, funcName)
		if n.Else != nil {
			violations = append(violations, r.checkNesting(ctx, n.Else, depth, funcName)...)
		}

	case *ast.ForStmt:
		violations = r.checkNestedBlock(ctx, n, n.Body, depth, funcName)

	case *ast.RangeStmt:
		violations = r.checkNestedBlock(ctx, n, n.Body, depth, funcName)

	case *ast.SwitchStmt:
		violations = r.checkNestedBlock(ctx, n, n.Body, depth, funcName)

	case *ast.TypeSwitchStmt:
		violations = r.checkNestedBlock(ctx, n, n.Body, depth, funcName)

	case *ast.SelectStmt:
		violations = r.checkNestedBlock(ctx, n, n.Body, depth, funcName)

	case *ast.CaseClause:
		violations = r.checkBlockStatements(ctx, n.Body, depth, funcName)

	case *ast.CommClause:
		violations = r.checkBlockStatements(ctx, n.Body, depth, funcName)
	}

	return violations
}

func (r *DeepNestingRule) checkNestedBlock(ctx *core.FileContext, node ast.Node, body *ast.BlockStmt, depth int, funcName string) []*core.Violation {
	var violations []*core.Violation
	newDepth := depth + 1

	if newDepth > r.maxDepth {
		pos := ctx.PositionFor(node)
		v := r.CreateViolation(ctx.RelPath, pos.Line, r.getMessage(newDepth, funcName))
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Consider extracting nested logic into separate functions or using early returns")
		violations = append(violations, v)
	}

	violations = append(violations, r.checkNesting(ctx, body, newDepth, funcName)...)
	return violations
}

func (r *DeepNestingRule) checkBlockStatements(ctx *core.FileContext, stmts []ast.Stmt, depth int, funcName string) []*core.Violation {
	var violations []*core.Violation
	for _, stmt := range stmts {
		violations = append(violations, r.checkNesting(ctx, stmt, depth, funcName)...)
	}
	return violations
}

func (r *DeepNestingRule) getMessage(depth int, funcName string) string {
	return "Nesting depth " + itoa(depth) + " exceeds maximum of " + itoa(r.maxDepth) + " in function " + funcName
}

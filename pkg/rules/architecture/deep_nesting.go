package architecture

import (
	"go/ast"
	"strconv"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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

// Configure sets rule settings
func (r *DeepNestingRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.maxDepth = r.GetIntSetting("max_depth", defaultMaxNestingDepth)
	return nil
}

// AnalyzeFile checks for deeply nested code
func (r *DeepNestingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	return helpers.AnalyzeFuncDecls(ctx, r.checkFuncDecl)
}

func (r *DeepNestingRule) checkFuncDecl(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	return r.checkNesting(ctx, fn.Body, 0, fn.Name.Name)
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

	default:
		// Statements without their own blocks (assignments, declarations,
		// expression/go/defer statements) may still carry function literals
		// whose bodies must be checked
		violations = r.checkFuncLits(ctx, node, funcName)
	}

	return violations
}

// checkFuncLits finds function literals inside a node and checks their bodies.
// A closure body is a new function, so its nesting depth starts from zero.
func (r *DeepNestingRule) checkFuncLits(ctx *core.FileContext, node ast.Node, funcName string) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(node, func(n ast.Node) bool {
		if lit, ok := n.(*ast.FuncLit); ok {
			violations = append(violations, r.checkNesting(ctx, lit.Body, 0, funcName)...)
			return false // nested literals are reached via checkNesting
		}
		return true
	})
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
	return "Nesting depth " + strconv.Itoa(depth) + " exceeds maximum of " + strconv.Itoa(r.maxDepth) + " in function " + funcName
}

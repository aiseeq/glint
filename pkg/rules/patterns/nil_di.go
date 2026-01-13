package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNilDIRule())
}

// NilDIRule detects nil arguments passed to constructor functions (New*)
// which often indicates missing dependency injection configuration
type NilDIRule struct {
	*rules.BaseRule
}

// NewNilDIRule creates the rule
func NewNilDIRule() *NilDIRule {
	return &NilDIRule{
		BaseRule: rules.NewBaseRule(
			"nil-di",
			"patterns",
			"Detects nil arguments to constructor functions which may indicate missing DI configuration",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for nil arguments in constructor calls
func (r *NilDIRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Get function name
		funcName := r.getFuncName(call)
		if funcName == "" {
			return true
		}

		// Only check constructors (functions starting with "New")
		if !strings.HasPrefix(funcName, "New") {
			return true
		}

		// Check each argument for nil
		for i, arg := range call.Args {
			if r.isNilIdent(arg) {
				line := r.getLineFromNode(ctx, call)
				v := r.CreateViolation(ctx.RelPath, line,
					"Nil argument to constructor "+funcName+" (arg "+string(rune('1'+i))+")")
				v.WithCode(ctx.GetLine(line))
				v.WithSuggestion("Review if nil is intentional or if a dependency should be injected")
				v.WithContext("constructor", funcName)
				v.WithContext("arg_index", i+1)
				violations = append(violations, v)
			}
		}

		return true
	})

	return violations
}

// getFuncName extracts the function name from a call expression
func (r *NilDIRule) getFuncName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// isNilIdent checks if expression is the nil identifier
func (r *NilDIRule) isNilIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "nil"
}

func (r *NilDIRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
	if node == nil {
		return 1
	}

	pos := node.Pos()
	if pos == 0 {
		return 1
	}

	offset := int(pos) - 1
	if offset < 0 || offset >= len(ctx.Content) {
		return 1
	}

	line := 1
	for i := 0; i < offset && i < len(ctx.Content); i++ {
		if ctx.Content[i] == '\n' {
			line++
		}
	}
	return line
}

package architecture

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewLongFunctionRule())
}

// LongFunctionRule detects functions that are too long
type LongFunctionRule struct {
	*rules.BaseRule
	maxLines int
}

// NewLongFunctionRule creates the rule
func NewLongFunctionRule() *LongFunctionRule {
	return &LongFunctionRule{
		BaseRule: rules.NewBaseRule(
			"long-function",
			"architecture",
			"Detects functions that exceed the maximum line count",
			core.SeverityMedium,
		),
		maxLines: 50, // Default max lines
	}
}

// Configure sets rule settings
func (r *LongFunctionRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.maxLines = r.GetIntSetting("max_lines", 50)
	return nil
}

// AnalyzeFile checks for long functions
func (r *LongFunctionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body == nil {
				return true
			}

			startPos := ctx.GoFileSet.Position(fn.Body.Lbrace)
			endPos := ctx.GoFileSet.Position(fn.Body.Rbrace)
			lineCount := endPos.Line - startPos.Line

			if lineCount > r.maxLines {
				funcName := fn.Name.Name
				if fn.Recv != nil && len(fn.Recv.List) > 0 {
					// Method - prepend receiver type
					if ident, ok := getReceiverType(fn.Recv.List[0].Type); ok {
						funcName = ident + "." + funcName
					}
				}

				v := r.CreateViolation(ctx.RelPath, startPos.Line, "")
				v.Message = formatLongFuncMessage(funcName, lineCount, r.maxLines)
				v.WithCode(ctx.GetLine(startPos.Line - 1)) // Function signature line
				v.WithSuggestion("Consider breaking this function into smaller functions")

				if lineCount > r.maxLines*2 {
					v.Severity = core.SeverityHigh
				}

				violations = append(violations, v)
			}
		}
		return true
	})

	return violations
}

func getReceiverType(expr ast.Expr) (string, bool) {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name, true
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return "*" + ident.Name, true
		}
	}
	return "", false
}

func formatLongFuncMessage(name string, lines, max int) string {
	return name + " is " + itoa(lines) + " lines long (max " + itoa(max) + ")"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}

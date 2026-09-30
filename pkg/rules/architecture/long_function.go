package architecture

import (
	"go/ast"
	"strconv"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

const (
	defaultMaxFunctionLines = 100
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
		maxLines: defaultMaxFunctionLines,
	}
}

// Configure sets rule settings
func (r *LongFunctionRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.maxLines = r.GetIntSetting("max_lines", defaultMaxFunctionLines)
	return nil
}

// AnalyzeFile checks for long functions
func (r *LongFunctionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() {
		return nil
	}
	if ctx.IsTestFile() {
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
					if name := receiverDisplayName(fn.Recv.List[0].Type); name != "" {
						funcName = name + "." + funcName
					}
				}

				v := r.CreateViolation(ctx.RelPath, startPos.Line, "")
				v.Message = formatLongFuncMessage(funcName, lineCount, r.maxLines)
				v.WithCode(ctx.GetLine(ctx.GoFileSet.Position(fn.Pos()).Line))
				v.WithSuggestion("Consider breaking this function into smaller functions")
				v.WithContext("function", fn.Name.Name)
				v.WithContext("lines", lineCount)
				v.WithContext("max_lines", r.maxLines)

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

// receiverDisplayName names a receiver type the way the finding shows it:
// the base type, with a star for a pointer receiver (*Box for *Box[T]).
func receiverDisplayName(expr ast.Expr) string {
	name := helpers.ReceiverTypeName(expr)
	if _, pointer := expr.(*ast.StarExpr); pointer && name != "" {
		return "*" + name
	}
	return name
}

func formatLongFuncMessage(name string, lines, max int) string {
	return name + " is " + strconv.Itoa(lines) + " lines long (max " + strconv.Itoa(max) + ")"
}

package frontendrules

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// analyzeGoMissingAmounts reports the Go forms of a missing amount turned
// into zero: a decimal parser that answers empty or unreadable text with
// decimal.Zero applied to money fields, and a nil *decimal replaced with
// decimal.Zero.
func (r *MissingAmountCoercedToZeroRule) analyzeGoMissingAmounts(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}
	parsers := patternkit.ZeroAnsweringDecimalParsers(ctx.GoAST)
	var violations []*core.Violation
	report := func(node ast.Node, message, suggestion string) {
		line := ctx.LineFor(node)
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion(suggestion)
		violations = append(violations, v)
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			name := helpers.CalleeName(node)
			if !parsers[name] || len(node.Args) != 1 {
				return true
			}
			if field, ok := node.Args[0].(*ast.SelectorExpr); ok && patternkit.HasWordFrom(field.Sel.Name, patternkit.MoneyWords) {
				report(node, name+" answers an empty or unreadable "+field.Sel.Name+" with zero - a missing amount goes on as an amount of 0",
					"Keep the amount missing (a nullable value) or refuse the payload without it")
			}
		case *ast.BlockStmt:
			for i := 0; i+1 < len(node.List); i++ {
				if ret, name := patternkit.ZeroReturnForNilAmount(node.List[i], node.List[i+1]); ret != nil {
					report(ret, "Missing "+name+" answered with decimal.Zero - the caller reads 0 for an amount nobody knows",
						"Return the amount as absent (a nil pointer, null) or an error, and let the caller decide")
				}
				if name := patternkit.ZeroPresetOverNilAmount(node.List[i], node.List[i+1]); name != "" {
					report(node.List[i], "Missing "+name+" replaced with decimal.Zero - the receiver reads 0 for an amount nobody knows",
						"Send the amount as absent (null) or refuse to build the message without it")
				}
			}
		}
		return true
	})
	return violations
}

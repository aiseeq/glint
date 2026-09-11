package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFinancialDirectionalRoundingRule())
}

// directionalRoundingMethods are the shopspring/decimal methods that move a
// value one way only. On money each of them biases every figure in the same
// direction instead of to the nearest cent.
var directionalRoundingMethods = map[string]string{
	"RoundCeil":  "rounds every amount up",
	"RoundUp":    "rounds every amount away from zero",
	"RoundFloor": "rounds every amount down",
	"RoundDown":  "rounds every amount toward zero",
	"Truncate":   "drops the digits past the scale",
	"Ceil":       "rounds every amount up to a whole unit",
	"Floor":      "rounds every amount down to a whole unit",
}

// FinancialDirectionalRoundingRule detects one-directional rounding of monetary
// decimals. Money has one rounding rule per system, and it is symmetric: a
// place that ceils, floors or truncates instead produces a figure the rest of
// the system cannot reproduce — a screen showing a cent the stored payment
// never had, an export that disagrees with the invoice. Deliberate cases exist
// (splitting an amount into parts that must not exceed a ceiling, a fee always
// resolved in the customer's favour); they belong in the config as an exception
// with a reason, so the choice is visible rather than buried in a call.
type FinancialDirectionalRoundingRule struct {
	*rules.BaseRule
}

// NewFinancialDirectionalRoundingRule creates the rule.
func NewFinancialDirectionalRoundingRule() *FinancialDirectionalRoundingRule {
	return &FinancialDirectionalRoundingRule{BaseRule: rules.NewBaseRule(
		"financial-directional-rounding",
		"patterns",
		"Detects one-directional rounding (ceil/floor/truncate) of monetary decimals — the figure stops matching the amount the payment carries",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports directional rounding applied to money.
func (r *FinancialDirectionalRoundingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	if len(importedPackageAliases(ctx.GoAST, `"github.com/shopspring/decimal"`, "decimal")) == 0 {
		return nil
	}

	var violations []*core.Violation
	for _, declaration := range ctx.GoAST.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		types := NewTypeInferrerFromNode(function)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			effect, directional := directionalRoundingMethods[selector.Sel.Name]
			if !directional {
				return true
			}
			receiver := receiverExpression(selector.X)
			if receiver == "" || !looksLikeMoney(receiver) {
				return true
			}
			if isTimeValue(types, selector.X) || takesDuration(types, call) || isMoneyRatio(selector.X) {
				return true
			}
			line := ctx.LineFor(call)
			violations = append(violations, r.violation(ctx, line, selector.Sel.Name, effect))
			return true
		})
	}
	return violations
}

// receiverExpression renders the identifiers a call is made on, so the rule can
// read the name the code gave the value: `total.Div(parts)` reads as
// "total.Div".
func receiverExpression(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		base := receiverExpression(typed.X)
		if base == "" {
			return typed.Sel.Name
		}
		return base + "." + typed.Sel.Name
	case *ast.CallExpr:
		return receiverExpression(typed.Fun)
	case *ast.IndexExpr:
		return receiverExpression(typed.X)
	case *ast.ParenExpr:
		return receiverExpression(typed.X)
	default:
		return ""
	}
}

// takesDuration reports whether the call rounds by a duration. decimal rounds
// by an int32 scale, so a duration argument means this is time.Time's own
// Truncate — reached through a chain like `record.UpdatedAt.UTC()`, where the
// receiver still reads as money by name.
func takesDuration(types *TypeInferrer, call *ast.CallExpr) bool {
	if len(call.Args) != 1 {
		return false
	}
	duration := false
	ast.Inspect(call.Args[0], func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := typed.X.(*ast.Ident); ok && pkg.Name == "time" {
				duration = true
			}
		case *ast.Ident:
			if info, known := types.GetType(typed.Name); known && strings.HasPrefix(info.TypeName, "time.") {
				duration = true
			}
		}
		return !duration
	})
	return duration
}

// isMoneyRatio reports whether the receiver is one money value divided by
// another: the result is a count, not an amount, and rounding it one way is how
// a caller covers the whole sum (how many parts a payout has to be split into).
func isMoneyRatio(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Div" {
		return false
	}
	return looksLikeMoney(receiverExpression(call.Args[0]))
}

// isTimeValue reports whether the receiver is a time value: time.Time carries
// its own Truncate, and truncating a deadline to the hour is not a money bug.
func isTimeValue(types *TypeInferrer, expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	info, known := types.GetType(ident.Name)
	return known && (info.IsTime || strings.HasPrefix(info.TypeName, "time."))
}

func (r *FinancialDirectionalRoundingRule) violation(ctx *core.FileContext, line int, method, effect string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, line,
		"decimal."+method+" on a monetary value "+effect+" — money needs one symmetric rounding shared by the whole system")
	if code := strings.TrimSpace(ctx.GetLine(line)); code != "" {
		v.WithCode(code)
	}
	v.WithSuggestion("Round money through the single rounding helper the domain exposes (Round to the money scale), or record this call as a configured exception with the reason it must round one way.")
	v.WithContext("pattern", "financial-directional-rounding")
	return v
}

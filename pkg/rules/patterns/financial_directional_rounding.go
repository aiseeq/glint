package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
//
// Not reported: a rounding whose remainder the function takes back — the
// source minus the rounded parts (total.Sub(base.Mul(n))) kept in a variable
// the code goes on to use. That is the largest-remainder split: the parts are
// floored and the dropped cents handed out again, so they add up exactly.
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

// AnalyzeFile reports directional rounding applied to money, judging the
// receiver by what the file itself declares.
func (r *FinancialDirectionalRoundingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *FinancialDirectionalRoundingRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; with type information the receiver's
// type decides whether the call rounds a decimal.
func (r *FinancialDirectionalRoundingRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze reports directional rounding of decimal.Decimal values named as
// money. info is nil for a file without type information: then a receiver is a
// decimal only when the file declares it as one (a parameter, variable, field
// or a decimal method chain over one); anything else is unknown and not
// reported.
func (r *FinancialDirectionalRoundingRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	aliases := helpers.PackageAliases(ctx.GoAST, `"`+shopspringDecimalPath+`"`, "decimal")
	if len(aliases) == 0 {
		return nil
	}
	var decimalFields decimalFieldEvidence
	if info == nil {
		decimalFields = collectDecimalFieldEvidence(ctx.GoAST, aliases)
	}

	var violations []*core.Violation
	for _, declaration := range ctx.GoAST.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		isDecimal := func(expr ast.Expr) bool { return isShopspringDecimalType(info.TypeOf(expr)) }
		if info == nil {
			inferred := NewTypeInferrerFromNode(function)
			isDecimal = func(expr ast.Expr) bool {
				return declaredDecimalValue(expr, function, inferred, aliases, decimalFields)
			}
		}
		var parents map[ast.Node]ast.Node
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
			if !isDecimal(selector.X) || isMoneyRatio(selector.X) {
				return true
			}
			if parents == nil {
				parents = helpers.ParentMap(function.Body)
			}
			if remainderTakenBack(function.Body, roundedResultName(call, parents), receiver) {
				return true
			}
			line := ctx.LineFor(call)
			violations = append(violations, r.violation(ctx, line, selector.Sel.Name, effect))
			return true
		})
	}
	return violations
}

// roundedResultName returns the variable the call's result is assigned to
// (base := total.Div(n).RoundDown(2)), or "".
func roundedResultName(call *ast.CallExpr, parents map[ast.Node]ast.Node) string {
	switch parent := parents[call].(type) {
	case *ast.AssignStmt:
		for i, rhs := range parent.Rhs {
			if rhs == call && len(parent.Lhs) == len(parent.Rhs) {
				return usedName(parent.Lhs[i])
			}
		}
	case *ast.ValueSpec:
		for i, value := range parent.Values {
			if value == call && len(parent.Names) == len(parent.Values) {
				return usedName(parent.Names[i])
			}
		}
	}
	return ""
}

// usedName returns the name of an identifier other than the blank one, or "".
func usedName(expr ast.Expr) string {
	ident, ok := expr.(*ast.Ident)
	if !ok || ident.Name == "_" {
		return ""
	}
	return ident.Name
}

// remainderTakenBack reports whether the function subtracts the rounded value
// from the source it was rounded from (rem := total.Sub(base.Mul(n))) into a
// variable it reads again: the remainder the rounding dropped is distributed,
// not lost.
func remainderTakenBack(body *ast.BlockStmt, rounded, roundedReceiver string) bool {
	if rounded == "" {
		return false
	}
	source, _, _ := strings.Cut(roundedReceiver, ".")
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if found || !ok || len(assign.Lhs) != len(assign.Rhs) {
			return !found
		}
		for i, rhs := range assign.Rhs {
			remainder := usedName(assign.Lhs[i])
			call, ok := rhs.(*ast.CallExpr)
			if remainder == "" || !ok || len(call.Args) != 1 {
				continue
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Sub" || !mentionsIdent(call.Args[0], rounded) {
				continue
			}
			subSource, _, _ := strings.Cut(receiverExpression(selector.X), ".")
			if subSource == source && identReadCount(body, remainder) > 1 {
				found = true
			}
		}
		return !found
	})
	return found
}

// identReadCount counts the identifiers named name in the body.
func identReadCount(body *ast.BlockStmt, name string) int {
	count := 0
	ast.Inspect(body, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok && ident.Name == name {
			count++
		}
		return true
	})
	return count
}

// decimalResultMethods are decimal.Decimal methods returning a decimal.Decimal.
var decimalResultMethods = map[string]bool{
	"Abs": true, "Add": true, "Ceil": true, "Div": true, "DivRound": true, "Floor": true,
	"Mod": true, "Mul": true, "Neg": true, "Pow": true, "Round": true, "RoundBank": true,
	"RoundCash": true, "RoundCeil": true, "RoundDown": true, "RoundFloor": true, "RoundUp": true,
	"Shift": true, "Sub": true, "Truncate": true,
}

// declaredDecimalValue reports whether the file declares expr as a
// decimal.Decimal: a declared variable, parameter or struct field, a decimal
// constructor, or a decimal method whose receiver is one of those.
func declaredDecimalValue(
	expr ast.Expr,
	function *ast.FuncDecl,
	inferred *TypeInferrer,
	aliases map[string]bool,
	decimalFields decimalFieldEvidence,
) bool {
	expr = ast.Unparen(expr)
	if call, ok := expr.(*ast.CallExpr); ok {
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if pkg, ok := selector.X.(*ast.Ident); ok && aliases[pkg.Name] {
			return strings.HasPrefix(selector.Sel.Name, "NewFrom") || selector.Sel.Name == "RequireFromString"
		}
		return decimalResultMethods[selector.Sel.Name] &&
			declaredDecimalValue(selector.X, function, inferred, aliases, decimalFields)
	}
	return isShopspringDecimalReceiver(expr, expr.Pos(), function, inferred, aliases, decimalFields)
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

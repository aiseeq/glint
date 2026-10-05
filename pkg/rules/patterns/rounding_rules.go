package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewRoundedTotalNotSumOfRoundedPartsRule())
	rules.Register(NewPublishedValueRoundedAfterUseRule())
	rules.Register(NewPercentileIndexOffByOneRule())
}

// roundedVar returns the variable of v.Round(n) or v.StringFixed(n) on a
// decimal and the spelling of n.
func roundedVar(info *types.Info, expr ast.Expr) (*ast.Ident, string, bool) {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil, "", false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || !roundingMethods[sel.Sel.Name] {
		return nil, "", false
	}
	ident, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok || !isShopspringDecimalType(info.TypeOf(ident)) {
		return nil, "", false
	}
	places, ok := ast.Unparen(call.Args[0]).(*ast.BasicLit)
	if !ok {
		return nil, "", false
	}
	return ident, places.Value, true
}

// roundedFields returns the fields of a struct literal set to a rounded
// variable, by the variable.
func roundedFields(info *types.Info, lit *ast.CompositeLit) map[types.Object]*ast.KeyValueExpr {
	fields := make(map[types.Object]*ast.KeyValueExpr)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if ident, _, ok := roundedVar(info, kv.Value); ok {
			fields[info.ObjectOf(ident)] = kv
		}
	}
	return fields
}

// addOperands returns the variables of a.Add(b).Add(c), nil when an operand
// is not a variable.
func addOperands(expr ast.Expr) []*ast.Ident {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		ident, ok := ast.Unparen(expr).(*ast.Ident)
		if !ok {
			return nil
		}
		return []*ast.Ident{ident}
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Add" || len(call.Args) != 1 {
		return nil
	}
	left := addOperands(sel.X)
	right, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
	if left == nil || !ok {
		return nil
	}
	return append(left, right)
}

// NewRoundedTotalNotSumOfRoundedPartsRule creates
// rounded-total-not-sum-of-rounded-parts: a total stored rounded next to
// its rounded parts while it was summed from the unrounded ones. Rounded
// separately, the parts and the total disagree by a cent, and the stored
// breakdown does not reconcile:
//
//	margin := spread.Add(surcharge)
//	return &Quote{
//		SpreadAmount:    spread.Round(2),
//		SurchargeAmount: surcharge.Round(2),
//		MarginAmount:    margin.Round(2),
func NewRoundedTotalNotSumOfRoundedPartsRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"rounded-total-not-sum-of-rounded-parts",
			"patterns",
			"Detects a total stored rounded next to its rounded parts while it was summed from the unrounded ones — the stored breakdown is a cent off its total",
			core.SeverityMedium,
		),
		suggestion: "Round the parts first and store their sum as the total",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		defs := singleDefinitions(scope.info, fn.Body)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			rounded := roundedFields(scope.info, lit)
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				total, places, ok := roundedVar(scope.info, kv.Value)
				if !ok {
					continue
				}
				parts := addOperands(defs[scope.info.ObjectOf(total)])
				if len(parts) < 2 || !allRoundedAs(scope.info, rounded, parts, places) {
					continue
				}
				findings = append(findings, funcFinding{node: kv, message: "The total " + total.Name + " is rounded on its own while its parts are stored rounded — the stored parts do not add up to it"})
			}
			return true
		})
		return findings
	}
	return r
}

// allRoundedAs reports parts that the literal stores rounded to the given
// places.
func allRoundedAs(info *types.Info, rounded map[types.Object]*ast.KeyValueExpr, parts []*ast.Ident, places string) bool {
	for _, part := range parts {
		kv, ok := rounded[info.ObjectOf(part)]
		if !ok {
			return false
		}
		if _, p, _ := roundedVar(info, kv.Value); p != places {
			return false
		}
	}
	return true
}

// NewPublishedValueRoundedAfterUseRule creates
// published-value-rounded-after-use: a value computed with unrounded and
// published rounded, next to the result computed from it. Whoever repeats
// the computation from the published value gets another result:
//
//	payout := amount.Mul(clientRate)
//	return &Quote{
//		ClientRate:   clientRate.Round(8),
//		PayoutAmount: payout.Round(2),
func NewPublishedValueRoundedAfterUseRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"published-value-rounded-after-use",
			"patterns",
			"Detects a value published rounded next to a result computed from its unrounded form — the published value does not reproduce the result",
			core.SeverityMedium,
		),
		suggestion: "Round the value once, before computing with it, and publish the same rounded value",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		defs := singleDefinitions(scope.info, fn.Body)
		assigned := valueAssignments(scope.info, fn.Body)
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				value, _, ok := roundedVar(scope.info, kv.Value)
				if !ok {
					continue
				}
				obj := scope.info.ObjectOf(value)
				if slices.ContainsFunc(assigned[obj], isRoundCall) {
					continue
				}
				if other := siblingFromProduct(scope.info, defs, lit, kv, obj); other != "" {
					findings = append(findings, funcFinding{node: kv, message: "The value " + value.Name + " is published rounded while " + other + " next to it was computed from its unrounded form — the published value does not reproduce it"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// isRoundCall reports an expression whose last call rounds: x.Mul(y).Round(8),
// or a helper named for rounding, RoundPublishedRate(r).
func isRoundCall(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		return roundingMethods[fun.Sel.Name] || strings.HasPrefix(fun.Sel.Name, "Round")
	case *ast.Ident:
		return strings.HasPrefix(fun.Name, "round") || strings.HasPrefix(fun.Name, "Round")
	}
	return false
}

// siblingFromProduct returns the field of the literal, other than published,
// whose value is a product or a quotient with the variable: directly, or a
// variable defined as one.
func siblingFromProduct(info *types.Info, defs map[types.Object]ast.Expr, lit *ast.CompositeLit, published *ast.KeyValueExpr, obj types.Object) string {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok || kv == published {
			continue
		}
		if multipliesBy(info, defs, kv.Value, obj, 2) {
			if key, ok := kv.Key.(*ast.Ident); ok {
				return key.Name
			}
		}
	}
	return ""
}

// multipliesBy reports an expression multiplying or dividing by the
// variable, or reading a variable defined so, within depth definitions.
func multipliesBy(info *types.Info, defs map[types.Object]ast.Expr, expr ast.Expr, obj types.Object, depth int) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			sel, ok := ast.Unparen(node.Fun).(*ast.SelectorExpr)
			if ok && (sel.Sel.Name == "Mul" || sel.Sel.Name == "Div") && len(node.Args) == 1 {
				if isIdentOf(info, sel.X, obj) || isIdentOf(info, node.Args[0], obj) {
					found = true
				}
			}
		case *ast.Ident:
			if def, ok := defs[info.ObjectOf(node)]; ok && depth > 0 && info.ObjectOf(node) != obj {
				found = multipliesBy(info, defs, def, obj, depth-1)
			}
		}
		return !found
	})
	return found
}

// isIdentOf reports the variable itself.
func isIdentOf(info *types.Info, expr ast.Expr, obj types.Object) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && info.ObjectOf(ident) == obj
}

// NewPercentileIndexOffByOneRule creates percentile-index-off-by-one: the
// index of a percentile taken as p*n/100 in a sorted slice. Nearest rank is
// ceil(p*n/100) counted from one, so the floor used as a zero-based index
// sits one rank high - the median of four values is the third, and p99 of a
// hundred is the maximum:
//
//	idx := (pct * len(sorted)) / 100
func NewPercentileIndexOffByOneRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"percentile-index-off-by-one",
			"patterns",
			"Detects a percentile taken from a sorted slice at index p*n/100 — the zero-based index sits one rank high, and p99 of a hundred values is the maximum",
			core.SeverityLow,
		),
		suggestion: "Use the nearest rank ceil(p*n/100) and subtract one for the zero-based index: (p*n+99)/100 - 1",
	}
	r.check = func(_ funcScope, fn *ast.FuncDecl) []funcFinding {
		name := strings.ToLower(fn.Name.Name)
		if fn.Body == nil || (!strings.Contains(name, "percentile") && !strings.Contains(name, "quantile")) {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			quo, ok := n.(*ast.BinaryExpr)
			if !ok || quo.Op != token.QUO || !isIntLiteral(ast.Unparen(quo.Y), 100) {
				return true
			}
			mul, ok := ast.Unparen(quo.X).(*ast.BinaryExpr)
			if !ok || mul.Op != token.MUL || (!isLenCall(ast.Unparen(mul.X)) && !isLenCall(ast.Unparen(mul.Y))) {
				return true
			}
			findings = append(findings, funcFinding{node: quo, message: "The percentile index p*n/100 is one rank high for a zero-based slice — p99 of a hundred values is the maximum"})
			return true
		})
		return findings
	}
	return r
}

package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDecimalDividedBeforeMultipliedRule())
	rules.Register(NewDecimalParseBoundedByTrimmedDigitsRule())
	rules.Register(NewMoneyRoundingDirectionMixedRule())
}

// NewDecimalDividedBeforeMultipliedRule creates
// decimal-divided-before-multiplied: an amount scaled by a ratio that Div
// computed first.
//
//	ratio := part.Div(whole)            // rounded to DivisionPrecision digits
//	taken := position.Amount.Mul(ratio) // 2600 - 497.4 leaves 2102.60000000000002
//
// Div rounds its quotient, and the product carries that rounding error into
// the amount as dust past the cents: a position that should be closed keeps a
// remainder, a sum stops matching its parts. Multiplying first and dividing
// last leaves a single rounding, at the end.
func NewDecimalDividedBeforeMultipliedRule() *typedFuncRule {
	return newFuncRule("decimal-divided-before-multiplied",
		"Detects an amount multiplied by a decimal ratio Div computed first — Div rounds the ratio, and the amount carries the error as dust past the cents",
		core.SeverityMedium,
		"Multiply first and divide last: amount.Mul(part).Div(whole)",
		decimalDividedBeforeMultiplied)
}

func decimalDividedBeforeMultiplied(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	if fn.Body == nil {
		return nil
	}
	info := scope.info
	defs := singleDefinitions(info, fn.Body)
	var findings []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || !decimalMethodCall(info, call, "Mul") {
			return true
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		for _, pair := range [2][2]ast.Expr{{sel.X, call.Args[0]}, {call.Args[0], sel.X}} {
			ratio, amount := pair[0], pair[1]
			div := decimalQuotient(info, defs, ratio, 0)
			if div == nil || !looksLikeMoney(types.ExprString(amount)) {
				continue
			}
			if constantDecimal(info, defs, amount, 0) || constantDecimal(info, defs, div.Args[0], 0) ||
				unitScale(info, defs, div.Args[0], 0) || hasTokenIn(types.ExprString(div), timeFractionTokens) {
				continue
			}
			findings = append(findings, funcFinding{node: call,
				message: types.ExprString(amount) + " is multiplied by a ratio Div rounded first (" + types.ExprString(div) + ") — the rounding error stays in the amount as dust past the cents"})
			break
		}
		return true
	})
	return findings
}

// timeFractionTokens name a ratio of durations: the weight of a cash flow by
// the part of the period it was invested (days.Sub(fromStart).Div(days)).
// It weighs an amount inside a return calculation, not a share of it.
var timeFractionTokens = wordSet("day", "hour", "minute", "second", "year", "period", "duration", "elapsed")

// unitScale reports a divisor that is a power of ten built at run time:
// decimal.New(1, int32(decimals)), pow10Of(decimals), ten.Pow(exp).
// Dividing raw token units by it is a change of unit.
func unitScale(info *types.Info, defs map[types.Object]ast.Expr, expr ast.Expr, depth int) bool {
	if depth > 3 {
		return false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		if calleeIn(e, info, shopspringDecimalPath, "New") && len(e.Args) == 2 {
			if tv, ok := info.Types[e.Args[0]]; ok && tv.Value != nil && tv.Value.String() == "1" {
				return true
			}
		}
		return hasWordFrom(callName(e), map[string]bool{"pow": true, "pow10": true})
	case *ast.Ident:
		if def, ok := defs[info.ObjectOf(e)]; ok {
			return unitScale(info, defs, def, depth+1)
		}
	}
	return false
}

// decimalMethodCall reports a call of the named method of decimal.Decimal.
func decimalMethodCall(info *types.Info, call *ast.CallExpr, name string) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	method, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := method.Type().(*types.Signature)
	return ok && sig.Recv() != nil && isShopspringDecimalType(sig.Recv().Type())
}

// decimalQuotient returns the Div call an expression is: the call itself or
// a local variable defined once by it.
func decimalQuotient(info *types.Info, defs map[types.Object]ast.Expr, expr ast.Expr, depth int) *ast.CallExpr {
	if depth > 3 {
		return nil
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		if len(e.Args) == 1 && decimalMethodCall(info, e, "Div") {
			return e
		}
	case *ast.Ident:
		if def, ok := defs[info.ObjectOf(e)]; ok {
			return decimalQuotient(info, defs, def, depth+1)
		}
	}
	return nil
}

// constantDecimal reports a decimal fixed by the code: a constructor of
// constants (decimal.NewFromInt(100)), a package-level variable
// (decimalHundred), or a local defined once as one of them. Dividing by a
// constant scale or multiplying by one is a change of unit, not a ratio.
func constantDecimal(info *types.Info, defs map[types.Object]ast.Expr, expr ast.Expr, depth int) bool {
	if depth > 3 {
		return false
	}
	expr = ast.Unparen(expr)
	if tv, ok := info.Types[expr]; ok && tv.Value != nil {
		return true
	}
	switch e := expr.(type) {
	case *ast.CallExpr:
		fn := staticFunc(info, e)
		if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != shopspringDecimalPath {
			return false
		}
		if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
			return false
		}
		for _, arg := range e.Args {
			if tv, ok := info.Types[arg]; !ok || tv.Value == nil {
				return false
			}
		}
		return true
	case *ast.Ident:
		obj := info.ObjectOf(e)
		if def, ok := defs[obj]; ok {
			return constantDecimal(info, defs, def, depth+1)
		}
		return packageLevelVar(obj)
	case *ast.SelectorExpr:
		return packageLevelVar(info.ObjectOf(e.Sel))
	}
	return false
}

// packageLevelVar reports a variable declared at the top level of a package.
func packageLevelVar(obj types.Object) bool {
	v, ok := obj.(*types.Var)
	return ok && !v.IsField() && v.Pkg() != nil && v.Parent() == v.Pkg().Scope()
}

// NewDecimalParseBoundedByTrimmedDigitsRule creates
// decimal-parse-bounded-by-trimmed-digits: a number checked for its digit
// count only after the zeros were trimmed, then parsed whole.
//
//	if len(strings.TrimRight(frac, "0")) > maxFractionDigits { return err }
//	parsed, err := decimal.NewFromString(raw)
//
// "10." followed by 900000 zeros passes the check and parses to an exponent of
// -900000: every comparison or addition with it rescales the other operand to
// that exponent, seconds of CPU per request on input anyone can send.
func NewDecimalParseBoundedByTrimmedDigitsRule() *typedFuncRule {
	return newFuncRule("decimal-parse-bounded-by-trimmed-digits",
		"Detects a decimal parsed from text whose digits were counted only after trimming zeros — a run of zeros passes the limit and becomes a huge exponent every comparison rescales to",
		core.SeverityHigh,
		"Bound the length of the text itself, or parse the number rebuilt from its significant digits",
		decimalParseBoundedByTrimmedDigits)
}

func decimalParseBoundedByTrimmedDigits(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	if fn.Body == nil {
		return nil
	}
	info := scope.info
	if !countsTrimmedZeros(info, fn.Body) {
		return nil
	}
	lengthChecked := lengthCheckedTexts(fn.Body)
	var findings []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		text := numberParseText(info, call)
		if text == nil || lengthChecked[types.ExprString(text)] {
			return true
		}
		findings = append(findings, funcFinding{node: call,
			message: "The digits of " + types.ExprString(text) + " are limited only after trimming zeros, then the whole text is parsed — a run of zeros passes and becomes a huge exponent"})
		return true
	})
	return findings
}

// numberParseText returns the text a call parses into an arbitrary-precision
// number: decimal.NewFromString(s), decimal.RequireFromString(s),
// new(big.Float).SetString(s), new(big.Rat).SetString(s).
func numberParseText(info *types.Info, call *ast.CallExpr) ast.Expr {
	if calleeIn(call, info, shopspringDecimalPath, "NewFromString", "RequireFromString") {
		if fn := staticFunc(info, call); fn != nil {
			if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() == nil {
				return call.Args[0]
			}
		}
		return nil
	}
	fn := staticFunc(info, call)
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "math/big" || fn.Name() != "SetString" {
		return nil
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	recv := types.TypeString(sig.Recv().Type(), nil)
	if strings.HasSuffix(recv, "big.Float") || strings.HasSuffix(recv, "big.Rat") {
		return call.Args[0]
	}
	return nil
}

// countsTrimmedZeros reports a body that measures text with its zeros cut:
// len(strings.TrimRight(frac, "0")), len(strings.TrimLeft(whole, "0")).
func countsTrimmedZeros(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found || len(call.Args) != 1 || !isIdentNamed(call.Fun, "len") {
			return !found
		}
		trim, ok := ast.Unparen(call.Args[0]).(*ast.CallExpr)
		if !ok || len(trim.Args) != 2 || !calleeIn(trim, info, "strings", "TrimLeft", "TrimRight", "Trim") {
			return true
		}
		if cutset, ok := stringLiteral(trim.Args[1]); ok && strings.Contains(cutset, "0") {
			found = true
		}
		return !found
	})
	return found
}

// lengthCheckedTexts returns the expressions whose length the body compares:
// len(raw) > maxLen.
func lengthCheckedTexts(body *ast.BlockStmt) map[string]bool {
	checked := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		switch bin.Op {
		case token.GTR, token.GEQ, token.LSS, token.LEQ:
		default:
			return true
		}
		for _, side := range []ast.Expr{bin.X, bin.Y} {
			if call, ok := ast.Unparen(side).(*ast.CallExpr); ok && len(call.Args) == 1 && isIdentNamed(call.Fun, "len") {
				checked[types.ExprString(call.Args[0])] = true
			}
		}
		return true
	})
	return checked
}

// NewMoneyRoundingDirectionMixedRule creates money-rounding-direction-mixed:
// one row of output whose amounts are put on the cent grid in two
// directions.
//
//	DailyEntry{
//		ClosingAmount: day.ClosingAmount.StringFixed(2), // half up
//		DailyGain:   yieldCents(day.Yield),            // RoundFloor(2)
//	}
//
// The figures of one row disagree by a cent with each other and with the
// screens that floor them all: a balance shows 10,630.51 in one place and
// 10,630.50 in another.
func NewMoneyRoundingDirectionMixedRule() *typedFuncRule {
	return newFuncRule("money-rounding-direction-mixed",
		"Detects one row of output whose amounts are rounded to the same places in two directions (half up and down) — the figures of the row disagree by a cent with each other and with the screens",
		core.SeverityMedium,
		"Put every amount of the row on one cent grid through one helper (floor everywhere, or half up everywhere)",
		moneyRoundingDirectionMixed)
}

// roundingDirection is how a value reaches its decimal places.
type roundingDirection int

const (
	roundingNone roundingDirection = iota
	roundingHalfUp
	roundingDown
)

// roundedField is a field of a literal and how its value was rounded.
type roundedField struct {
	name      string
	node      ast.Node
	direction roundingDirection
	places    int64
}

func moneyRoundingDirectionMixed(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	if fn.Body == nil {
		return nil
	}
	var findings []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		var fields []roundedField
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			direction, places := valueRounding(scope, kv.Value, 1)
			if direction != roundingNone {
				fields = append(fields, roundedField{name: key.Name, node: kv, direction: direction, places: places})
			}
		}
		down := make(map[int64]string)
		for _, field := range fields {
			if _, seen := down[field.places]; !seen && field.direction == roundingDown {
				down[field.places] = field.name
			}
		}
		for _, up := range fields {
			if name, ok := down[up.places]; ok && up.direction == roundingHalfUp {
				findings = append(findings, funcFinding{node: up.node,
					message: up.name + " is rounded half up while " + name + " of the same row is rounded down — the row's amounts sit on two cent grids"})
			}
		}
		return true
	})
	return findings
}

// halfUpMethods and downMethods are the decimal methods that round half up
// and toward the floor, with their places as the first argument.
var (
	halfUpMethods = map[string]bool{"StringFixed": true, "Round": true}
	downMethods   = map[string]bool{"RoundFloor": true, "Truncate": true, "RoundDown": true}
)

// valueRounding returns how an expression rounds a decimal: a chain of
// decimal methods (x.RoundFloor(2).StringFixed(2) is down), or a call of a
// project helper whose body rounds so (depth levels deep).
func valueRounding(scope funcScope, expr ast.Expr, depth int) (roundingDirection, int64) {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return roundingNone, 0
	}
	if direction, places := chainRounding(scope.info, call); direction != roundingNone {
		return direction, places
	}
	if depth == 0 {
		return roundingNone, 0
	}
	decl, ok := scope.callee(call)
	if !ok || decl.decl.Body == nil {
		return roundingNone, 0
	}
	direction, places := roundingNone, int64(0)
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		inner := funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}
		d, p := valueRounding(inner, ret.Results[0], depth-1)
		if direction == roundingNone {
			direction, places = d, p
		} else if d != direction || p != places {
			direction = roundingNone
			return false
		}
		return true
	})
	return direction, places
}

// chainRounding reads a chain of decimal method calls: any rounding toward
// the floor makes it down, else a final StringFixed or Round makes it half up.
func chainRounding(info *types.Info, call *ast.CallExpr) (roundingDirection, int64) {
	direction, places := roundingNone, int64(0)
	for current := call; current != nil; {
		sel, ok := ast.Unparen(current.Fun).(*ast.SelectorExpr)
		if !ok {
			break
		}
		if len(current.Args) == 1 && (downMethods[sel.Sel.Name] || halfUpMethods[sel.Sel.Name]) && decimalMethodCall(info, current, sel.Sel.Name) {
			if p, ok := constantInt(info, current.Args[0]); ok {
				if downMethods[sel.Sel.Name] {
					direction, places = roundingDown, p
				} else if direction == roundingNone {
					direction, places = roundingHalfUp, p
				}
			}
		}
		next, _ := ast.Unparen(sel.X).(*ast.CallExpr)
		current = next
	}
	return direction, places
}

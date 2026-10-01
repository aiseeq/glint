package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewMoneyIntegerDivisionTruncatesRule())
}

// MoneyIntegerDivisionTruncatesRule detects an amount in base units divided
// by a power of ten as an integer and then made a decimal:
//
//	whole := new(big.Int).Div(valueWei, big.NewInt(1e18))
//	amount := decimal.NewFromBigInt(whole, 0)   // 1.5 ETH becomes 1
//
// big.Int division drops the remainder, so the fraction of a token is lost
// before the decimal that could hold it is made. Shift the exponent instead:
// decimal.NewFromBigInt(valueWei, -18). Integer rescaling whose quotient
// stays a big.Int (base units of another token) is not reported: there a
// remainder has nowhere to go.
//
// Without type information (a package that does not type-check) the rule
// reads what the syntax states for certain: new(big.Int), big.NewInt with a
// literal, the decimal package's constructors.
type MoneyIntegerDivisionTruncatesRule struct {
	*rules.BaseRule
}

// NewMoneyIntegerDivisionTruncatesRule creates the rule
func NewMoneyIntegerDivisionTruncatesRule() *MoneyIntegerDivisionTruncatesRule {
	return &MoneyIntegerDivisionTruncatesRule{BaseRule: rules.NewBaseRule(
		"money-integer-division-truncates",
		"patterns",
		"Detects a big.Int amount divided by a power of ten and then made a decimal — the integer division drops the fraction the decimal could hold",
		core.SeverityHigh,
	)}
}

// AnalyzeFile checks a file on its own, without type information.
func (r *MoneyIntegerDivisionTruncatesRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *MoneyIntegerDivisionTruncatesRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, with type information where its
// package has it.
func (r *MoneyIntegerDivisionTruncatesRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze reports the truncating divisions whose quotient becomes a
// decimal. info is nil for a file without type information.
func (r *MoneyIntegerDivisionTruncatesRule) analyze(file *core.FileContext, info *types.Info) []*core.Violation {
	if !file.IsGoFile() || file.IsTestFile() || file.GoAST == nil {
		return nil
	}
	bigAliases := helpers.PackageAliases(file.GoAST, `"math/big"`, "big")
	decimalAliases := helpers.PackageAliases(file.GoAST, `"`+shopspringDecimalPath+`"`, "decimal")
	if len(bigAliases) == 0 || len(decimalAliases) == 0 {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		d := &bigDivisionCheck{fn: fn, info: info, bigAliases: bigAliases, decimalAliases: decimalAliases}
		decimals := d.decimalConstructions()
		if len(decimals) == 0 {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !d.quotient(call) || !d.powerOfTen(call.Args[1], 2) || !d.reachesDecimal(call, decimals) {
				return true
			}
			line := file.LineFor(call)
			if file.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(file.RelPath, line, "Integer division of an amount by "+types.ExprString(call.Args[1])+" before it becomes a decimal — big.Int drops the remainder, and the fraction of a unit is lost")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Make the decimal from the base units and shift the exponent: decimal.NewFromBigInt(value, -decimals)")
			violations = append(violations, v)
			return true
		})
	}
	return violations
}

// bigDivisionCheck reads one function, with or without type information.
type bigDivisionCheck struct {
	fn             *ast.FuncDecl
	info           *types.Info // nil without type information
	bigAliases     map[string]bool
	decimalAliases map[string]bool
}

// variable identifies the variable an identifier names: its object, or
// without type information its name.
func (d *bigDivisionCheck) variable(ident *ast.Ident) any {
	if d.info == nil {
		return ident.Name
	}
	if obj := d.info.Uses[ident]; obj != nil {
		return obj
	}
	if obj := d.info.Defs[ident]; obj != nil {
		return obj
	}
	return nil
}

// value returns the expression a local variable was defined with.
func (d *bigDivisionCheck) value(ident *ast.Ident) ast.Expr {
	if d.info != nil {
		return definingValue(d.fn, d.info, ident)
	}
	var value ast.Expr
	ast.Inspect(d.fn.Body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && assign.Tok == token.DEFINE && len(assign.Lhs) == len(assign.Rhs) && value == nil {
			for i, lhs := range assign.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == ident.Name {
					value = assign.Rhs[i]
				}
			}
		}
		return value == nil
	})
	return value
}

// packageCall reports a call of the named package-level function (any name
// when name is empty) of math/big (inBig) or of decimal.
func (d *bigDivisionCheck) packageCall(expr ast.Expr, inBig bool, name string) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (name != "" && sel.Sel.Name != name) {
		return false
	}
	path, aliases := shopspringDecimalPath, d.decimalAliases
	if inBig {
		path, aliases = "math/big", d.bigAliases
	}
	if d.info == nil {
		pkg, ok := sel.X.(*ast.Ident)
		return ok && aliases[pkg.Name]
	}
	callee, ok := d.info.Uses[sel.Sel].(*types.Func)
	if !ok || callee.Pkg() == nil || callee.Pkg().Path() != path {
		return false
	}
	sig, ok := callee.Type().(*types.Signature)
	return ok && sig.Recv() == nil
}

// bigInt reports a *big.Int value; without type information only
// new(big.Int), big.NewInt(…) and a variable defined with one of them.
func (d *bigDivisionCheck) bigInt(expr ast.Expr) bool {
	if d.info != nil {
		return bigIntType(d.info.TypeOf(expr))
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		if builtin, ok := e.Fun.(*ast.Ident); ok && builtin.Name == "new" && len(e.Args) == 1 {
			sel, ok := e.Args[0].(*ast.SelectorExpr)
			if !ok {
				return false
			}
			pkg := identOf(sel.X)
			return pkg != nil && d.bigAliases[pkg.Name] && sel.Sel.Name == "Int"
		}
		return d.packageCall(e, true, "NewInt")
	case *ast.Ident:
		value := d.value(e)
		return value != nil && d.bigInt(value)
	}
	return false
}

// quotient reports z.Div(x, y) or z.Quo(x, y) of *big.Int.
func (d *bigDivisionCheck) quotient(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Div" && sel.Sel.Name != "Quo") || len(call.Args) != 2 {
		return false
	}
	return d.bigInt(sel.X)
}

func bigIntType(t types.Type) bool {
	named := namedOf(t)
	return named != nil && named.Obj().Pkg().Path() == "math/big" && named.Obj().Name() == "Int"
}

// constantOf returns the constant value of an expression.
func (d *bigDivisionCheck) constantOf(expr ast.Expr) constant.Value {
	if d.info != nil {
		return d.info.Types[expr].Value
	}
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	if !ok {
		return nil
	}
	return constant.ToInt(constant.MakeFromLiteral(lit.Value, lit.Kind, 0))
}

// powerOfTen reports a divisor that is ten to some power: big.NewInt(1e18),
// new(big.Int).Exp(big.NewInt(10), n, nil), or a local variable holding one.
func (d *bigDivisionCheck) powerOfTen(expr ast.Expr, depth int) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if depth == 0 {
			return false
		}
		value := d.value(e)
		return value != nil && d.powerOfTen(value, depth-1)
	case *ast.CallExpr:
		if len(e.Args) == 0 {
			return false
		}
		if d.packageCall(e, true, "NewInt") {
			return tenToPower(d.constantOf(e.Args[0]), false)
		}
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Exp" || !d.bigInt(sel.X) || !d.packageCall(e.Args[0], true, "NewInt") {
			return false
		}
		base, ok := ast.Unparen(e.Args[0]).(*ast.CallExpr)
		return ok && len(base.Args) == 1 && tenToPower(d.constantOf(base.Args[0]), true)
	}
	return false
}

// tenToPower reports a constant 10, 100, 1000, …; exactlyTen asks for 10
// itself, the base of an Exp.
func tenToPower(value constant.Value, exactlyTen bool) bool {
	if value == nil || value.Kind() != constant.Int {
		return false
	}
	text := value.ExactString()
	if exactlyTen {
		return text == "10"
	}
	return len(text) > 1 && text[0] == '1' && strings.Trim(text[1:], "0") == ""
}

// decimalConstructions returns the calls of decimal's constructors.
func (d *bigDivisionCheck) decimalConstructions() []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(d.fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !d.packageCall(call, false, "") {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (strings.HasPrefix(sel.Sel.Name, "New") || strings.HasPrefix(sel.Sel.Name, "Require")) {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

// reachesDecimal reports a quotient that an argument of a decimal
// constructor holds: the division itself, or the variable it was stored in
// (q := new(big.Int).Div(...), or z.Div(...) on z).
func (d *bigDivisionCheck) reachesDecimal(division *ast.CallExpr, decimals []*ast.CallExpr) bool {
	holders := d.quotientHolders(division)
	for _, construction := range decimals {
		found := false
		for _, arg := range construction.Args {
			ast.Inspect(arg, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					found = found || x == division
				case *ast.Ident:
					if v := d.variable(x); v != nil {
						found = found || holders[v]
					}
				}
				return !found
			})
		}
		if found {
			return true
		}
	}
	return false
}

// quotientHolders returns the variables that hold the quotient of division.
func (d *bigDivisionCheck) quotientHolders(division *ast.CallExpr) map[any]bool {
	holders := make(map[any]bool)
	if sel, ok := division.Fun.(*ast.SelectorExpr); ok {
		if receiver, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
			if v := d.variable(receiver); v != nil {
				holders[v] = true
			}
		}
	}
	ast.Inspect(d.fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			if ident, ok := assign.Lhs[i].(*ast.Ident); ok && ast.Unparen(rhs) == division {
				if v := d.variable(ident); v != nil {
					holders[v] = true
				}
			}
		}
		return true
	})
	return holders
}

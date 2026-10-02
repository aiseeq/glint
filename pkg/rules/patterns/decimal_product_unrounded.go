package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDecimalProductUnroundedRule())
}

// decimalRounders are the decimal methods that bound a value's digits.
var decimalRounders = map[string]bool{
	"Round": true, "RoundBank": true, "RoundCash": true, "RoundCeil": true, "RoundFloor": true,
	"RoundUp": true, "RoundDown": true, "Truncate": true, "StringFixed": true,
}

// decimalIntConstructors build a decimal from an integer: a factor of a few
// digits that does not make a product grow.
var decimalIntConstructors = map[string]bool{"NewFromInt": true, "NewFromInt32": true, "NewFromUint64": true}

// NewDecimalProductUnroundedRule creates decimal-product-unrounded: a decimal
// product carried through a loop without rounding keeps every digit of every
// factor, so its mantissa grows by a quotient's 16 digits per step — dozens
// of steps make it hundreds of digits long, and every later operation on it
// (Pow above all) slows to seconds:
//
//	growth := one
//	for _, s := range steps {
//	    growth = growth.Mul(s.End.Div(s.Start))   // never rounded
//	}
func NewDecimalProductUnroundedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"decimal-product-unrounded",
			"patterns",
			"Detects a decimal product carried through a loop without rounding — its digits grow with every factor and every operation on it slows down",
			core.SeverityMedium,
		),
		suggestion: "Round the running product in the loop to the precision the result needs (acc = acc.Mul(x).Round(18))",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		reported := make(map[types.Object]bool)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			var body *ast.BlockStmt
			switch loop := n.(type) {
			case *ast.RangeStmt:
				body = loop.Body
			case *ast.ForStmt:
				body = loop.Body
			default:
				return true
			}
			for _, product := range unroundedProducts(scope.info, fn.Body, n, body) {
				acc, assign := product.acc, product.assign
				if !reported[acc] {
					reported[acc] = true
					findings = append(findings, funcFinding{node: assign, message: "The decimal product " + acc.Name() + " is carried through the loop without rounding — its digits grow with every factor"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// loopProduct is an `acc = acc.Mul(x)` statement and its accumulator.
type loopProduct struct {
	acc    types.Object
	assign *ast.AssignStmt
}

// unroundedProducts returns the `acc = acc.Mul(x)` statements of a loop body
// whose accumulator, declared before the loop, is never rounded in it.
func unroundedProducts(info *types.Info, fnBody *ast.BlockStmt, loop ast.Node, body *ast.BlockStmt) []loopProduct {
	var products []loopProduct
	rounded := make(map[types.Object]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		acc := info.ObjectOf(ident)
		if acc == nil || acc.Pos() >= loop.Pos() || !isShopspringDecimalType(acc.Type()) {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if decimalRounders[sel.Sel.Name] {
			rounded[acc] = true
			return true
		}
		receiver, ok := ast.Unparen(sel.X).(*ast.Ident)
		if ok && sel.Sel.Name == "Mul" && info.ObjectOf(receiver) == acc && len(call.Args) == 1 && !isIntDecimal(info, fnBody, call.Args[0]) {
			products = append(products, loopProduct{acc: acc, assign: assign})
		}
		return true
	})
	var unrounded []loopProduct
	for _, product := range products {
		if !rounded[product.acc] {
			unrounded = append(unrounded, product)
		}
	}
	return unrounded
}

// isIntDecimal reports a decimal built from an integer: decimal.NewFromInt(2),
// or a local the function defines as one (ten := decimal.NewFromInt(10)).
func isIntDecimal(info *types.Info, fnBody *ast.BlockStmt, expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		fn := staticFunc(info, e)
		return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == shopspringDecimalPath && decimalIntConstructors[fn.Name()]
	case *ast.Ident:
		obj := info.ObjectOf(e)
		found := false
		ast.Inspect(fnBody, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || found || assign.Tok != token.DEFINE || len(assign.Lhs) != len(assign.Rhs) {
				return !found
			}
			for i, lhs := range assign.Lhs {
				if ident, isIdent := lhs.(*ast.Ident); isIdent && info.Defs[ident] == obj {
					found = isIntDecimal(info, fnBody, assign.Rhs[i])
				}
			}
			return !found
		})
		return found
	}
	return false
}

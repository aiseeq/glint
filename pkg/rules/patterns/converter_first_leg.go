package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewConverterKeepsFirstLegRule())
}

// NewConverterKeepsFirstLegRule creates converter-keeps-first-leg: a converter
// that returns one record and fills its amount from the first element of a
// list of movements that matches the owner, then breaks, keeps one leg of a
// transaction that moved several coins for that owner:
//
//	for _, c := range b.Changes {
//	    if c.Owner == wallet {
//	        amount = c.Amount
//	        coin = c.Coin
//	        break                     // a swap's second coin is lost
//	    }
//	}
//	return &Tx{Coin: coin, Amount: amount}
func NewConverterKeepsFirstLegRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"converter-keeps-first-leg",
			"patterns",
			"Detects a converter returning one record that takes the amount of the first matching movement and breaks — the other movements of the same owner are lost",
			core.SeverityMedium,
		),
		suggestion: "Return one record per matching movement, or sum the movements, instead of keeping the first",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if !returnsOneRecord(scope.info, fn) {
			return nil
		}
		params := map[types.Object]bool{}
		for _, field := range fn.Type.Params.List {
			for _, name := range field.Names {
				params[scope.info.Defs[name]] = true
			}
		}
		var findings []funcFinding
		for _, stmt := range fn.Body.List {
			loop, ok := stmt.(*ast.RangeStmt)
			if ok && takesFirstLeg(scope.info, loop, params) {
				findings = append(findings, funcFinding{node: loop, message: "The converter keeps the amount of the first matching movement and breaks — the other movements of the same owner are lost from the one record it returns"})
			}
		}
		return findings
	}
	return r
}

// returnsOneRecord reports a function whose result is a single pointer to a
// struct, with or without an error.
func returnsOneRecord(info *types.Info, fn *ast.FuncDecl) bool {
	results := fn.Type.Results
	if results == nil || results.NumFields() == 0 || results.NumFields() > 2 {
		return false
	}
	first := info.TypeOf(results.List[0].Type)
	if _, ok := types.Unalias(first).(*types.Pointer); !ok || structUnder(first) == nil {
		return false
	}
	return results.NumFields() == 1 || implementsError(info.TypeOf(results.List[len(results.List)-1].Type))
}

// takesFirstLeg reports a range over a parameter's list whose body is one if
// comparing the element with a parameter, assigning two or more variables of
// the function (one an amount) and breaking.
func takesFirstLeg(info *types.Info, loop *ast.RangeStmt, params map[types.Object]bool) bool {
	value, ok := loop.Value.(*ast.Ident)
	if !ok || !rootedInParam(info, loop.X, params) || len(loop.Body.List) != 1 {
		return false
	}
	element, ok := info.ObjectOf(value).(*types.Var)
	if !ok {
		return false
	}
	check, ok := loop.Body.List[0].(*ast.IfStmt)
	if !ok || check.Else != nil || len(check.Body.List) == 0 {
		return false
	}
	cond, ok := check.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.EQL || !comparesWithParam(info, cond, element, params) {
		return false
	}
	if last, isBranch := check.Body.List[len(check.Body.List)-1].(*ast.BranchStmt); !isBranch || last.Tok != token.BREAK {
		return false
	}
	assigned := map[types.Object]bool{}
	amount := false
	ast.Inspect(check.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN {
			return true
		}
		for _, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			obj := info.ObjectOf(ident)
			if obj == nil || obj.Pos() >= loop.Pos() {
				continue
			}
			assigned[obj] = true
			amount = amount || isAmountVar(obj)
		}
		return true
	})
	return len(assigned) >= 2 && amount
}

// comparesWithParam reports `element... == param...` in either order.
func comparesWithParam(info *types.Info, cond *ast.BinaryExpr, element *types.Var, params map[types.Object]bool) bool {
	if mentionsVar(info, cond.X, element) && rootedInParam(info, cond.Y, params) {
		return true
	}
	return mentionsVar(info, cond.Y, element) && rootedInParam(info, cond.X, params)
}

// isAmountVar reports a decimal variable or one whose name says amount.
func isAmountVar(obj types.Object) bool {
	if isShopspringDecimalType(obj.Type()) {
		return true
	}
	if st := structUnder(obj.Type()); st != nil {
		for i := 0; i < st.NumFields(); i++ {
			if st.Field(i).Embedded() && isShopspringDecimalType(st.Field(i).Type()) {
				return true
			}
		}
	}
	for _, word := range helpers.IdentifierWords(obj.Name()) {
		if word == "amount" {
			return true
		}
	}
	return false
}

// rootedInParam reports an expression reading a parameter (b.Changes, wallet).
func rootedInParam(info *types.Info, expr ast.Expr, params map[types.Object]bool) bool {
	for {
		switch e := ast.Unparen(expr).(type) {
		case *ast.Ident:
			return params[info.ObjectOf(e)]
		case *ast.SelectorExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		default:
			return false
		}
	}
}

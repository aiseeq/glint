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
	rules.Register(NewValuationZeroWhenNoCaseMatchesRule())
}

// valuationWords name a value in money: a price or a valuation in a currency.
var valuationWords = wordSet("usd", "price", "value", "valuation", "fiat", "eur", "rub")

// NewValuationZeroWhenNoCaseMatchesRule creates
// valuation-zero-when-no-case-matches: a valuation that starts at zero and is
// set only in the cases of a switch with no default is zero for every asset
// the cases do not name, and that zero goes on as if it were a price:
//
//	usdValue := decimal.Zero
//	switch {
//	case b.Kind == "native": usdValue = b.Amount.Mul(nativePrice)
//	case b.Symbol == "USDC": usdValue = b.Amount
//	}                                   // any other token is worth $0
//	total = total.Add(usdValue)
func NewValuationZeroWhenNoCaseMatchesRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"valuation-zero-when-no-case-matches",
			"patterns",
			"Detects a valuation set only in the cases of a switch with no default — an asset no case names is valued at zero and silently drops out of totals",
			core.SeverityMedium,
		),
		suggestion: "Add a default that prices the rest (or fails, or marks the value unknown) instead of leaving it at zero",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		// One report per switch: the valuations it sets share one fix.
		reported := make(map[*ast.SwitchStmt]bool)
		forEachOwnStatementList(fn.Body, func(list []ast.Stmt) {
			for i, stmt := range list {
				v := zeroValuation(scope.info, stmt)
				if v == nil {
					continue
				}
				if sw := setOnlyInCases(scope.info, list[i+1:], v); sw != nil && !reported[sw] {
					reported[sw] = true
					findings = append(findings, funcFinding{node: stmt, message: "The valuation " + v.Name() + " is set only in the cases of a switch with no default — an asset no case names is worth zero"})
				}
			}
		})
		return findings
	}
	return r
}

// zeroValuation returns the variable a statement declares as a zero decimal
// valuation (usdValue := decimal.Zero).
func zeroValuation(info *types.Info, stmt ast.Stmt) *types.Var {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return nil
	}
	ident, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return nil
	}
	v, ok := info.ObjectOf(ident).(*types.Var)
	if !ok || !isShopspringDecimalType(v.Type()) || !isDecimalZero(info, assign.Rhs[0]) {
		return nil
	}
	for _, word := range helpers.IdentifierWords(v.Name()) {
		if valuationWords[word] {
			return v
		}
	}
	return nil
}

// isDecimalZero reports decimal.Zero or decimal.NewFromInt(0).
func isDecimalZero(info *types.Info, expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		obj := info.ObjectOf(e.Sel)
		return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == shopspringDecimalPath && obj.Name() == "Zero"
	case *ast.CallExpr:
		fn := staticFunc(info, e)
		if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != shopspringDecimalPath || len(e.Args) != 1 {
			return false
		}
		lit, ok := e.Args[0].(*ast.BasicLit)
		return ok && lit.Value == "0"
	}
	return false
}

// setOnlyInCases returns the switch with no default in whose clauses (at
// least two) the rest of the list assigns the variable, when it is assigned
// nowhere else there and read after that switch.
func setOnlyInCases(info *types.Info, rest []ast.Stmt, v *types.Var) *ast.SwitchStmt {
	for i, stmt := range rest {
		sw, ok := stmt.(*ast.SwitchStmt)
		if !ok {
			if assignsVar(info, stmt, v) {
				return nil
			}
			continue
		}
		assigned := 0
		for _, clause := range sw.Body.List {
			cc, ok := clause.(*ast.CaseClause)
			if !ok || cc.List == nil {
				return nil
			}
			if assignsVar(info, &ast.BlockStmt{List: cc.Body}, v) {
				assigned++
			}
		}
		if assigned < 2 {
			return nil
		}
		read := false
		for _, after := range rest[i+1:] {
			if assignsVar(info, after, v) {
				return nil
			}
			read = read || mentionsVar(info, after, v)
		}
		if !read {
			return nil
		}
		return sw
	}
	return nil
}

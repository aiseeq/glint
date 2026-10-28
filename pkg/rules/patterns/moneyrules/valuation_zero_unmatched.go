package moneyrules

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewValuationZeroWhenNoCaseMatchesRule())
}

// valuationWords name a value in money: a price or a valuation in a currency.
var valuationWords = patternkit.WordSet("usd", "price", "value", "valuation", "fiat", "eur", "rub")

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
func NewValuationZeroWhenNoCaseMatchesRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"valuation-zero-when-no-case-matches",
			"patterns",
			"Detects a valuation set only in the cases of a switch with no default — an asset no case names is valued at zero and silently drops out of totals",
			core.SeverityMedium,
		),
		Suggestion: "Add a default that prices the rest (or fails, or marks the value unknown) instead of leaving it at zero",
	}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		var findings []patternkit.FuncFinding
		// One report per switch: the valuations it sets share one fix.
		reported := make(map[*ast.SwitchStmt]bool)
		patternkit.ForEachOwnStatementList(fn.Body, func(list []ast.Stmt) {
			for i, stmt := range list {
				v := zeroValuation(scope.Info, stmt)
				if v == nil {
					continue
				}
				if sw := setOnlyInCases(scope.Info, list[i+1:], v); sw != nil && !reported[sw] {
					reported[sw] = true
					findings = append(findings, patternkit.FuncFinding{Node: stmt, Message: "The valuation " + v.Name() + " is set only in the cases of a switch with no default — an asset no case names is worth zero"})
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
	if !ok || !isShopspringDecimalType(v.Type()) || !patternkit.IsDecimalZero(info, assign.Rhs[0]) {
		return nil
	}
	for _, word := range helpers.IdentifierWords(v.Name()) {
		if valuationWords[word] {
			return v
		}
	}
	return nil
}

// setOnlyInCases returns the switch with no default in whose clauses (at
// least two) the rest of the list assigns the variable, when it is assigned
// nowhere else there and read after that switch.
func setOnlyInCases(info *types.Info, rest []ast.Stmt, v *types.Var) *ast.SwitchStmt {
	for i, stmt := range rest {
		sw, ok := stmt.(*ast.SwitchStmt)
		if !ok {
			if patternkit.AssignsVar(info, stmt, v) {
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
			if patternkit.AssignsVar(info, &ast.BlockStmt{List: cc.Body}, v) {
				assigned++
			}
		}
		if assigned < 2 {
			return nil
		}
		read := false
		for _, after := range rest[i+1:] {
			if patternkit.AssignsVar(info, after, v) {
				return nil
			}
			read = read || patternkit.MentionsVar(info, after, v)
		}
		if !read {
			return nil
		}
		return sw
	}
	return nil
}

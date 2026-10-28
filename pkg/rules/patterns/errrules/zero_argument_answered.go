package errrules

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewZeroArgumentAnsweredByCalleeRule())
}

// NewZeroArgumentAnsweredByCalleeRule creates
// zero-argument-answered-by-callee: a zero passed for a parameter that the
// callee returns as the answer of one of its cases makes that case answer
// zero every time:
//
//	func basis(kind string, assets, committed, called decimal.Decimal) decimal.Decimal {
//	    switch kind { case "committed": return committed; ... }
//	}
//	b := basis(fs.Kind, assets, decimal.Zero, decimal.Zero)   // fees on committed capital are always 0
//
// The case is chosen by another argument, so the caller cannot know the
// placeholder is never used. A parameter returned for a nil check of another
// (valueOr(v, decimal.Zero)) is a default and is not reported.
func NewZeroArgumentAnsweredByCalleeRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"zero-argument-answered-by-callee",
			"patterns",
			"Detects a zero placeholder passed for a parameter the callee returns as the answer of a case — that case always answers zero",
			core.SeverityMedium,
		),
		Suggestion: "Compute the value before the call and pass it, or split the callee so the case that needs it cannot be chosen without it",
	}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		var findings []patternkit.FuncFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := scope.Callee(call)
			if !ok {
				return true
			}
			params := patternkit.ParamObjects(callee)
			for i, arg := range call.Args {
				if i < len(params) && isZeroPlaceholder(scope.Info, arg) && answeredByCase(callee, params, params[i]) {
					findings = append(findings, patternkit.FuncFinding{Node: call, Message: "A zero is passed for " + params[i].Name() + ", which the callee returns as the answer of a case chosen by another argument — that case always answers zero"})
					break
				}
			}
			return true
		})
		return findings
	}
	return r
}

// isZeroPlaceholder reports a zero value written out as an argument:
// decimal.Zero, a call of a niladic *Zero* constructor, decimal.NewFromInt(0)
// or a 0 literal.
func isZeroPlaceholder(info *types.Info, expr ast.Expr) bool {
	if patternkit.IsDecimalZero(info, expr) {
		return true
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		return len(e.Args) == 0 && strings.Contains(helpers.CalleeName(e), "Zero")
	case *ast.BasicLit:
		return (e.Kind == token.INT || e.Kind == token.FLOAT) && strings.Trim(e.Value, "0.") == ""
	}
	return false
}

// answeredByCase reports a parameter the callee returns as is from a case of
// a switch that another parameter decides.
func answeredByCase(fn patternkit.TypedFuncDecl, params []*types.Var, param *types.Var) bool {
	if param == nil {
		return false
	}
	others := func(node ast.Node) bool {
		for _, p := range params {
			if p != nil && p != param && patternkit.MentionsVar(fn.Info, node, p) {
				return true
			}
		}
		return false
	}
	found := false
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || found {
			return !found
		}
		decided := sw.Tag != nil && others(sw.Tag)
		for _, clause := range sw.Body.List {
			cc, ok := clause.(*ast.CaseClause)
			if !ok {
				continue
			}
			chosen := decided
			for _, expr := range cc.List {
				chosen = chosen || (sw.Tag == nil && others(expr))
			}
			if chosen && returnsVarAsIs(fn.Info, cc.Body, param) {
				found = true
			}
		}
		return !found
	})
	return found
}

// returnsVarAsIs reports a statement list ending in `return v`.
func returnsVarAsIs(info *types.Info, body []ast.Stmt, v *types.Var) bool {
	if len(body) == 0 {
		return false
	}
	ret, ok := body[len(body)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) == 0 {
		return false
	}
	ident, ok := ast.Unparen(ret.Results[0]).(*ast.Ident)
	return ok && info.ObjectOf(ident) == v
}

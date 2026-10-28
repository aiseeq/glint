package frontendrules

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// checkGoLookupMissLiterals reports a money variable that a lookup or a
// parse produced and the branch for its failure overwrote with a made-up
// non-zero number:
//
//	rate, ok := rates[pair]
//	if !ok {
//	    rate = decimal.NewFromFloat(1.0) // the quote goes on at 1:1
//	}
//
// The failure is the lookup's own result (ok, err) or the value read back
// (rate.IsZero()). A branch that leaves the flow is a refusal, not a default.
func (r *DefaultInventsDomainValueRule) checkGoLookupMissLiterals(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i := 1; i < len(block.List); i++ {
			ifStmt, ok := block.List[i].(*ast.IfStmt)
			if !ok || ifStmt.Else != nil || ifStmt.Init != nil || patternkit.BlockLeaves(ifStmt.Body) {
				continue
			}
			produced := patternkit.LookupResults(block.List[i-1])
			if produced == nil || !patternkit.MentionsSome(ifStmt.Cond, produced) {
				continue
			}
			for _, stmt := range ifStmt.Body.List {
				assign, ok := stmt.(*ast.AssignStmt)
				if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
					continue
				}
				target, ok := assign.Lhs[0].(*ast.Ident)
				if !ok || !produced[target.Name] || !patternkit.HasWordFrom(target.Name, patternkit.MoneyWords) || !patternkit.NonZeroNumber(assign.Rhs[0]) {
					continue
				}
				line := ctx.LineFor(assign)
				v := r.CreateViolation(ctx.RelPath, line,
					"Failed lookup or parse of "+target.Name+" replaced with a made-up number - the calculation goes on with a value the data does not have")
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Return an error or reject the item when the value is missing")
				violations = append(violations, v)
			}
		}
		return true
	})
	return violations
}

// checkGoCoalesceDefaults reports a first-non-empty helper whose fallback
// invents the value: a literal other than a placeholder word, or a company's
// field standing in for a person's or a sender's own field:
//
//	firstNonEmpty(tx.SenderIDExpireDate, "2030-12-31")
//	firstNonEmpty(tx.SenderFirstName, tx.SenderCorporateName)
//
// The provider receives an identity the sender never gave.
func (r *DefaultInventsDomainValueRule) checkGoCoalesceDefaults(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !patternkit.CoalesceHelpers[helpers.CalleeName(call)] || len(call.Args) < 2 || !patternkit.RecordField(call.Args[0]) {
			return true
		}
		message := ""
		switch last := call.Args[len(call.Args)-1].(type) {
		case *ast.BasicLit:
			if patternkit.InventedLiteral(last) {
				message = "Missing " + patternkit.ArgName(call.Args[0]) + " filled with the literal " + last.Value + " - the receiver gets a value nobody entered"
			}
		case *ast.SelectorExpr:
			if patternkit.SubstitutesCompanyField(call.Args[0], last) {
				message = "Missing " + patternkit.ArgName(call.Args[0]) + " filled from " + last.Sel.Name + " - a company's field passes for the sender's own"
			}
		}
		if message == "" {
			return true
		}
		line := ctx.LineFor(call)
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Require the field from the caller, or send it empty and let the receiver reject it")
		violations = append(violations, v)
		return true
	})
	return violations
}

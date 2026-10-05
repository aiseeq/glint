package patterns

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// moneyWords name a value a quote or a transfer is computed from.
var moneyWords = map[string]bool{
	"amount": true, "rate": true, "price": true, "fee": true, "total": true,
	"balance": true, "cost": true, "commission": true, "sum": true,
	"amounts": true, "rates": true, "prices": true, "fees": true, "totals": true, "costs": true,
}

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
			if !ok || ifStmt.Else != nil || ifStmt.Init != nil || blockLeaves(ifStmt.Body) {
				continue
			}
			produced := lookupResults(block.List[i-1])
			if produced == nil || !mentionsSome(ifStmt.Cond, produced) {
				continue
			}
			for _, stmt := range ifStmt.Body.List {
				assign, ok := stmt.(*ast.AssignStmt)
				if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
					continue
				}
				target, ok := assign.Lhs[0].(*ast.Ident)
				if !ok || !produced[target.Name] || !hasWordFrom(target.Name, moneyWords) || !nonZeroNumber(assign.Rhs[0]) {
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

// mentionsSome reports a condition that reads one of the names.
func mentionsSome(cond ast.Expr, names map[string]bool) bool {
	for name := range names {
		if mentions(cond, name) {
			return true
		}
	}
	return false
}

// lookupResults returns the variables an assignment of a call or a map index
// defines: `rate, ok := rates[pair]`, `amount, err = parse(s)`.
func lookupResults(stmt ast.Stmt) map[string]bool {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		return nil
	}
	// A map index, or a call answering a value with its ok or err: a plain
	// computation (int64(d.Hours())) is not a lookup that can miss.
	switch assign.Rhs[0].(type) {
	case *ast.IndexExpr:
	case *ast.CallExpr:
		if len(assign.Lhs) < 2 {
			return nil
		}
	default:
		return nil
	}
	names := make(map[string]bool)
	for _, lhs := range assign.Lhs {
		if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
			names[id.Name] = true
		}
	}
	return names
}

// nonZeroNumber reports a numeric literal other than zero, bare or wrapped in
// a decimal constructor: 100, decimal.NewFromFloat(1.0), decimal.NewFromInt(1).
func nonZeroNumber(expr ast.Expr) bool {
	if call, ok := expr.(*ast.CallExpr); ok {
		switch callName(call) {
		case "NewFromFloat", "NewFromInt", "NewFromInt32", "NewFromString", "RequireFromString":
		default:
			return false
		}
		if len(call.Args) != 1 {
			return false
		}
		expr = call.Args[0]
	}
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return false
	}
	text, isString := stringLiteral(lit)
	if !isString {
		if lit.Kind != token.INT && lit.Kind != token.FLOAT {
			return false
		}
		text = lit.Value
	}
	value, err := strconv.ParseFloat(text, 64)
	return err == nil && value != 0
}

// coalesceHelpers are the first-non-empty helpers a request builder uses.
var coalesceHelpers = map[string]bool{
	"firstNonEmpty": true, "coalesce": true, "valueOr": true, "orDefault": true,
	"defaultIfEmpty": true, "firstNotEmpty": true, "nonEmpty": true,
}

// organizationWords name a company's field.
var organizationWords = map[string]bool{
	"corporate": true, "company": true, "business": true, "organization": true,
	"organisation": true, "legal": true, "registration": true, "registered": true,
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
		if !ok || !coalesceHelpers[callName(call)] || len(call.Args) < 2 || !recordField(call.Args[0]) {
			return true
		}
		message := ""
		switch last := call.Args[len(call.Args)-1].(type) {
		case *ast.BasicLit:
			if inventedLiteral(last) {
				message = "Missing " + argName(call.Args[0]) + " filled with the literal " + last.Value + " - the receiver gets a value nobody entered"
			}
		case *ast.SelectorExpr:
			if substitutesCompanyField(call.Args[0], last) {
				message = "Missing " + argName(call.Args[0]) + " filled from " + last.Sel.Name + " - a company's field passes for the sender's own"
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

// configNames are the names of configuration holders and of the settings a
// default is the documented answer for.
var configNames = map[string]bool{"cfg": true, "config": true, "conf": true, "settings": true, "opts": true, "options": true, "env": true}

// recordField reports a field of a data record (tx.SenderIDExpireDate): an
// environment variable or a setting falling back to a default is
// configuration, which config-value-fallback looks at.
func recordField(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if base, ok := sel.X.(*ast.Ident); ok && configNames[strings.ToLower(base.Name)] {
		return false
	}
	for _, word := range helpers.IdentifierWords(sel.Sel.Name) {
		switch strings.ToLower(word) {
		case "url", "endpoint", "host", "addr", "address", "path", "dir", "port", "timeout":
			return false
		}
	}
	return true
}

// argName renders the first argument of the helper for the message.
func argName(expr ast.Expr) string {
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return "value"
}

// inventedLiteral reports a non-empty string literal that is not a word for a
// missing value (N/A, unknown).
func inventedLiteral(lit *ast.BasicLit) bool {
	value, ok := stringLiteral(lit)
	if !ok || strings.TrimSpace(value) == "" {
		return false
	}
	return !jsMissingWord.MatchString(strings.TrimSpace(value))
}

// substitutesCompanyField reports a fallback field named for a company while
// the primary is not: SenderCorporateName for SenderFirstName.
func substitutesCompanyField(primary ast.Expr, fallback *ast.SelectorExpr) bool {
	sel, ok := primary.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return hasWordFrom(fallback.Sel.Name, organizationWords) && !hasWordFrom(sel.Sel.Name, organizationWords)
}

// hasWordFrom reports an identifier with one of the words in it.
func hasWordFrom(name string, words map[string]bool) bool {
	for _, word := range helpers.IdentifierWords(name) {
		if words[strings.ToLower(word)] {
			return true
		}
	}
	return false
}

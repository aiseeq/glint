package patternkit

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// MoneyWords name a value a quote or a transfer is computed from.
var MoneyWords = map[string]bool{
	"amount": true, "rate": true, "price": true, "fee": true, "total": true,
	"balance": true, "cost": true, "commission": true, "sum": true,
	"amounts": true, "rates": true, "prices": true, "fees": true, "totals": true, "costs": true,
}

// MentionsSome reports a condition that reads one of the names.
func MentionsSome(cond ast.Expr, names map[string]bool) bool {
	for name := range names {
		if Mentions(cond, name) {
			return true
		}
	}
	return false
}

// LookupResults returns the variables an assignment of a call or a map index
// defines: `rate, ok := rates[pair]`, `amount, err = parse(s)`.
func LookupResults(stmt ast.Stmt) map[string]bool {
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

// NonZeroNumber reports a numeric literal other than zero, bare or wrapped in
// a decimal constructor: 100, decimal.NewFromFloat(1.0), decimal.NewFromInt(1).
func NonZeroNumber(expr ast.Expr) bool {
	if call, ok := expr.(*ast.CallExpr); ok {
		switch helpers.CalleeName(call) {
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
	text, isString := helpers.StringLiteral(lit)
	if !isString {
		if lit.Kind != token.INT && lit.Kind != token.FLOAT {
			return false
		}
		text = lit.Value
	}
	value, err := strconv.ParseFloat(text, 64)
	return err == nil && value != 0
}

// CoalesceHelpers are the first-non-empty helpers a request builder uses.
var CoalesceHelpers = map[string]bool{
	"firstNonEmpty": true, "coalesce": true, "valueOr": true, "orDefault": true,
	"defaultIfEmpty": true, "firstNotEmpty": true, "nonEmpty": true,
}

// organizationWords name a company's field.
var organizationWords = map[string]bool{
	"corporate": true, "company": true, "business": true, "organization": true,
	"organisation": true, "legal": true, "registration": true, "registered": true,
}

// configNames are the names of configuration holders and of the settings a
// default is the documented answer for.
var configNames = map[string]bool{"cfg": true, "config": true, "conf": true, "settings": true, "opts": true, "options": true, "env": true}

// RecordField reports a field of a data record (tx.SenderIDExpireDate): an
// environment variable or a setting falling back to a default is
// configuration, which config-value-fallback looks at.
func RecordField(expr ast.Expr) bool {
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

// ArgName renders the first argument of the helper for the message.
func ArgName(expr ast.Expr) string {
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return "value"
}

// InventedLiteral reports a non-empty string literal that is not a word for a
// missing value (N/A, unknown).
func InventedLiteral(lit *ast.BasicLit) bool {
	value, ok := helpers.StringLiteral(lit)
	if !ok || strings.TrimSpace(value) == "" {
		return false
	}
	return !JsMissingWord.MatchString(strings.TrimSpace(value))
}

// SubstitutesCompanyField reports a fallback field named for a company while
// the primary is not: SenderCorporateName for SenderFirstName.
func SubstitutesCompanyField(primary ast.Expr, fallback *ast.SelectorExpr) bool {
	sel, ok := primary.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return HasWordFrom(fallback.Sel.Name, organizationWords) && !HasWordFrom(sel.Sel.Name, organizationWords)
}

// HasWordFrom reports an identifier with one of the words in it.
func HasWordFrom(name string, words map[string]bool) bool {
	for _, word := range helpers.IdentifierWords(name) {
		if words[strings.ToLower(word)] {
			return true
		}
	}
	return false
}

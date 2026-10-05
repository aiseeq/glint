package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewMoneySummedAcrossCurrenciesRule())
}

// MoneySummedAcrossCurrenciesRule detects a SUM of an amount over rows of a
// table that keeps a currency per row, in a query that neither groups by the
// currency nor fixes one:
//
//	SELECT COUNT(*), COALESCE(SUM(transfer_amount), 0) FROM transfers WHERE created_at >= $1
//	-- transfers.sender_currency
//
// Roubles and dollars add up to a number in no currency, and the dashboard
// shows it as the volume. GROUP BY the currency column, or a WHERE fixing
// one, keeps the sums apart.
type MoneySummedAcrossCurrenciesRule struct {
	*rules.BaseRule
}

// NewMoneySummedAcrossCurrenciesRule creates the rule
func NewMoneySummedAcrossCurrenciesRule() *MoneySummedAcrossCurrenciesRule {
	return &MoneySummedAcrossCurrenciesRule{BaseRule: rules.NewBaseRule(
		"money-summed-across-currencies",
		"patterns",
		"Detects SUM of an amount of a table with a currency column, in a query that neither groups by the currency nor fixes one — amounts in different currencies add up to a number in none",
		core.SeverityHigh,
	)}
}

// ReadsOtherFiles reports that the findings depend on the migrations' columns.
func (r *MoneySummedAcrossCurrenciesRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports the sums of a file's SQL that mix currencies.
func (r *MoneySummedAcrossCurrenciesRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	schema, ok := fileSchema(ctx, r.BaseRule)
	if !ok || schema == nil {
		return nil
	}
	var violations []*core.Violation
	reported := make(map[int]bool)
	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range ctx.GoAST.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && fn.Recv == nil {
			funcs[fn.Name.Name] = fn
		}
	}
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		violations = append(violations, r.functionSums(ctx, schema, fn, funcs, reported)...)
	}
	return violations
}

// functionSums reports the sums of a function's SQL that mix currencies.
func (r *MoneySummedAcrossCurrenciesRule) functionSums(ctx *core.FileContext, schema *sqlschema.Schema, fn *ast.FuncDecl, funcs map[string]*ast.FuncDecl, reported map[int]bool) []*core.Violation {
	var violations []*core.Violation
	for _, literal := range sqlLiterals(fn.Body) {
		sums := schema.MixedCurrencySums(literal.text)
		if len(sums) == 0 && literal.bare != "" {
			sums = schema.MixedCurrencySums(literal.bare)
		}
		for _, sum := range sums {
			// A WHERE joined in may fix the currency: the conditions the
			// function and the file's functions it calls write count.
			if literal.bare != "" && conditionsOn(fn, funcs, sum.Currency) {
				continue
			}
			line := literal.lineAt(ctx, sum.Offset)
			if reported[line] || ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			reported[line] = true
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"SUM("+sum.Column+") adds up rows of "+sum.Table+" in every "+strings.Join(sum.Currency, "/")+" — amounts in different currencies make a number in none",
				"GROUP BY "+sum.Currency[0]+" and show a total per currency, or fix the currency in the WHERE"))
		}
	}
	return violations
}

// conditionsOn reports a string literal of the function, or of a function of
// the file it calls, comparing one of the columns: currency = $1,
// sender_currency IN (...).
func conditionsOn(fn *ast.FuncDecl, funcs map[string]*ast.FuncDecl, columns []string) bool {
	quoted := make([]string, len(columns))
	for i, column := range columns {
		quoted[i] = regexp.QuoteMeta(column)
	}
	condition := regexp.MustCompile(`(?i)\b(?:` + strings.Join(quoted, "|") + `)\s*(?:=|\bIN\b)`)
	bodies := []ast.Node{fn.Body}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok && funcs[ident.Name] != nil {
				bodies = append(bodies, funcs[ident.Name].Body)
			}
		}
		return true
	})
	found := false
	for _, body := range bodies {
		ast.Inspect(body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && condition.MatchString(lit.Value) {
				found = true
			}
			return !found
		})
	}
	return found
}

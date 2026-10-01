package patterns

import (
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewMoneyZeroShownAsOtherFieldRule())
	rules.Register(NewCSVFormulaInjectionRule())
}

// MoneyZeroShownAsOtherFieldRule detects a money value that is used only when
// positive and otherwise replaced with another money value:
//
//	if (parseFloat(String(inv.currentValue)) > 0) {
//	  return parseFloat(String(inv.currentValue))
//	}
//	return invAmount // valuation not done yet
//
// A real zero (the investment lost everything) and a missing valuation both
// show as the invested amount: a loss reads as break-even. A missing value is
// shown as missing; a zero is shown as zero.
type MoneyZeroShownAsOtherFieldRule struct {
	*rules.BaseRule
}

// NewMoneyZeroShownAsOtherFieldRule creates the rule
func NewMoneyZeroShownAsOtherFieldRule() *MoneyZeroShownAsOtherFieldRule {
	return &MoneyZeroShownAsOtherFieldRule{BaseRule: rules.NewBaseRule(
		"money-zero-shown-as-other-field",
		"patterns",
		"Detects a money value used only when positive and otherwise replaced with another money value — a real zero shows as the other amount",
		core.SeverityMedium,
	)}
}

var (
	// jsPositiveThenReturn is `if (... x.f > 0) { return A } return B`.
	jsPositiveThenReturn = regexp.MustCompile(`\bif\s*\([^{};]*?\b[\w$]+\.(\w+)\)*\s*>\s*0\s*\)\s*\{?\s*return\s+([^;}\n]+?)[\s;]*\}?\s*return\s+([^;}\n]+)`)
	// jsPositiveTernary is `x.f > 0 ? A : B`.
	jsPositiveTernary = regexp.MustCompile(`\b[\w$]+\.(\w+)\)*\s*>\s*0\s*\?\s*([^:?\n]+?)\s*:\s*([\w$.()]+)`)
	jsMoneyValueWords = []string{"value", "amount", "balance", "price", "total", "worth", "valuation"}
)

// moneyWordIn reports an identifier word of the text that names money.
func moneyWordIn(text string) bool {
	for _, name := range jsIdentifierWord.FindAllString(text, -1) {
		if slices.ContainsFunc(helpers.IdentifierWords(name), func(w string) bool { return slices.Contains(jsMoneyValueWords, w) }) {
			return true
		}
	}
	return false
}

var jsIdentifierWord = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

// AnalyzeFile reports the positive-only money values.
func (r *MoneyZeroShownAsOtherFieldRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := newJSFlat(ctx)
	var violations []*core.Violation
	for _, re := range []*regexp.Regexp{jsPositiveThenReturn, jsPositiveTernary} {
		for _, m := range re.FindAllStringSubmatchIndex(f.code, -1) {
			field := f.code[m[2]:m[3]]
			used, other := f.code[m[4]:m[5]], f.code[m[6]:m[7]]
			if !moneyWordIn(field) || !strings.Contains(used, "."+field) ||
				strings.Contains(other, "."+field) || !moneyWordIn(other) {
				continue
			}
			violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
				"'"+field+"' is used only when above zero and replaced with another amount otherwise — a real zero or a missing value shows as that amount",
				"Show a zero as zero and a missing value as missing")
		}
	}
	return violations
}

// CSVFormulaInjectionRule detects a CSV export that quotes its cells but
// never neutralizes a leading =, +, - or @:
//
//	return str.includes(',') ? `"${str.replace(/"/g, '""')}"` : str
//
// A spreadsheet runs a cell starting with = as a formula: a user who puts
// =HYPERLINK(...) into a name field gets it executed on the admin's machine
// when the export is opened. Prefix such cells with a quote.
type CSVFormulaInjectionRule struct {
	*rules.BaseRule
}

// NewCSVFormulaInjectionRule creates the rule
func NewCSVFormulaInjectionRule() *CSVFormulaInjectionRule {
	return &CSVFormulaInjectionRule{BaseRule: rules.NewBaseRule(
		"csv-formula-injection",
		"security",
		"Detects a CSV export that escapes quotes but not a leading =, +, - or @ — a cell runs as a spreadsheet formula",
		core.SeverityHigh,
	)}
}

var (
	// jsCSVQuoteDoubling is the escaping of a CSV cell: " doubled.
	jsCSVQuoteDoubling = regexp.MustCompile(`\.\s*replace(?:All)?\s*\(\s*(?:/"/g|'"'|"\\"")\s*,\s*(?:'""'|"\\"\\""|` + "`\"\"`" + `)\s*\)`)
	// jsFormulaGuard is a check of a leading formula character.
	jsFormulaGuard = regexp.MustCompile(`\^\[[^\]\n]*[=+@]|startsWith\s*\(\s*['"][=+@-]|['"]=['"]\s*,\s*['"][+@-]['"]`)
)

// AnalyzeFile reports the CSV cell escapers of files without a formula guard.
func (r *CSVFormulaInjectionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := newJSFlat(ctx)
	if !jsCSVMention.MatchString(f.text) || jsFormulaGuard.MatchString(f.text) {
		return nil
	}
	var violations []*core.Violation
	for _, m := range jsCSVQuoteDoubling.FindAllStringIndex(f.text, -1) {
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
			"CSV cell is quoted but a leading =, +, - or @ is kept — the spreadsheet runs the cell as a formula",
			"Prefix a cell that starts with =, +, -, @, tab or CR with a single quote before quoting it")
	}
	return violations
}

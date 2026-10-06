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
	rules.Register(newTSRule("csv-formula-guard-mangles-negative-number",
		"Detects a CSV formula guard that quotes a cell starting with - or + with no exemption for numbers — a negative amount becomes text the spreadsheet does not sum",
		checkFormulaGuardNumbers))
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
// when the export is opened. Prefix such cells with a quote. A leading tab or
// carriage return starts a formula too (OWASP): a guard character class
// without them is reported, and so is a cell quoted for \n but not for \r,
// which breaks the row. In Go,
// encoding/csv quotes but never neutralizes: a row of a file writing it that
// takes a free-text field (a name, a description) as is is reported.
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
	// jsFormulaClass is the character class of a regexp formula guard,
	// ^[=+\-@]: = is in every guard and in no number pattern (^[+-]?\d).
	jsFormulaClass = regexp.MustCompile(`\^\[([^\]\n]*=[^\]\n]*)\]`)
	// jsQuotesOnNewline is a quoting condition that looks for \n in a cell.
	jsQuotesOnNewline = regexp.MustCompile(`\.includes\(\s*['"` + "`" + `]\\n['"` + "`" + `]\s*\)`)
	// jsQuotesOnCarriageReturn looks for \r in a cell: includes('\r') or a
	// class with \r in it that is not anchored at the start, as a guard is.
	jsQuotesOnCarriageReturn = regexp.MustCompile(`\.includes\(\s*['"` + "`" + `]\\r['"` + "`" + `]\s*\)|(?:^|[^^])\[[^\]\n]*\\r[^\]\n]*\]`)
)

// AnalyzeFile reports the CSV cell escapers of files without a formula guard.
func (r *CSVFormulaInjectionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if productionGoFile(ctx) {
		return r.analyzeGo(ctx)
	}
	if !productionFrontendFile(ctx) {
		return nil
	}
	f := newJSFlat(ctx)
	if !jsCSVMention.MatchString(f.text) {
		return nil
	}
	if jsFormulaGuard.MatchString(f.text) {
		return r.incompleteGuard(ctx, f)
	}
	var violations []*core.Violation
	for _, m := range jsCSVQuoteDoubling.FindAllStringIndex(f.text, -1) {
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
			"CSV cell is quoted but a leading =, +, - or @ is kept — the spreadsheet runs the cell as a formula",
			"Prefix a cell that starts with =, +, -, @, tab or CR with a single quote before quoting it")
	}
	return violations
}

// incompleteGuard reports the formula guard classes of a CSV file that leave
// out a leading tab or carriage return, and a quoting condition of a file that
// doubles quotes which looks for \n in a cell but never for \r.
func (r *CSVFormulaInjectionRule) incompleteGuard(ctx *core.FileContext, f jsFlat) []*core.Violation {
	var violations []*core.Violation
	for _, m := range jsFormulaClass.FindAllStringSubmatchIndex(f.text, -1) {
		class := f.text[m[2]:m[3]]
		if strings.Contains(class, `\t`) && strings.Contains(class, `\r`) {
			continue
		}
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
			"The formula guard leaves out a leading tab or carriage return — the spreadsheet still runs such a cell as a formula",
			"Add \\t and \\r to the leading characters the guard prefixes with a quote")
	}
	if !jsCSVQuoteDoubling.MatchString(f.text) || jsQuotesOnCarriageReturn.MatchString(f.text) {
		return violations
	}
	for _, m := range jsQuotesOnNewline.FindAllStringIndex(f.text, -1) {
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
			"The cell is quoted for \\n but not for \\r — a carriage return in an unquoted cell breaks the row",
			"Quote a cell that contains \\r as well as \\n, a comma or a quote")
	}
	return violations
}

var (
	// jsFormulaSignList is a list of formula characters with a sign in it:
	// ['=', '+', '-', '@'].
	jsFormulaSignList = regexp.MustCompile(`\[\s*['"]=['"]\s*,[^\]\n]*['"][-+]['"]`)
	// jsNumberExemption is a test that tells a number from a formula.
	jsNumberExemption = regexp.MustCompile(`\\d|isNaN\s*\(|isFinite\s*\(|Number\s*\(|parseFloat\s*\(`)
)

// checkFormulaGuardNumbers reports a formula guard whose characters include
// a sign in a function that never tells a number from a formula.
func checkFormulaGuardNumbers(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	if !jsCSVMention.MatchString(f.text) {
		return nil
	}
	var out []*core.Violation
	for _, m := range jsFormulaSignList.FindAllStringIndex(f.text, -1) {
		scope := f.text
		if fn, ok := f.enclosingFunction(m[0]); ok {
			if end, ok := f.closing(fn.brace); ok {
				scope = f.text[fn.brace:end]
			}
		}
		if jsNumberExemption.MatchString(scope) || jsNumberExemption.MatchString(fileConstants(f.text)) {
			continue
		}
		out = jsReport(out, r.BaseRule, ctx, f.line(m[0]),
			"The formula guard quotes a cell that starts with - or +, numbers included — a negative amount becomes text the spreadsheet does not sum",
			"Leave a plain decimal number (/^-?\\d+(\\.\\d+)?$/) unquoted, and quote the rest")
	}
	return out
}

// fileConstants returns the top-level const declarations of a file, where a
// number pattern used by the guard is defined.
func fileConstants(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "const ") || strings.HasPrefix(line, "export const ") {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

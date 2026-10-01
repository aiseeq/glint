package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewMoneyFormatBypassesFormatterRule())
}

// MoneyFormatBypassesFormatterRule detects an amount formatted on the spot in
// a frontend that has a shared money formatter:
//
//	export const formatters = { formatAmount: (amount, decimals = 2) => ... }  // shared/lib
//	...
//	{transaction.amount.toLocaleString()} USDC     // 1234.5 → "1,234.5"
//	`${Math.abs(op.amount).toFixed(2)}`
//
// The formatter fixes the decimals, the grouping and the rounding once; a
// screen that formats by hand shows 1,234.5 next to 1,234.50 on the
// neighbouring one, and toLocaleString() without options cuts the amount at
// three decimals in the viewer's locale. Reported are toFixed and
// toLocaleString (without a fraction-digits option) on a money value and a
// currency Intl.NumberFormat, in the files under the same top directory as a
// formatter (formatAmount, formatMoney, formatCurrency, formatUsd, ...) of a
// shared module (shared/, lib/, utils/, common/). The files declaring a
// formatter, log lines and ratios (balance / goal * 100) are left alone.
type MoneyFormatBypassesFormatterRule struct {
	*rules.BaseRule
	// formatters holds the files declaring a money formatter.
	formatters map[string]bool
	// scopes maps a top directory to the shared module declaring its
	// formatter, names to the formatter's name.
	scopes map[string]string
	names  map[string]string
}

// NewMoneyFormatBypassesFormatterRule creates the rule
func NewMoneyFormatBypassesFormatterRule() *MoneyFormatBypassesFormatterRule {
	return &MoneyFormatBypassesFormatterRule{BaseRule: rules.NewBaseRule(
		"money-format-bypasses-formatter",
		"patterns",
		"Detects an amount formatted on the spot (toFixed, toLocaleString, a currency Intl.NumberFormat) in a frontend that has a shared money formatter",
		core.SeverityMedium,
	)}
}

const moneyFormatterName = `(format(?i:amount|money|currency|usd|price|balance|fiat)[\w$]*)`

var (
	moneyFormatterDecls = []*regexp.Regexp{
		regexp.MustCompile(`\bfunction\s+` + moneyFormatterName + `\s*[(<]`),
		regexp.MustCompile(`\b(?:const|let|var)\s+` + moneyFormatterName + `\s*(?::[^=]*)?=\s*(?:async\s*)?(?:\(|function\b|[\w$]+\s*=>|useCallback\()`),
		regexp.MustCompile(`^\s*` + moneyFormatterName + `\s*:\s*(?:async\s*)?(?:\(|function\b|[\w$]+\s*=>)`),
		regexp.MustCompile(`^\s*(?:(?:public|private|protected|static|async|export)\s+)*` + moneyFormatterName + `\s*\([^)]*\)\s*(?::\s*[\w<>\[\]| ]+)?\{`),
	}
	onTheSpotFormat = regexp.MustCompile(`\.(toFixed|toLocaleString)\(`)
	sharedModule    = regexp.MustCompile(`(?i)/(?:shared|libs?|utils?|common|helpers?|formatters?|formatting)/`)
	logCall         = regexp.MustCompile(`\b(?:console|logger|log)\.\w+\(`)
)

// UseProjectFiles finds the money formatters of the root.
func (r *MoneyFormatBypassesFormatterRule) UseProjectFiles(files []*core.FileContext) {
	r.formatters = make(map[string]bool)
	r.scopes = make(map[string]string)
	r.names = make(map[string]string)
	for _, ctx := range files {
		if !frontendSource(ctx) {
			continue
		}
		for _, line := range helpers.FileJSCode(ctx) {
			if !strings.Contains(line, "format") {
				continue
			}
			for _, decl := range moneyFormatterDecls {
				m := decl.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				r.formatters[ctx.RelPath] = true
				if !sharedModule.MatchString("/" + ctx.RelPath) {
					break // a screen's own helper, not the project's formatter
				}
				scope := topDirectory(ctx.RelPath)
				if seen, ok := r.scopes[scope]; !ok || ctx.RelPath < seen {
					r.scopes[scope] = ctx.RelPath
					r.names[scope] = m[1]
				}
				break
			}
		}
	}
}

// ResetState drops the formatters of the previous root.
func (r *MoneyFormatBypassesFormatterRule) ResetState() {
	r.formatters = nil
	r.scopes = nil
	r.names = nil
}

// frontendSource reports a TS/JS source file of the product: not a test, not
// generated, not a dependency or a build output.
func frontendSource(ctx *core.FileContext) bool {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() || ctx.IsTestFile() || isE2EPath(ctx.RelPath) {
		return false
	}
	path := "/" + ctx.RelPath
	for _, dir := range []string{"/node_modules/", "/dist/", "/build/", "/.next/", "/out/"} {
		if strings.Contains(path, dir) {
			return false
		}
	}
	return !ctx.IsGenerated()
}

// topDirectory is the first directory of a relative path, "" for a file at
// the root.
func topDirectory(relPath string) string {
	if slash := strings.IndexByte(relPath, '/'); slash >= 0 {
		return relPath[:slash]
	}
	return ""
}

// AnalyzeFile reports the amounts a file formats by hand.
func (r *MoneyFormatBypassesFormatterRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	scope := topDirectory(ctx.RelPath)
	module, ok := r.scopes[scope]
	if !ok || r.formatters[ctx.RelPath] || !frontendSource(ctx) {
		return nil
	}
	formatter := r.names[scope] + " (" + module + ")"
	code, text := helpers.FileJSCode(ctx), helpers.FileJSText(ctx)
	var violations []*core.Violation
	for i, line := range code {
		if !strings.Contains(line, ".to") && !strings.Contains(line, "Intl.NumberFormat") {
			continue
		}
		if logCall.MatchString(line) || ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		what, found := handFormattedMoney(code, text, i)
		if !found {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1,
			"Amount formatted on the spot with "+what+" while the project formats money with "+formatter+" — decimals and grouping differ from the other screens")
		v.WithCode(strings.TrimSpace(ctx.Lines[i]))
		v.WithSuggestion("Format the amount with the shared formatter")
		violations = append(violations, v)
	}
	return violations
}

// handFormattedMoney returns the call that formats a money value on line i:
// toFixed or toLocaleString on a money value, or a currency NumberFormat.
func handFormattedMoney(code, text []string, i int) (string, bool) {
	line := code[i]
	for _, loc := range onTheSpotFormat.FindAllStringSubmatchIndex(line, -1) {
		start := jsReceiverStart(line, loc[0])
		receiver := text[i][start:loc[0]]
		// A quotient of money is a ratio or a share: a percentage, not an amount.
		if start == loc[0] || strings.Contains(line[start:loc[0]], "/") || !looksLikeMoney(receiver) {
			continue
		}
		method := line[loc[2]:loc[3]]
		if method == "toLocaleString" {
			end := matchingParenEnd(line, loc[1])
			if end < 0 || strings.Contains(text[i][loc[1]:end], "FractionDigits") {
				continue
			}
		}
		return method, true
	}
	if k := strings.Index(line, "Intl.NumberFormat("); k >= 0 {
		options := text[i][k:] + " " + strings.Join(text[i+1:min(i+5, len(text))], " ")
		if strings.Contains(options, "'currency'") || strings.Contains(options, `"currency"`) {
			return "Intl.NumberFormat", true
		}
	}
	return "", false
}

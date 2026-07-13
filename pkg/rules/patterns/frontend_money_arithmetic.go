package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewFrontendMoneyArithmeticRule())
}

// defaultMoneyFields are field-name fragments treated as money values.
const defaultMoneyFields = "amount|balance|fee|fees|price|profit|yield|deposit|withdrawal|invested|debit|credit"

// FrontendMoneyArithmeticRule detects client-side arithmetic over money
// values in TS/JS:
//
//	investedAmount += parseFloat(inv.amount)
//	pending.reduce((sum, w) => sum + parseFloat(w.amount || '0'), 0)
//
// Financial aggregates must be computed on the backend (single canonical
// calculation logic); parseFloat over decimal strings silently loses
// precision, and duplicated client math diverges from the server.
//
// Not flagged: pure formatting (formatAmount(parseFloat(x))), comparisons,
// non-money numerics, tests.
type FrontendMoneyArithmeticRule struct {
	*rules.BaseRule
	parseCall     *regexp.Regexp
	moneyField    *regexp.Regexp
	reduceRawSum  *regexp.Regexp
	accumulate    *regexp.Regexp
	reduceMarker  string
	arithmeticOps string
}

// NewFrontendMoneyArithmeticRule creates the rule
func NewFrontendMoneyArithmeticRule() *FrontendMoneyArithmeticRule {
	r := &FrontendMoneyArithmeticRule{
		BaseRule: rules.NewBaseRule(
			"frontend-money-arithmetic",
			"patterns",
			"Detects client-side arithmetic over money values (must come from backend)",
			core.SeverityHigh,
		),
		parseCall:     regexp.MustCompile(`\b(?:parseFloat|Number)\s*\(`),
		accumulate:    regexp.MustCompile(`\b([\w$]+)\s*[+\-]=\s*(.+)$`),
		reduceMarker:  ".reduce(",
		arithmeticOps: "+-*/",
	}
	r.setMoneyFields(defaultMoneyFields)
	return r
}

// Configure reads the optional money_fields setting ("a|b|c" fragments).
func (r *FrontendMoneyArithmeticRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.setMoneyFields(r.GetStringSetting("money_fields", defaultMoneyFields))
	return nil
}

func (r *FrontendMoneyArithmeticRule) setMoneyFields(fields string) {
	r.moneyField = regexp.MustCompile(`(?i)\b\w*(?:` + fields + `)\w*\b`)
	r.reduceRawSum = regexp.MustCompile(`[+]\s*[\w$]+\.\w*(?i:` + fields + `)\w*\b`)
}

// AnalyzeFile checks TS/JS lines for money arithmetic
func (r *FrontendMoneyArithmeticRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if ctx.IsTestFile() || strings.Contains(ctx.RelPath, "generated") {
		return nil
	}

	var violations []*core.Violation

	for i, rawLine := range ctx.Lines {
		line := stripTrailingComment(rawLine)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if r.isSameFieldComparator(line) {
			continue
		}

		if r.lineHasParsedMoneyArithmetic(line) ||
			(strings.Contains(line, r.reduceMarker) && r.reduceRawSum.MatchString(line)) ||
			r.isMoneyAccumulation(line) {
			v := r.CreateViolation(ctx.RelPath, i+1,
				"Client-side arithmetic over a money value — financial aggregates must be computed on the backend")
			v.WithCode(trimmed)
			v.WithSuggestion("Return the computed value from the backend API (canonical calculation) and only format it here")
			violations = append(violations, v)
		}
	}

	return violations
}

// isMoneyAccumulation matches "moneyVar += <expr with money ident>" —
// aggregation through intermediate variables (investedAmount += invAmount).
func (r *FrontendMoneyArithmeticRule) isMoneyAccumulation(line string) bool {
	m := r.accumulate.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	return r.moneyField.MatchString(m[1]) && r.moneyField.MatchString(m[2])
}

// isSameFieldComparator reports whether the line subtracts the SAME money
// field of two different receivers — the sort-comparator / trend-delta idiom
// (presentational, not aggregation):
//
//	(parseFloat(String(a.amount)) - parseFloat(String(b.amount))) * dir
func (r *FrontendMoneyArithmeticRule) isSameFieldComparator(line string) bool {
	locs := r.parseCall.FindAllStringIndex(line, -1)
	if len(locs) != 2 {
		return false
	}
	var fields []string
	for _, loc := range locs {
		end := matchingParenEnd(line, loc[1])
		if end < 0 {
			return false
		}
		words := r.moneyField.FindAllString(line[loc[1]:end], -1)
		if len(words) == 0 {
			return false
		}
		fields = append(fields, strings.ToLower(words[len(words)-1]))
	}
	between := line[locs[0][1]:locs[1][0]]
	return fields[0] == fields[1] && strings.Contains(between, "-")
}

// stripTrailingComment removes a trailing // or /* comment, ignoring comment
// markers inside string literals.
func stripTrailingComment(line string) string {
	quote := byte(0)
	for i := 0; i < len(line)-1; i++ {
		c := line[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '/':
			if line[i+1] == '/' || line[i+1] == '*' {
				return line[:i]
			}
		}
	}
	return line
}

// lineHasParsedMoneyArithmetic reports whether the line applies an arithmetic
// operator to parseFloat/Number over a money-named field.
func (r *FrontendMoneyArithmeticRule) lineHasParsedMoneyArithmetic(line string) bool {
	for _, loc := range r.parseCall.FindAllStringIndex(line, -1) {
		argStart := loc[1] // position right after '('
		argEnd := matchingParenEnd(line, argStart)
		if argEnd < 0 {
			continue
		}
		if !r.moneyField.MatchString(line[argStart:argEnd]) {
			continue
		}
		if hasArithmeticBefore(line[:loc[0]]) || hasArithmeticAfter(line[argEnd+1:]) {
			return true
		}
	}
	return false
}

// matchingParenEnd returns the index of the ')' closing the call whose
// argument starts at start, or -1. Nested parens and quoted strings are
// handled.
func matchingParenEnd(line string, start int) int {
	depth := 1
	quote := byte(0)
	for i := start; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// hasArithmeticBefore reports whether the text ends with an arithmetic
// operator ("sum + ", "total += ") rather than a plain assignment or arrow.
func hasArithmeticBefore(prefix string) bool {
	trimmed := strings.TrimRight(prefix, " \t")
	if trimmed == "" {
		return false
	}
	last := trimmed[len(trimmed)-1]
	if strings.IndexByte("+-*/", last) >= 0 {
		// "=>" arrow already excluded (ends with '>'); unary minus after '('
		// or '=' ("= -parseFloat") is sign, not aggregation.
		if last == '-' && len(trimmed) >= 2 {
			beforeMinus := trimmed[len(trimmed)-2]
			if strings.IndexByte("(=,", beforeMinus) >= 0 {
				return false
			}
		}
		return true
	}
	// Compound assignment: "+=", "-=", "*=", "/=".
	if last == '=' && len(trimmed) >= 2 && strings.IndexByte("+-*/", trimmed[len(trimmed)-2]) >= 0 {
		return true
	}
	return false
}

// hasArithmeticAfter reports whether the text starts with an arithmetic
// operator, excluding comment starts ("//", "/*").
func hasArithmeticAfter(suffix string) bool {
	trimmed := strings.TrimLeft(suffix, " \t")
	if trimmed == "" {
		return false
	}
	first := trimmed[0]
	if strings.IndexByte("+-*", first) >= 0 {
		return true
	}
	if first == '/' && len(trimmed) >= 2 && trimmed[1] != '/' && trimmed[1] != '*' {
		return true
	}
	return false
}

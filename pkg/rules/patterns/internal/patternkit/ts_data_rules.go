package patternkit

import (
	"regexp"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// JsReport appends the finding of a frontend rule at a line unless the line
// suppresses it.
func JsReport(violations []*core.Violation, rule *rules.BaseRule, ctx *core.FileContext, line int, message, suggestion string) []*core.Violation {
	if ctx.IsSuppressed(line, rule.Name()) {
		return violations
	}
	return append(violations, SqlViolation(rule, ctx, line, message, suggestion))
}

const jsDomainNames = `network|chain|currency|token|asset|symbol|coin`

var (
	JsDomainFieldDefault = regexp.MustCompile(`\.\s*(?:` + jsDomainNames + `)\s*(?:\?\?|\|\|)\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]`)
	JsDomainParamDefault = regexp.MustCompile(`[(,{]\s*(?:` + jsDomainNames + `)\s*(?::\s*string\s*)?=\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]`)
	// JsDomainCode is a value that names a network or a currency: USDC,
	// polygon, eth-mainnet. Words for a missing value are not codes.
	JsDomainCode  = regexp.MustCompile(`^[A-Za-z][\w.-]*$`)
	JsMissingWord = regexp.MustCompile(`(?i)^(?:unknown|none|n/?a|null|undefined|tbd|empty|missing)$`)
	// JsMoneyFieldZero is a money field, or any field of a balance record,
	// defaulted to 0 with ?? or ||.
	JsMoneyFieldZero = regexp.MustCompile(`(?:(?:^|[^?])\.\s*\w*(?:[Aa]mount|[Ff]ee|[Bb]alance|[Pp]rice)|\b\w*[Bb]alance\s*\.\s*[a-z]\w*)\s*(?:\?\.\s*toString\s*\(\s*\))?\s*(?:\?\?|\|\|)\s*(?:'0'|"0"|0\b)\s*\)?\s*([<>!=]?)`)
)

var (
	JsDisplayFormatterCall = regexp.MustCompile(`\b(format(?:Amount|Money|Currency|Usd|USD|Number|Price|Balance)\w*)\s*\(`)
	JsPlainFormatter       = regexp.MustCompile(`Plain|Raw|Input|Csv|CSV`)
	JsCSVMention           = regexp.MustCompile(`(?i)csv`)
)

// InCSVRow reports a position inside an array literal of a block that builds
// a CSV.
func (f JsFlat) InCSVRow(pos int) bool {
	if f.innermostOpen(pos) != '[' {
		return false
	}
	brace := f.EnclosingBrace(pos)
	if brace < 0 {
		return false
	}
	end, ok := f.Closing(brace)
	return ok && JsCSVMention.MatchString(f.Text[brace:end])
}

// innermostOpen returns the innermost bracket left open before pos, 0 at the
// top level.
func (f JsFlat) innermostOpen(pos int) byte {
	depth := 0
	for i := pos - 1; i >= 0; i-- {
		switch c := f.Code[i]; c {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth == 0 {
				return c
			}
			depth--
		}
	}
	return 0
}

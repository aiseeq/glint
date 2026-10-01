package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewFloatToTokenUnitsRule())
}

// FloatToTokenUnitsRule detects an amount turned into integer token units
// through a float:
//
//	const amountWei = Math.floor(amount * 1000000) // USDC has 6 decimals
//
// 0.29 * 1e6 is 289999.99999999994 in IEEE-754, so floor sends one unit less
// than the user typed, and past 2^53 (any amount at 18 decimals) the product
// is not even an integer of the right size. Parse the decimal string into
// units instead (parseUnits(amount, decimals), BigInt arithmetic over the
// digits). Math.round is reported only when the scale is the token's
// decimals or 1e16 and above: below that rounding lands on the right unit.
// A product divided back (Math.floor(x * 1e6) / 1e6) truncates to a
// precision and is not a conversion.
type FloatToTokenUnitsRule struct {
	*rules.BaseRule
}

// NewFloatToTokenUnitsRule creates the rule
func NewFloatToTokenUnitsRule() *FloatToTokenUnitsRule {
	return &FloatToTokenUnitsRule{BaseRule: rules.NewBaseRule(
		"float-to-token-units",
		"patterns",
		"Detects Math.floor(amount * 1e6) and the like — converting an amount to integer token units through a float loses a unit; parse the decimal string (parseUnits)",
		core.SeverityHigh,
	)}
}

var (
	jsRounding = regexp.MustCompile(`\bMath\.(floor|ceil|trunc|round)\s*\(`)
	// tokenScale is a power of ten: 1e6, 1000000, 10 ** decimals, Math.pow(10, 6).
	tokenScale = regexp.MustCompile(`^\s*(?:1e\+?(\d+)|1(0{3,})|10\s*\*\*\s*([\w$.]+)|Math\.pow\(\s*10\s*,\s*([\w$.]+)\s*\))\s*$`)
)

// AnalyzeFile reports the float conversions to token units of a TS/JS file.
func (r *FloatToTokenUnitsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() || ctx.IsTestFile() || ctx.IsGenerated() {
		return nil
	}
	code := helpers.FileJSCode(ctx)
	text := helpers.FileJSText(ctx)
	var violations []*core.Violation
	for i, line := range code {
		if !strings.Contains(line, "Math.") {
			continue
		}
		for _, loc := range jsRounding.FindAllStringSubmatchIndex(line, -1) {
			end := matchingParenEnd(line, loc[1])
			if end < 0 || strings.HasPrefix(strings.TrimSpace(line[end+1:]), "/") {
				continue
			}
			if !scalesMoneyToUnits(text[i][loc[1]:end], line[loc[2]:loc[3]] == "round") || ctx.IsSuppressed(i+1, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, i+1,
				"Amount converted to integer token units through a float — "+line[loc[0]:loc[3]]+"(amount * 10^decimals) can land one unit off (0.29 * 1e6 = 289999.99999999994)")
			v.WithCode(strings.TrimSpace(ctx.Lines[i]))
			v.WithSuggestion("Parse the decimal string into units (parseUnits(amount, decimals) in ethers/viem) or do BigInt arithmetic on its digits")
			violations = append(violations, v)
		}
	}
	return violations
}

// scalesMoneyToUnits reports whether the argument multiplies a money operand
// by a power of ten large enough to be token units. Rounding to nearest is
// exact below 1e16, so it counts only for a symbolic exponent or above.
func scalesMoneyToUnits(argument string, nearest bool) bool {
	factors := topLevelFactors(argument)
	if len(factors) != 2 {
		return false
	}
	for k, factor := range factors {
		m := tokenScale.FindStringSubmatch(factor)
		if m == nil || !looksLikeMoney(factors[1-k]) {
			continue
		}
		exponent := len(m[2])
		if digits := m[1] + m[3] + m[4]; digits != "" {
			number, numeric := decimalNumber(digits)
			if !numeric {
				return true // the token's decimals
			}
			exponent = number
		}
		if nearest {
			return exponent >= 16
		}
		return exponent >= 3
	}
	return false
}

// decimalNumber reads an exponent written in digits, capped at 1000; a name
// (decimals, token.decimals) is not numeric.
func decimalNumber(s string) (int, bool) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = min(n*10+int(c-'0'), 1000)
	}
	return n, true
}

// topLevelFactors splits an expression at its top-level '*' (not '**').
func topLevelFactors(expression string) []string {
	var factors []string
	depth, from := 0, 0
	for j := 0; j < len(expression); j++ {
		switch c := expression[j]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '*':
			if j+1 < len(expression) && expression[j+1] == '*' {
				j++
				continue
			}
			if depth == 0 {
				factors = append(factors, expression[from:j])
				from = j + 1
			}
		}
	}
	return append(factors, expression[from:])
}

package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewMoneyMaxRoundedHalfUpRule())
}

// MoneyMaxRoundedHalfUpRule detects the most a user may spend put into the
// amount field through toFixed:
//
//	<button onClick={() => setWithdrawalAmount(maxWithdraw.toFixed(2))}>Max</button>
//
// toFixed rounds half up: a balance of 10.005 becomes "10.01", a cent more
// than there is, and the "Max" button produces a request the backend rejects.
// The limit has to be rounded down (floor to the cent) before it is entered.
// Reported is toFixed on a balance, an available amount or a maximum of
// money whose result goes into a state setter, a form value or an input's
// value, unless the variable was floored where it was assigned.
type MoneyMaxRoundedHalfUpRule struct {
	*rules.BaseRule
}

// NewMoneyMaxRoundedHalfUpRule creates the rule
func NewMoneyMaxRoundedHalfUpRule() *MoneyMaxRoundedHalfUpRule {
	return &MoneyMaxRoundedHalfUpRule{BaseRule: rules.NewBaseRule(
		"money-max-rounded-half-up",
		"patterns",
		"Detects a balance or a money maximum entered into the amount field through toFixed, which rounds up past what is available",
		core.SeverityHigh,
	)}
}

var (
	// amountDestination ends the code before a value entered as the amount:
	// setX(, setValue('field', , input.value =.
	amountDestination = regexp.MustCompile(`(?:\bset[A-Z][\w$]*\(\s*|\bsetValue\(\s*['"\x60][^'"\x60]*['"\x60]\s*,\s*|\.value\s*=\s*)$`)
	roundedDown       = regexp.MustCompile(`(?i)floor|trunc|round_?down`)
	limitSpend        = wordSet("stake", "stakeable", "withdrawable", "spendable", "send", "transfer", "receive")
)

// AnalyzeFile reports the money limits of a TS/JS file entered through toFixed.
func (r *MoneyMaxRoundedHalfUpRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() || ctx.IsTestFile() || ctx.IsGenerated() {
		return nil
	}
	code := helpers.FileJSCode(ctx)
	var violations []*core.Violation
	for i, line := range code {
		from := 0
		for {
			k := strings.Index(line[from:], ".toFixed(")
			if k < 0 {
				break
			}
			dot := from + k
			from = dot + 1
			start := jsReceiverStart(line, dot)
			receiver := line[start:dot]
			if receiver == "" || strings.ContainsAny(receiver, "([") || !moneyLimit(receiver) {
				continue
			}
			if !amountDestination.MatchString(line[:start]) || flooredAtAssignment(code, i, receiver) {
				continue
			}
			if ctx.IsSuppressed(i+1, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, i+1,
				"The limit "+receiver+" is entered as the amount through toFixed, which rounds half up — the field can get a cent more than is available")
			v.WithCode(strings.TrimSpace(ctx.Lines[i]))
			v.WithSuggestion("Round the limit down before entering it: (Math.floor(limit * 100) / 100).toFixed(2), or a decimal type rounding toward zero")
			violations = append(violations, v)
		}
	}
	return violations
}

// moneyLimit reports whether a receiver names the most a user can spend: a
// balance, an available or remaining amount, or a maximum of money.
func moneyLimit(receiver string) bool {
	tokens := identifierTokens(receiver)
	limit, money := false, false
	for _, token := range tokens {
		switch token {
		case "balance", "balances", "available", "remaining":
			return true
		case "max", "maximum":
			limit = true
		}
		if moneyValueTokens[token] || moneyFlowTokens[token] || limitSpend[token] {
			money = true
		}
	}
	return limit && money
}

// flooredAtAssignment reports whether the variable the receiver names was
// assigned a rounded-down value in the lines before line.
func flooredAtAssignment(code []string, line int, receiver string) bool {
	name := receiver
	if dot := strings.LastIndexAny(name, ".!?"); dot >= 0 {
		name = name[dot+1:]
	}
	if name == "" {
		return false
	}
	assignment := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*=[^=]`)
	for j := line - 1; j >= 0 && j >= line-40; j-- {
		if loc := assignment.FindStringIndex(code[j]); loc != nil {
			return roundedDown.MatchString(code[j][loc[1]:])
		}
	}
	return false
}

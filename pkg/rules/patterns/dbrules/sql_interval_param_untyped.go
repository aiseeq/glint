package dbrules

import (
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() { rules.Register(NewSQLIntervalParamUntypedRule()) }

// SQLIntervalParamUntypedRule detects an untyped parameter first used in
// interval arithmetic:
//
//	SELECT created_at < $2 - INTERVAL '30 days'
//
// PostgreSQL infers $2 as interval from that expression, then cannot compare
// the timestamp column with the resulting interval, so the query fails at run
// time. A cast or an earlier use with a column gives the parameter its type.
type SQLIntervalParamUntypedRule struct{ *rules.BaseRule }

// NewSQLIntervalParamUntypedRule creates the rule.
func NewSQLIntervalParamUntypedRule() *SQLIntervalParamUntypedRule {
	return &SQLIntervalParamUntypedRule{BaseRule: rules.NewBaseRule(
		"sql-interval-param-untyped",
		"patterns",
		"Detects a parameter first inferred as interval by interval arithmetic — PostgreSQL cannot compare the result with a timestamp, so the query fails at run time",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports parameters PostgreSQL would infer as interval.
func (r *SQLIntervalParamUntypedRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !patternkit.ProductionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, literal := range patternkit.SqlLiterals(ctx.GoAST) {
		tokens := sqlIntervalTokens(literal.Text)
		first := make(map[string]int)
		for i, token := range tokens {
			if !token.parameter {
				continue
			}
			if _, exists := first[token.text]; exists {
				continue
			}
			first[token.text] = i
		}
		for i, token := range tokens {
			if !token.parameter || first[token.text] != i || sqlParamTyped(tokens, i) || sqlParamTypedByColumn(tokens, i) {
				continue
			}
			if !sqlParamMeetsInterval(tokens, i) {
				continue
			}
			line := literal.LineAt(ctx, token.start)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, patternkit.SqlViolation(r.BaseRule, ctx, line,
				token.text+" meets INTERVAL arithmetic before any cast, so Postgres infers it as interval and the comparison fails at run time",
				"Cast the parameter: "+token.text+"::timestamptz"))
		}
	}
	return violations
}

type sqlIntervalToken struct {
	text      string
	start     int
	parameter bool
	word      bool
	string    bool
}

func sqlIntervalTokens(sql string) []sqlIntervalToken {
	var tokens []sqlIntervalToken
	for i := 0; i < len(sql); {
		if unicode.IsSpace(rune(sql[i])) {
			i++
			continue
		}
		start := i
		if i+1 < len(sql) && sql[i:i+2] == "--" {
			if end := strings.IndexByte(sql[i+2:], '\n'); end >= 0 {
				i += end + 3
			} else {
				break
			}
			continue
		}
		if sql[i] == '\'' || sql[i] == '"' {
			quote := sql[i]
			i = sqlIntervalQuotedEnd(sql, i+1, quote)
			tokens = append(tokens, sqlIntervalToken{text: sql[start:i], start: start, string: quote == '\''})
			continue
		}
		if sql[i] == '$' && i+1 < len(sql) && sql[i+1] >= '0' && sql[i+1] <= '9' {
			i += 2
			for i < len(sql) && sql[i] >= '0' && sql[i] <= '9' {
				i++
			}
			tokens = append(tokens, sqlIntervalToken{text: sql[start:i], start: start, parameter: true})
			continue
		}
		if sqlIntervalWordByte(sql[i]) {
			i++
			for i < len(sql) && sqlIntervalWordByte(sql[i]) {
				i++
			}
			tokens = append(tokens, sqlIntervalToken{text: sql[start:i], start: start, word: true})
			continue
		}
		if i+1 < len(sql) && (sql[i:i+2] == "::" || sql[i:i+2] == "<=" || sql[i:i+2] == ">=" || sql[i:i+2] == "<>" || sql[i:i+2] == "!=") {
			i += 2
		} else {
			i++
		}
		tokens = append(tokens, sqlIntervalToken{text: sql[start:i], start: start})
	}
	return tokens
}

func sqlIntervalQuotedEnd(sql string, i int, quote byte) int {
	for i < len(sql) {
		if sql[i] == quote {
			i++
			if i < len(sql) && sql[i] == quote {
				i++
				continue
			}
			break
		}
		if sql[i] == '\\' && i+1 < len(sql) {
			i += 2
		} else {
			i++
		}
	}
	return i
}

func sqlIntervalWordByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

func sqlParamTyped(tokens []sqlIntervalToken, i int) bool {
	if i+1 < len(tokens) && tokens[i+1].text == "::" {
		return true
	}
	if i >= 2 && strings.EqualFold(tokens[i-2].text, "CAST") && tokens[i-1].text == "(" {
		for j := i + 1; j+1 < len(tokens) && tokens[j].text != ")"; j++ {
			if strings.EqualFold(tokens[j].text, "AS") {
				return true
			}
		}
	}
	return false
}

func sqlParamTypedByColumn(tokens []sqlIntervalToken, i int) bool {
	if i > 1 && (sqlComparisonOperator(tokens[i-1].text) || sqlArithmeticOperator(tokens[i-1].text)) && sqlColumnBefore(tokens, i-1) {
		// Arithmetic is left-associative and binds tighter than a comparison:
		// col - $1 - INTERVAL types $1 by col, col < $1 - INTERVAL does not.
		return sqlArithmeticOperator(tokens[i-1].text) || i+1 >= len(tokens) || !sqlArithmeticOperator(tokens[i+1].text)
	}
	return i+2 < len(tokens) && (sqlComparisonOperator(tokens[i+1].text) || sqlArithmeticOperator(tokens[i+1].text)) && sqlColumnToken(tokens[i+2])
}

func sqlColumnBefore(tokens []sqlIntervalToken, operator int) bool {
	if operator == 0 || !sqlColumnToken(tokens[operator-1]) {
		return false
	}
	if operator >= 2 && tokens[operator-2].text == "." {
		return operator >= 4 && sqlColumnToken(tokens[operator-3])
	}
	return true
}

func sqlComparisonOperator(op string) bool {
	switch op {
	case "=", "<>", "!=", "<", ">", "<=", ">=":
		return true
	default:
		return false
	}
}

func sqlArithmeticOperator(op string) bool { return op == "+" || op == "-" || op == "*" || op == "/" }

func sqlColumnToken(token sqlIntervalToken) bool {
	return token.word && !strings.EqualFold(token.text, "AND") && !strings.EqualFold(token.text, "OR") && !strings.EqualFold(token.text, "INTERVAL")
}

func sqlParamMeetsInterval(tokens []sqlIntervalToken, i int) bool {
	if i+2 < len(tokens) && sqlIntervalOperator(tokens[i+1].text) && sqlIntervalLiteral(tokens, i+2) {
		return true
	}
	return i >= 3 && sqlIntervalOperator(tokens[i-1].text) && sqlIntervalLiteralBefore(tokens, i-2)
}

func sqlIntervalLiteralBefore(tokens []sqlIntervalToken, end int) bool {
	if end >= 1 && strings.EqualFold(tokens[end-1].text, "INTERVAL") && tokens[end].string {
		return true
	}
	return end >= 2 && tokens[end-2].string && tokens[end-1].text == "::" && strings.EqualFold(tokens[end].text, "interval")
}

func sqlIntervalOperator(op string) bool { return op == "+" || op == "-" }

func sqlIntervalLiteral(tokens []sqlIntervalToken, i int) bool {
	if i+1 < len(tokens) && strings.EqualFold(tokens[i].text, "INTERVAL") && tokens[i+1].string {
		return true
	}
	return i+2 < len(tokens) && tokens[i].string && tokens[i+1].text == "::" && strings.EqualFold(tokens[i+2].text, "interval")
}

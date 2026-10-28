package dbrules

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewSQLGlobalMaxUsedAsPerGroupLatestRule())
}

// SQLGlobalMaxUsedAsPerGroupLatestRule detects a global maximum date applied
// to rows whose result is ordered by multiple key columns.
type SQLGlobalMaxUsedAsPerGroupLatestRule struct {
	*rules.BaseRule
}

// NewSQLGlobalMaxUsedAsPerGroupLatestRule creates the rule.
func NewSQLGlobalMaxUsedAsPerGroupLatestRule() *SQLGlobalMaxUsedAsPerGroupLatestRule {
	return &SQLGlobalMaxUsedAsPerGroupLatestRule{BaseRule: rules.NewBaseRule(
		"sql-global-max-used-as-per-group-latest",
		"patterns",
		"Detects a global MAX(date) used to select the latest rows for multiple keys; each key needs its own latest date",
		core.SeverityMedium,
	)}
}

var globalMaxCTE = regexp.MustCompile(`(?is)\bWITH\s+(\w+)\s+AS\s*\((.*?)\)\s*SELECT\b(.*?)\bFROM\s+(\S+)(.*?)\bWHERE\s+(\w+)\s*=\s*\(\s*SELECT\s+(\w+)\s+FROM\s+(\w+)\s*\)(.*)`)
var maxDateExpr = regexp.MustCompile(`(?is)\bMAX\s*\(\s*(\w+)\s*\)\s+AS\s+(\w+)`)
var multiKeyOrder = regexp.MustCompile(`(?is)\bORDER\s+BY\s+\w+\s*\.\s*\w+\s*,\s*\w+\s*\.\s*\w+|\bORDER\s+BY\s+\w+\s*,\s*\w+`)
var globalMaxSubquery = regexp.MustCompile(`(?is)\bWHERE\s+(\w+)\s*=\s*\(\s*SELECT\s+MAX\s*\(\s*(\w+)\s*\)\s+FROM\s+(\S+)(?:\s+WHERE\s+([^)]*))?\)`)
var qualifiedColumn = regexp.MustCompile(`\b\w+\s*\.\s*\w+\b`)
var comparedColumn = regexp.MustCompile(`(?i)\b([a-z_]\w*)\s*(?:=|<>|!=|\bIN\b)`)

// maxFiltersKeys reports a WHERE of the MAX(date) query that compares a column
// other than the date: the maximum is then taken over a chosen set of keys, and
// a key of that set missing on the date drops out. A MAX over the whole table,
// or bounded by the date only, is the date of the latest complete publication.
func maxFiltersKeys(where, dateColumn string) bool {
	for _, match := range comparedColumn.FindAllStringSubmatch(where, -1) {
		if !strings.EqualFold(match[1], dateColumn) {
			return true
		}
	}
	return false
}

func cteWhere(body string) string {
	at := strings.Index(strings.ToLower(body), "where")
	if at < 0 {
		return ""
	}
	return body[at+len("where"):]
}

// AnalyzeFile reports global date maxima used to filter rows for multiple keys.
func (r *SQLGlobalMaxUsedAsPerGroupLatestRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !patternkit.ProductionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, literal := range patternkit.SqlLiterals(ctx.GoAST) {
		match := globalMaxCTE.FindStringSubmatch(literal.Text)
		dateColumn, offset, suffix := "", 0, ""
		if len(match) > 0 {
			cteName, cteBody, outerProjection, table, beforeWhere, filterDate, selectedColumn, selectedCTE := match[1], match[2], match[3], match[4], match[5], match[6], match[7], match[8]
			max := maxDateExpr.FindStringSubmatch(cteBody)
			if len(max) == 0 || !maxFiltersKeys(cteWhere(cteBody), max[1]) || !strings.EqualFold(cteName, selectedCTE) || !strings.EqualFold(max[2], selectedColumn) || !strings.EqualFold(max[1], filterDate) || !strings.Contains(strings.ToLower(cteBody), "from "+strings.ToLower(table)) || !strings.Contains(strings.ToLower(outerProjection), strings.ToLower(filterDate)) {
				continue
			}
			dateColumn, suffix = filterDate, beforeWhere+match[9]
			offset = strings.Index(strings.ToLower(literal.Text), "where "+strings.ToLower(dateColumn))
		} else {
			subquery := globalMaxSubquery.FindStringSubmatch(literal.Text)
			if len(subquery) == 0 || !strings.EqualFold(subquery[1], subquery[2]) || qualifiedColumn.MatchString(subquery[4]) || !maxFiltersKeys(subquery[4], subquery[2]) || !multiKeyOrder.MatchString(literal.Text) {
				continue
			}
			dateColumn, suffix = subquery[1], literal.Text
			offset = strings.Index(strings.ToLower(literal.Text), "where "+strings.ToLower(dateColumn))
		}
		if !multiKeyOrder.MatchString(suffix) {
			continue
		}
		if offset < 0 {
			offset = 0
		}
		line := literal.LineAt(ctx, offset)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		violations = append(violations, patternkit.SqlViolation(r.BaseRule, ctx, line,
			"one global MAX(date) selects rows for multiple keys, so keys missing on that date disappear",
			"Select each key's latest row with DISTINCT ON, a window function, or a correlated MAX(date)"))
	}
	return violations
}

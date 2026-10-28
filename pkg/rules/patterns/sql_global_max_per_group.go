package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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

// AnalyzeFile reports global date maxima used to filter rows for multiple keys.
func (r *SQLGlobalMaxUsedAsPerGroupLatestRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, literal := range sqlLiterals(ctx.GoAST) {
		match := globalMaxCTE.FindStringSubmatch(literal.text)
		dateColumn, offset, suffix := "", 0, ""
		if len(match) > 0 {
			cteName, cteBody, outerProjection, table, beforeWhere, filterDate, selectedColumn, selectedCTE := match[1], match[2], match[3], match[4], match[5], match[6], match[7], match[8]
			max := maxDateExpr.FindStringSubmatch(cteBody)
			if len(max) == 0 || !strings.EqualFold(cteName, selectedCTE) || !strings.EqualFold(max[2], selectedColumn) || !strings.EqualFold(max[1], filterDate) || !strings.Contains(strings.ToLower(cteBody), "from "+strings.ToLower(table)) || !strings.Contains(strings.ToLower(outerProjection), strings.ToLower(filterDate)) {
				continue
			}
			dateColumn, suffix = filterDate, beforeWhere+match[9]
			offset = strings.Index(strings.ToLower(literal.text), "where "+strings.ToLower(dateColumn))
		} else {
			subquery := globalMaxSubquery.FindStringSubmatch(literal.text)
			if len(subquery) == 0 || !strings.EqualFold(subquery[1], subquery[2]) || qualifiedColumn.MatchString(subquery[4]) || !multiKeyOrder.MatchString(literal.text) {
				continue
			}
			dateColumn, suffix = subquery[1], literal.text
			offset = strings.Index(strings.ToLower(literal.text), "where "+strings.ToLower(dateColumn))
		}
		if !multiKeyOrder.MatchString(suffix) {
			continue
		}
		if offset < 0 {
			offset = 0
		}
		line := literal.lineAt(ctx, offset)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
			"one global MAX(date) selects rows for multiple keys, so keys missing on that date disappear",
			"Select each key's latest row with DISTINCT ON, a window function, or a correlated MAX(date)"))
	}
	return violations
}

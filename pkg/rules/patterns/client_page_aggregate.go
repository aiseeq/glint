package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewClientPageAggregateRule())
}

// ClientPageAggregateRule detects a page of a server list treated in the
// browser as the whole list:
//
//	const sorted = [...usersData.users].sort(byPriority)   // usersData.pagination read too
//	setTotalPages(usersData.pagination.totalPages)
//
//	const withdrawals = wdr.withdrawals ?? []
//	setStats({ totalWithdrawals: withdrawals.length })     // a page counted as the total
//
// A sort orders the rows of one page while the pager walks the server's
// order: the "most urgent first" list puts page 2's most urgent row after
// page 1's least urgent one. A length of a page stops at the page size and
// says "100 withdrawals" for every count past it.
type ClientPageAggregateRule struct {
	*rules.BaseRule
}

// NewClientPageAggregateRule creates the rule
func NewClientPageAggregateRule() *ClientPageAggregateRule {
	return &ClientPageAggregateRule{BaseRule: rules.NewBaseRule(
		"client-page-aggregate",
		"patterns",
		"Detects a page of a server list sorted or counted in the browser as if it were the whole list",
		core.SeverityMedium,
	)}
}

var (
	// pageSortSpread is [...resp.list].sort( or .toSorted(.
	pageSortSpread = regexp.MustCompile(`\[\s*\.\.\.\s*([A-Za-z_$][\w$]*)\.[A-Za-z_$][\w$]*\s*\]\s*\.(?:sort|toSorted)\(`)
	// pageSortInPlace is resp.list.sort(.
	pageSortInPlace = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\.[A-Za-z_$][\w$]*\.(?:sort|toSorted)\(`)
	// pageTotalLength is a total* key given the length of a list.
	pageTotalLength = regexp.MustCompile(`\btotal\w*\s*:\s*([A-Za-z_$][\w$]*)\.length\b`)
)

// AnalyzeFile reports the page sorts and page counts of a TS/JS file.
func (r *ClientPageAggregateRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || ctx.IsTestFile() {
		return nil
	}
	code := newJSSource(ctx).code
	joined := strings.Join(code, "\n")
	var violations []*core.Violation
	report := func(i int, message, suggestion string) {
		if ctx.IsSuppressed(i+1, r.Name()) {
			return
		}
		v := r.CreateViolation(ctx.RelPath, i+1, message)
		v.WithCode(strings.TrimSpace(ctx.Lines[i]))
		v.WithSuggestion(suggestion)
		violations = append(violations, v)
	}
	for i, line := range code {
		if sorted := pageSortedResponse(line); sorted != "" && readsPagination(joined, sorted) {
			report(i, "One page of "+sorted+" sorted in the browser — the order holds inside the page while the pager walks the server's order",
				"Sort on the server (an ORDER BY the request asks for) and keep the page as it came")
			continue
		}
		if m := pageTotalLength.FindStringSubmatch(line); m != nil && listOffResponse(code, i, m[1]) {
			report(i, "Total taken from the length of "+m[1]+", a list as one response returned it — a page stops at its size and the total with it",
				"Show the total the server reports for the whole query (pagination.total or a dedicated aggregate)")
		}
	}
	return violations
}

// pageSortedResponse returns the object whose list property a line sorts.
func pageSortedResponse(line string) string {
	if m := pageSortSpread.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := pageSortInPlace.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

// readsPagination reports a file reading the page counters of an object.
func readsPagination(code, object string) bool {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(object) + `\s*\??\.\s*(?:pagination|totalPages|total_pages|pageCount)\b`).MatchString(code)
}

// pageListLookback bounds the search for a list's definition.
const pageListLookback = 40

// listOffResponse reports a variable defined, a few lines above, as a list
// property of an object taken from a response: const xs = resp.items ?? [].
func listOffResponse(code []string, at int, name string) bool {
	def := regexp.MustCompile(`\b(?:const|let|var)\s+` + regexp.QuoteMeta(name) + `\s*=\s*([A-Za-z_$][\w$]*)\??\.[A-Za-z_$][\w$]*\s*(?:\?\?\s*\[\s*\]|\|\|\s*\[\s*\])?\s*$`)
	for i := at - 1; i >= 0 && i >= at-pageListLookback; i-- {
		m := def.FindStringSubmatch(code[i])
		if m == nil {
			continue
		}
		return fromResponse(code, i, m[1])
	}
	return false
}

// fromResponse reports an object defined, a few lines above, from a
// response: awaited, or the value of a response variable.
func fromResponse(code []string, at int, name string) bool {
	def := regexp.MustCompile(`\b(?:const|let|var)\s+` + regexp.QuoteMeta(name) + `\s*=\s*(.*)$`)
	for i := at; i >= 0 && i >= at-pageListLookback; i-- {
		m := def.FindStringSubmatch(code[i])
		if m == nil {
			continue
		}
		return strings.Contains(m[1], "await ") || strings.Contains(strings.ToLower(m[1]), "response")
	}
	return false
}

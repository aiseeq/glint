package patterns

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(paginatedFetchFirstPageOnlyRule())
}

// paginatedFetchFirstPageOnlyRule detects a frontend URL that asks a list
// endpoint for one large page and never for the next:
//
//	const TRANSACTIONS_LIMIT = 1000
//	api.get(`${ENDPOINTS.TRANSACTIONS}?limit=${TRANSACTIONS_LIMIT}`)
//
// The large cap reads as "all of it" until the history outgrows it; then
// totals, exports and "all history" views built from the answer lose the rows
// past the first page without an error. A URL that names the page, an offset
// or a cursor walks the list; a function that wants a few rows on purpose
// (recent, latest, preview) is not judged. The Go side is
// paginated-call-first-page-only.
func paginatedFetchFirstPageOnlyRule() *tsRule {
	return newTSRule("paginated-fetch-first-page-only",
		"Detects a frontend URL that reads a list once with a large page size and no page, offset or cursor — rows past the first page are lost",
		checkPaginatedFetchFirstPageOnly)
}

// jsPageCapMin is the smallest page size a frontend URL asks for to mean
// "all of it": a page of 100 is the usual size of a screen's list, which
// shows the server's totals beside it.
const jsPageCapMin = 500

var (
	// jsPageSizeParam is a page size in a URL: ?limit=1000, &per_page=${LIMIT}.
	jsPageSizeParam = regexp.MustCompile(`[?&](?:limit|per_?page|perPage|page_?size|pageSize)=(?:(\d{1,9})\b|\$\{\s*([A-Za-z_$][\w$]*)\s*\})`)
	// jsPageWalkParam is a URL parameter that walks a list.
	jsPageWalkParam = regexp.MustCompile(`[?&](?:page|offset|cursor|after|before|skip|start|from_?id|last_?id|next)=`)
	// jsNumberConst is a numeric constant of a file: const LIMIT = 1000.
	jsNumberConst = regexp.MustCompile(`(?m)^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::\s*number\s*)?=\s*(\d{1,9})\b`)
)

func checkPaginatedFetchFirstPageOnly(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	if !strings.Contains(f.text, "=") || !jsPageSizeParam.MatchString(f.text) {
		return nil
	}
	consts := make(map[string]int)
	for _, m := range jsNumberConst.FindAllStringSubmatch(f.text, -1) {
		if n, err := strconv.Atoi(m[2]); err == nil {
			consts[m[1]] = n
		}
	}
	var violations []*core.Violation
	for _, m := range jsPageSizeParam.FindAllStringSubmatchIndex(f.text, -1) {
		size := -1
		if m[2] >= 0 {
			if n, err := strconv.Atoi(f.text[m[2]:m[3]]); err == nil {
				size = n
			}
		} else if n, ok := consts[f.text[m[4]:m[5]]]; ok {
			size = n
		}
		if size < jsPageCapMin || jsPageWalkParam.MatchString(jsURLAround(f.text, m[0])) {
			continue
		}
		if fn, ok := f.enclosingFunction(m[0]); ok && smallPageFuncName.MatchString(fn.name) {
			continue
		}
		violations = jsReport(violations, r.BaseRule, ctx, f.line(m[0]),
			fmt.Sprintf("The list is read once with page size %d and no page, offset or cursor — rows past the first page are lost", size),
			"Read page after page until a short page, or ask for a total computed by the server")
	}
	return violations
}

// jsURLAround returns the string literal around pos: from the quote or
// backtick before it to the one after it.
func jsURLAround(text string, pos int) string {
	start := strings.LastIndexAny(text[:pos], "`'\"\n")
	if start < 0 {
		start = 0
	}
	end := strings.IndexAny(text[pos:], "`'\"\n")
	if end < 0 {
		return text[start:]
	}
	return text[start : pos+end]
}

package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A frontend that reads a list endpoint once with a large page size takes
// the first page for the whole history: totals and exports built from it
// lose the rows past the cap without an error. A URL that names the page,
// an offset or a cursor walks the list; a small page on purpose is a preview,
// and a page of 100 is a screen's list shown beside the server's totals.
func TestPaginatedCallFirstPageOnlyFrontend(t *testing.T) {
	rule := paginatedFetchFirstPageOnlyRule()
	source := `const TRANSACTIONS_LIMIT = 1000
const PAGE = 100
const RECENT = 5

export async function fetchSnapshot() {
  const [txns, withdrawals] = await Promise.all([
    api.get(` + "`${ENDPOINTS.TRANSACTIONS}?limit=${TRANSACTIONS_LIMIT}`" + `),
    api.get(ENDPOINTS.WITHDRAWALS),
  ])
  return { txns, withdrawals }
}

export function getWithdrawalsForDashboard() {
  return request(` + "`${ENDPOINTS.ADMIN_WITHDRAWALS}?limit=100`" + `, 'GET')
}

export function loadPage(page: number) {
  return api.get(` + "`${ENDPOINTS.TRANSACTIONS}?limit=${PAGE}&page=${page}`" + `)
}

export function loadOffset(offset: number, limit: number) {
  return api.get(` + "`/positions?limit=${limit}&offset=${offset}`" + `)
}

export function getRecentActivity() {
  return api.get(` + "`/activity?limit=${RECENT}`" + `)
}

export function getLatestRates() {
  return api.get('/rates?limit=500')
}
`
	assert.Equal(t, []string{"src/hooks/useOperations.ts:7"},
		linesOf(t, rule, "src/hooks/useOperations.ts", source))
}

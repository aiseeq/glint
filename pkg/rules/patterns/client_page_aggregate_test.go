package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A page of users sorted in the browser: the order holds inside the page
// only, and the pager walks the server's order.
func TestClientPageAggregateSort(t *testing.T) {
	rule := NewClientPageAggregateRule()
	lines := violationLines(rule.AnalyzeFile(rulestest.TextFile(t, "app/users/page.tsx", `export default function UsersPage() {
  const load = async () => {
    const usersData = await api.listUsers({ page, limit: 20 })
    const sorted = [...usersData.users].sort((a, b) => b.priority - a.priority)
    const named = usersData.users.sort(byName)
    setUsers(sorted)
    setTotalPages(usersData.pagination.totalPages)
  }
  const local = [...rows.items].sort(byName)
}
`)))
	assert.Equal(t, []int{4, 5}, lines)
}

// The length of a page shown as the total: past the page size the count
// stops growing.
func TestClientPageAggregateTotal(t *testing.T) {
	rule := NewClientPageAggregateRule()
	lines := violationLines(rule.AnalyzeFile(rulestest.TextFile(t, "components/Dashboard.tsx", `export default function Dashboard() {
  const load = async () => {
    const [wdrResponse] = await Promise.allSettled([adminApi.getWithdrawals()])
    if (wdrResponse.status === 'fulfilled' && wdrResponse.value) {
      const wdr = wdrResponse.value as { withdrawals?: Array<{ status: string }> }
      const withdrawals = wdr.withdrawals ?? []
      const pending = withdrawals.filter(w => w.status === 'pending')
      setStats({
        totalWithdrawals: withdrawals.length,
        pendingCount: pending.length,
      })
    }
    const feed = buildFeed(items)
    logger.info('loaded', { total: feed.length })
    setCounter({ total: wdr.total ?? withdrawals.length })
  }
}
`)))
	assert.Equal(t, []int{9}, lines)
}

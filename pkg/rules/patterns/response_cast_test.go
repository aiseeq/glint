package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func responseCastLines(t *testing.T, path, source string) []int {
	t.Helper()
	return violationLines(NewResponseCastRule().AnalyzeFile(rulestest.TextFile(t, path, source)))
}

// A response cast to any or to a shape written on the spot is read as the
// cast says: a field the server renamed reads undefined and the screen shows
// an empty list.
func TestResponseCast(t *testing.T) {
	assert.Equal(t, []int{2}, responseCastLines(t, "web/src/app/history.tsx", `async function load(period: string) {
  const response = await api.get(`+"`/api/reports/daily?period=${period}`"+`) as any
  setData(response.data.items || [])
}
`))
	assert.Equal(t, []int{2}, responseCastLines(t, "web/src/app/deposits.tsx", `async function load(accountId: string) {
  const response = await backoffice.listPayouts({ accountId }) as { payouts?: PayoutRow[] }
  return response.payouts ?? []
}
`))
	assert.Equal(t, []int{4}, responseCastLines(t, "web/src/app/list.ts", `async function load() {
  const response = await client.request(
    '/api/list',
  ) as unknown as { rows: Row[] }
  return response.rows
}
`))
	assert.Equal(t, []int{2}, responseCastLines(t, "web/src/app/one.ts", `async function load() {
  return (await api.get('/api/one')) as any
}
`))
}

func TestResponseCastAllowed(t *testing.T) {
	assert.Empty(t, responseCastLines(t, "web/src/app/typed.ts", `async function load() {
  const response = await api.get<Orders>('/api/orders')
  const body = (await res.json()) as OrdersResponse
  const value = input as any
  const other = compute(x) as { a: number }
  return [response, body, value, other]
}
`), "a named type, a cast of something not awaited")
	assert.Empty(t, responseCastLines(t, "web/src/lib/api-client.ts", `class Client {
  async classify(limit: number) {
    return await this.makeRequest('/api/classify', 'POST', { limit }) as { classified: number }
  }
}
`), "the client typing its own transport")
	assert.Empty(t, responseCastLines(t, "web/src/app/history.test.tsx", `async function load() {
  const response = await api.get('/api/x') as any
}
`), "test code")
}

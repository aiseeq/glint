package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func responseJSONLines(t *testing.T, path, source string) []int {
	t.Helper()
	return violationLines(NewResponseJSONUnguardedRule().AnalyzeFile(rulestest.TextFile(t, path, source)))
}

// A body that is not JSON — a plain-text refusal from a middleware, a proxy's
// HTML page — makes response.json() throw a SyntaxError, and the user reads
// the parser's message instead of the reason.
func TestResponseJSONUnguarded(t *testing.T) {
	assert.Equal(t, []int{3}, responseJSONLines(t, "web/src/lib/claim.ts", `export async function claim(): Promise<void> {
  const response = await fetch('/api/codes/claim', { method: 'POST' })
  const data = await response.json()
  use(data)
}
`))
	assert.Equal(t, []int{2}, responseJSONLines(t, "web/src/lib/list.ts", `export const list = (): Promise<Item[]> =>
  fetch('/api/items').then((res) => res.json())
`))
	assert.Equal(t, []int{2}, responseJSONLines(t, "web/src/lib/read.ts", `export async function read(resp: Response) {
  return (await resp.json()) as Envelope
}
`))
}

func TestResponseJSONUnguardedAllowed(t *testing.T) {
	assert.Empty(t, responseJSONLines(t, "web/src/app/cancel/page.tsx", `export async function cancel(): Promise<void> {
  const response = await fetch('/api/profile/cancel', { method: 'POST' })
  const payload = await response.json().catch(() => null)
  const other = await fetch('/api/x')
    .then((r) => r.json())
    .catch(() => null)
  use(payload, other)
}
`), ".catch in the chain")
	assert.Empty(t, responseJSONLines(t, "web/src/lib/guarded.ts", `export async function load() {
  const response = await fetch('/api/users/profile')
  try {
    return await response.json()
  } catch {
    throw new ApiError(response.status, await response.text())
  }
}
`), "inside try")
	assert.Empty(t, responseJSONLines(t, "web/src/lib/schema.ts", `export const body = schema.json()
const text = JSON.stringify(value)
// const data = await response.json()
const s = 'response.json()'
`), "not a response, comments and strings")
	code := "const body = await response.json()\n"
	assert.Empty(t, responseJSONLines(t, "e2e/tests/codes-api.spec.ts", code), "tests read raw responses on purpose")
	assert.Empty(t, responseJSONLines(t, "web/src/__tests__/api.test.ts", code))
	assert.Empty(t, responseJSONLines(t, "api/x.go", "package api\n// await response.json()\n"))
}

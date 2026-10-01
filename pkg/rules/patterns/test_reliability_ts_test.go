package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// An upper bound on measured time fails by machine load.
func TestTestAssertsWallClock(t *testing.T) {
	ctx := rulestest.TextFile(t, "shared/tests/unit/validator.test.ts", `describe('validator', () => {
  it('caches', () => {
    const startFirst = performance.now();
    validate(input);
    const firstTime = performance.now() - startFirst;
    const startSecond = performance.now();
    validate(input);
    const secondTime = performance.now() - startSecond;
    expect(secondTime).toBeLessThanOrEqual(firstTime * 2);
    expect(Date.now() - started).toBeLessThan(100);
  });
  it('waits at least the delay', () => {
    const waited = Date.now() - before;
    expect(waited).toBeGreaterThanOrEqual(50);
    expect(count).toBeLessThan(3);
  });
});
`)
	assert.Equal(t, []int{9, 10}, violationLines(NewTestAssertsWallClockRule().AnalyzeFile(ctx)))
}

// A wait started after its action misses a fast response.
func TestBrowserWaitRegisteredAfterAction(t *testing.T) {
	ctx := rulestest.TextFile(t, "e2e/tests/analytics.spec.ts", `test('period switch', async ({ page }) => {
  await page.locator('button:has-text("All time")').click()
  await page.waitForResponse(
    resp => resp.url().includes('/analytics/metrics') && resp.status() === 200,
  )
  const refresh = page.waitForResponse(resp => resp.url().includes('/metrics'))
  await page.locator('button:has-text("7 days")').click()
  await refresh
  await page.getByRole('button', {
    name: 'Save',
  }).click()

  const response = await page.waitForResponse('**/api/save')
  await page.fill('#amount', '10')
  await expect(page.locator('#total')).toHaveText('10')
})
`)
	assert.Equal(t, []int{3, 13}, violationLines(NewBrowserWaitAfterActionRule().AnalyzeFile(ctx)))
}

// A ** glued to a word does not cross '/'.
func TestBrowserRouteGlobGlued(t *testing.T) {
	ctx := rulestest.TextFile(t, "e2e/tests/mfa.spec.ts", `test('mfa', async ({ page }) => {
  await page.route('**/factors**', async (route) => {
    if (new URL(route.request().url()).pathname.endsWith('/challenge')) {
      return route.fulfill({ body: '{}' })
    }
    await route.fulfill({ body: '[]' })
  })
  await page.route('**/api/user/**', handler)
  await page.route(/\/auth\/v1\/factors(\/|\?|$)/, handler)
  await page.waitForURL('**dashboard')
  await page.waitForURL('**/dashboard')
  await page.route('**', handler)
  await page.route('**/api/events**', async route => {
    if (route.request().url().includes('/api/events/subscribe')) {
      return route.fulfill({ body: '{}' })
    }
    await route.fulfill({ body: '[]' })
  })
  await page.route('**/api/positions**', async route => route.fulfill({ body: '[]' }))
  await page.route('**/api/deposits?**', async route => route.fulfill({ body: '[]' }))
  await page.route('**/api/user**', async route => {
    if (route.request().url().endsWith('/api/user')) {
      return route.fulfill({ body: '{}' })
    }
  })
})
`)
	assert.Equal(t, []int{2, 10, 13}, violationLines(NewBrowserRouteGlobGluedRule().AnalyzeFile(ctx)))
}

// Test addresses on registrable domains reach their owners.
func TestTestEmailRegistrableDomain(t *testing.T) {
	goCtx := rulestest.GoFile(t, "middleware/auth.go", `package middleware

import "strings"

const testDomain = "@shop-test.com"

func isTestUser(email string) bool {
	return strings.HasSuffix(email, testDomain) || email == "qa@test.com"
}

var safe = []string{"user@example.com", "user@shop.test", "admin@app.local", "news@latest.com", "a@testing.example"}
`)
	assert.Equal(t, []int{5, 8}, violationLines(NewTestEmailRegistrableDomainRule().AnalyzeFile(goCtx)))

	tsCtx := rulestest.TextFile(t, "e2e/fixtures/users.ts", `// owner: dev@test.com
export const email = 'e2e-user@app-test.com'
export const other = 'user@example.com'
const at = user@testmail.com
export const cleanup = ['%@app-test.com']
`)
	assert.Equal(t, []int{5}, violationLines(NewTestEmailRegistrableDomainRule().AnalyzeFile(tsCtx)))

	// A test's own fixture address sends nothing by itself; a domain it
	// matches users by does.
	testCtx := rulestest.GoFile(t, "tests/integration/users_test.go", `package integration

var fixture = "qa@test.com"

var markers = []string{
	"@test.com",
	"%@shop-test.com",
}
`)
	assert.Equal(t, []int{6, 7}, violationLines(NewTestEmailRegistrableDomainRule().AnalyzeFile(testCtx)))
}

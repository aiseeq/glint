package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func tautologicalTSLines(t *testing.T, path, source string) []int {
	t.Helper()
	ctx := core.NewFileContext(path, ".", []byte(source), nil)
	return violationLines(NewTautologicalAssertionRule().AnalyzeFile(ctx))
}

// A browser-test helper that returns before its assertions when the server
// answers with an unexpected status: the page check passes having checked
// nothing. Helpers under e2e/ are test code.
func TestTautologicalAssertion_TSReturnBeforeAssertions(t *testing.T) {
	const source = `import { expect, Page } from '@playwright/test'

export async function expectRouteReachable(page: Page, path: string): Promise<void> {
  const response = await page.goto(path)
  if (response?.status() === 429) {
    return
  }
  expect(response?.status()).not.toBe(404)
  expect(page.url()).toContain(path)
}

export async function openOptional(page: Page, path: string): Promise<boolean> {
  const response = await page.goto(path)
  if (!response?.ok()) return false
  return true
}

export async function expectListed(page: Page, path: string): Promise<void> {
  const response = await page.goto(path)
  if (response?.status() !== 200) {
    throw new Error('unexpected status ' + response?.status())
  }
  expect(page.url()).toContain(path)
}
`
	assert.Equal(t, []int{5}, tautologicalTSLines(t, "frontend/e2e/utils/navigation.ts", source))
	assert.Equal(t, []int{5}, tautologicalTSLines(t, "frontend/e2e/tests/navigation.spec.ts", source))
}

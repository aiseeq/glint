package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func skippedTestLines(t *testing.T, path, source string) []int {
	t.Helper()
	var ctx = rulestest.TextFile(t, path, source)
	if len(path) > 3 && path[len(path)-3:] == ".go" {
		ctx = rulestest.GoFile(t, path, source)
	}
	return violationLines(NewSkippedTestRule().AnalyzeFile(ctx))
}

// A suite switched off whole masks broken tests; so does a single test
// skipped with no reason beside it.
func TestSkippedTestTypeScript(t *testing.T) {
	assert.Equal(t, []int{1}, skippedTestLines(t, "e2e/tests/plans.spec.ts",
		"test.describe.skip('[OBSOLETE] plans page', () => {\n  test('renders', async ({ page }) => {})\n})\n"))
	assert.Equal(t, []int{1, 2}, skippedTestLines(t, "web/src/components/Chart.test.tsx",
		"xdescribe('old suite', () => {\n  xit('old case', () => {})\n})\n"))
	assert.Equal(t, []int{1}, skippedTestLines(t, "e2e/tests/details.spec.ts",
		"test.skip('details error scenarios', async ({ page }) => {})\n"))
	assert.Equal(t, []int{2}, skippedTestLines(t, "e2e/tests/details.spec.ts",
		"describe('details', () => {\n  it.skip('loads', () => {})\n})\n"))
	// A reason covers the skip it stands by: not the next skip, not the one
	// after a skip whose title names a ticket.
	assert.Equal(t, []int{3, 4}, skippedTestLines(t, "e2e/tests/suites.spec.ts",
		"// TODO: PROJ-1\ntest.describe.skip('a', () => {})\ntest.describe.skip('b', () => {})\ntest.describe.skip('c', () => {})\n"))
	assert.Equal(t, []int{2}, skippedTestLines(t, "e2e/tests/suites.spec.ts",
		"test.skip('PROJ-7 flaky upstream', () => {})\ntest.skip('checkout', () => {})\n"))
}

// A skip decided at run time adapts to the environment; a skip with a reason
// and a ticket beside it is a decision on record.
func TestSkippedTestTypeScriptAllowed(t *testing.T) {
	assert.Empty(t, skippedTestLines(t, "e2e/tests/security/headers.spec.ts",
		"test('external headers', async ({ page }) => {\n  test.skip(!process.env.EXTERNAL_ENABLED, 'external env not available')\n  test.skip()\n})\n"))
	assert.Empty(t, skippedTestLines(t, "e2e/tests/admin/mfa.spec.ts",
		"// PROJ-372: enable once the auth provider is mocked\ntest.skip('admin MFA requirement', async ({ page }) => {})\n"))
	assert.Empty(t, skippedTestLines(t, "e2e/tests/mfa.spec.ts",
		"// PROJ-372: the auth provider has no sandbox,\n// enable once it is mocked\ntest.skip('admin MFA requirement', async ({ page }) => {})\n"),
		"a comment block above")
	assert.Empty(t, skippedTestLines(t, "web/src/lib/helpers.ts",
		"test.describe.skip('whatever', () => {})\n"), "not a test file")
	assert.Empty(t, skippedTestLines(t, "e2e/tests/notes.spec.ts",
		"// test.describe.skip('commented out', () => {})\nconst s = 'xit(1)'\n"), "comments and strings")
}

// An unconditional t.Skip always skips: the test is dead however it fails.
// A build constraint ignore switches off the whole file.
func TestSkippedTestGo(t *testing.T) {
	assert.Equal(t, []int{4}, skippedTestLines(t, "tests/search_test.go", `package tests

func TestSearch(t *testing.T) {
	t.Skip("SKIP: possible race condition with user creation")
	db := open(t)
	_ = db
}
`))
	assert.Equal(t, []int{5}, skippedTestLines(t, "tests/sub_test.go", `package tests

func TestSub(t *testing.T) {
	t.Run("case", func(t *testing.T) {
		t.SkipNow()
	})
}
`))
	assert.Equal(t, []int{1}, skippedTestLines(t, "calc/calc_test.go", `//go:build ignore

package calc

func TestSomething(t *testing.T) {}
`))
}

func TestSkippedTestGoAllowed(t *testing.T) {
	assert.Empty(t, skippedTestLines(t, "tests/live_test.go", `package tests

func TestLive(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	if os.Getenv("API_KEY") == "" {
		t.Skip("no credentials")
	}
	for _, c := range cases {
		switch c {
		case "x":
			t.Skip("not here")
		}
	}
}
`))
	assert.Empty(t, skippedTestLines(t, "tests/env_test.go", `//go:build integration

package tests

func TestSomething(t *testing.T) {}
`), "an environment tag segments the suite")
	assert.Empty(t, skippedTestLines(t, "tools/gen.go", `//go:build ignore

package main

func main() {}
`), "a generator program kept out of the build is not a test")
}

package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnfalsifiableTestCaseRule_Metadata(t *testing.T) {
	rule := NewUnfalsifiableTestCaseRule()
	assert.Equal(t, "unfalsifiable-test-case", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestUnfalsifiableTestCaseRule_Detection(t *testing.T) {
	rule := NewUnfalsifiableTestCaseRule()
	tests := []struct {
		name       string
		code       string
		expectTest string
	}{
		{
			// Форма balance-split-e2e.spec.ts: страницы такой нет, тест зелёный.
			name: "generic page checks only",
			code: `test('shows both balances', async ({ page }) => {
  await page.goto('/deposits');
  await expect(page).toHaveURL(/deposits/);
  await expect(page.locator('body')).toBeVisible();
});`,
			expectTest: "shows both balances",
		},
		{
			// Форма dashboard-metrics.spec.ts: удалённый эндпоинт засчитывается как рабочий.
			name: "status set accepts both success and failure",
			code: `test('pending withdrawals endpoint answers', async ({ request }) => {
  const resp = await request.get('/api/admin/withdrawals/pending');
  expect([200, 404]).toContain(resp.status());
});`,
			expectTest: "pending withdrawals endpoint answers",
		},
		{
			// «Элементов больше нуля» на отрисованной странице верно всегда.
			name: "count of a generic locator is above zero",
			code: `test('renders something', async ({ page }) => {
  const count = await page.locator('div').count();
  expect(count).toBeGreaterThan(0);
});`,
			expectTest: "renders something",
		},
		{
			// Условие ложно ровно тогда, когда фича сломана.
			name: "every assertion sits behind an optional guard",
			code: `test('withdrawal list loads', async ({ request }) => {
  const resp = await request.get('/api/admin/withdrawals');
  if (resp.ok()) {
    const body = await resp.json();
    expect(body.items.length).toBe(3);
  }
});`,
			expectTest: "withdrawal list loads",
		},
		{
			// Есть хотя бы одна безусловная проверка по существу.
			name: "concrete assertion alongside generic ones",
			code: `test('shows the balance', async ({ page }) => {
  await expect(page.locator('body')).toBeVisible();
  await expect(page.getByTestId('total-balance')).toHaveText('$1 200.00');
});`,
		},
		{
			// Конкретный статус — тест упадёт, если эндпоинт удалят.
			name: "exact status is falsifiable",
			code: `test('endpoint answers', async ({ request }) => {
  const resp = await request.get('/api/admin/withdrawals');
  expect(resp.status()).toBe(200);
});`,
		},
		{
			// Набор без провальных кодов проверяет реальное поведение.
			name: "status set without failure codes",
			code: `test('either page is fine', async ({ request }) => {
  const resp = await request.get('/api/admin/withdrawals');
  expect([200, 204]).toContain(resp.status());
});`,
		},
		{
			// Проверка после guard, но снаружи его тела.
			name: "assertion after the guard block",
			code: `test('withdrawal list loads', async ({ request }) => {
  const resp = await request.get('/api/admin/withdrawals');
  if (resp.ok()) {
    await resp.json();
  }
  expect(resp.status()).toBe(200);
});`,
		},
		{
			// Группа describe сама утверждений не содержит и тестом не считается.
			name: "describe group is not a test",
			code: `test.describe('balances', () => {
  test('shows the balance', async ({ page }) => {
    await expect(page.getByTestId('total')).toHaveText('$1.00');
  });
});`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createUnfalsifiableContext("balance.spec.ts", tt.code)
			violations := rule.AnalyzeFile(ctx)
			if tt.expectTest == "" {
				assert.Empty(t, violations, "ожидалось отсутствие находок: %s", tt.name)
				return
			}
			require.Len(t, violations, 1, "ожидалась одна находка: %s", tt.name)
			assert.Equal(t, "unfalsifiable_test_case", violations[0].Context["pattern"])
			assert.Contains(t, violations[0].Message, tt.expectTest)
		})
	}
}

func TestUnfalsifiableTestCaseRule_NonTestFilesExcluded(t *testing.T) {
	rule := NewUnfalsifiableTestCaseRule()
	code := `test('shows both balances', async ({ page }) => {
  await expect(page.locator('body')).toBeVisible();
});`
	assert.Empty(t, rule.AnalyzeFile(createUnfalsifiableContext("helpers.ts", code)))
	// Go-тесты закрывает tautological-assertion, здесь их разбирать нечем.
	assert.Empty(t, rule.AnalyzeFile(createUnfalsifiableContext("balance_test.go", code)))
}

func createUnfalsifiableContext(path, code string) *core.FileContext {
	return &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   strings.Split(code, "\n"),
		Content: []byte(code),
	}
}

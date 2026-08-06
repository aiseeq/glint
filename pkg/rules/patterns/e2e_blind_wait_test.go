package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func analyzeBlindWait(path, code string) []*core.Violation {
	rule := NewE2EBlindWaitRule()
	return rule.AnalyzeFile(core.NewFileContext("/src/"+path, "/src", []byte(code), core.DefaultConfig()))
}

// Репро из saga: четыре админских спека падали по таймауту networkidle или читали
// страницу до отрисовки данных.
func TestE2EBlindWait_NetworkIdleIsFlagged(t *testing.T) {
	code := `import { test, expect } from '@playwright/test'

test('dashboard renders', async ({ page }) => {
  await page.goto('https://admin.example/dashboard')
  await page.waitForLoadState('networkidle', { timeout: 15000 })
  expect(await page.locator('h1').innerText()).toContain('Обзор')
})
`
	violations := analyzeBlindWait("frontend/e2e/tests/admin/dashboard.spec.ts", code)
	if len(violations) != 1 {
		t.Fatalf("networkidle должен быть найден ровно один раз, получили: %+v", violations)
	}
	if !strings.Contains(violations[0].Message, "networkidle") {
		t.Fatalf("сообщение должно называть networkidle: %s", violations[0].Message)
	}
}

func TestE2EBlindWait_WaitUntilOptionIsFlagged(t *testing.T) {
	code := `test('opens page', async ({ page }) => {
  await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 })
  await page.locator('[data-testid="main"]').waitFor({ state: 'visible' })
})
`
	if got := analyzeBlindWait("frontend/e2e/tests/admin/zoom.spec.ts", code); len(got) != 1 {
		t.Fatalf("waitUntil: 'networkidle' должен быть найден, получили: %+v", got)
	}
}

func TestE2EBlindWait_FixedPauseIsFlagged(t *testing.T) {
	code := `test('cancels batch', async ({ page }) => {
  await page.getByRole('button', { name: 'Отменить' }).click()
  await page.waitForTimeout(1000)
  await expect(page.getByRole('button', { name: 'Отменить' })).toBeHidden()
})
`
	got := analyzeBlindWait("frontend/e2e/tests/admin/gift-codes.spec.ts", code)
	if len(got) != 1 {
		t.Fatalf("waitForTimeout должен быть найден, получили: %+v", got)
	}
	if !strings.Contains(got[0].Message, "fixed time") {
		t.Fatalf("сообщение должно объяснять зависимость от скорости машины: %s", got[0].Message)
	}
}

// Ожидание факта — то, ради чего правило и написано: оно не должно мешать.
func TestE2EBlindWait_WaitingForFactIsClean(t *testing.T) {
	code := `test('redirects anonymous user', async ({ page }) => {
  await page.goto(url + '/analytics')
  await page.waitForURL(/\/onboarding/, { timeout: 15000 })
  await expect(page.getByText('Загрузка')).toHaveCount(0, { timeout: 20000 })
  await page.locator('[data-testid="admin-main-content"]').waitFor({ state: 'visible' })
})
`
	if got := analyzeBlindWait("frontend/e2e/tests/auth/redirect.spec.ts", code); len(got) != 0 {
		t.Fatalf("ожидание конкретного факта не должно флагаться, получили: %+v", got)
	}
}

// Мягкая синхронизация с запасным путём (хелпер forDataSync в saga) — не единственное
// условие готовности, поэтому не находка.
func TestE2EBlindWait_NetworkIdleInsideTryIsAllowed(t *testing.T) {
	code := `export async function forDataSync(page, timeout) {
  try {
    await page.waitForLoadState('networkidle', { timeout: 3000 })
    await page.waitForFunction(() => !document.querySelector('.loading-spinner'), { timeout: 2000 })
  } catch {
    await page.locator('[data-testid="content"]').waitFor({ state: 'visible', timeout })
  }
}
`
	if got := analyzeBlindWait("frontend/e2e/utils/test-stability-helpers.ts", code); len(got) != 0 {
		t.Fatalf("networkidle с явным запасным путём не должен флагаться, получили: %+v", got)
	}
}

// После закрытия try правило снова работает: запасной путь остался позади.
func TestE2EBlindWait_NetworkIdleAfterTryBlockIsFlagged(t *testing.T) {
	code := `export async function ready(page) {
  try {
    await page.waitForLoadState('networkidle', { timeout: 3000 })
  } catch {
    // мягкий путь
  }
  await page.waitForLoadState('networkidle', { timeout: 15000 })
}
`
	if got := analyzeBlindWait("frontend/e2e/utils/ready.ts", code); len(got) != 1 {
		t.Fatalf("жёсткое ожидание после try должно флагаться, получили: %+v", got)
	}
}

// Продакшен-код с той же строкой правилу не интересен: правило про тесты.
func TestE2EBlindWait_ProductionCodeIsOutOfScope(t *testing.T) {
	code := `export async function snapshot(page) {
  await page.waitForLoadState('networkidle')
}
`
	if got := analyzeBlindWait("src/lib/screenshot.ts", code); len(got) != 0 {
		t.Fatalf("не-тестовый код вне области правила, получили: %+v", got)
	}
}

func TestE2EBlindWait_CommentedOutWaitIsIgnored(t *testing.T) {
	code := `test('renders', async ({ page }) => {
  // await page.waitForTimeout(1000)
  await expect(page.getByRole('heading')).toBeVisible()
})
`
	if got := analyzeBlindWait("frontend/e2e/tests/x.spec.ts", code); len(got) != 0 {
		t.Fatalf("закомментированное ожидание не находка, получили: %+v", got)
	}
}

// Репро из saga: стадия e2e_regression регулярно уходила в перезапуск, потому что
// проверка адреса шла до того, как клиентский роутер уводил со страницы.
func TestE2EBlindWait_URLAssertedWithoutWaitingForNavigation(t *testing.T) {
	code := `test('redirects anonymous user', async ({ page }) => {
  await page.goto(url + '/analytics')
  await smartWait.forDataSync()

  const currentUrl = page.url()
  expect(currentUrl).toContain('/onboarding')
})

test('asserts after waiting', async ({ page }) => {
  await page.goto(url + '/analytics')
  await page.waitForURL(/\/onboarding/, { timeout: 15000 })
  expect(page.url()).toContain('/onboarding')
})
`
	got := analyzeBlindWait("frontend/e2e/tests/auth/redirect.spec.ts", code)
	if len(got) != 1 {
		t.Fatalf("адрес, снятый в переменную до ожидания перехода, должен флагаться ровно раз: %+v", got)
	}
	if got[0].Line != 6 {
		t.Fatalf("находка должна указывать на строку проверки, получили строку %d", got[0].Line)
	}
}

func TestE2EBlindWait_DirectURLAssertAfterClickIsFlagged(t *testing.T) {
	code := `test('opens card', async ({ page }) => {
  await page.getByRole('row').first().click()
  expect(page.url()).toContain('/users/card')
})
`
	got := analyzeBlindWait("frontend/e2e/tests/admin/users.spec.ts", code)
	if len(got) != 1 {
		t.Fatalf("проверка нового адреса без ожидания перехода должна флагаться: %+v", got)
	}
	if !strings.Contains(got[0].Message, "without waiting") {
		t.Fatalf("сообщение должно объяснять отсутствие ожидания: %s", got[0].Message)
	}
}

func TestE2EBlindWait_URLAssertAfterWaitForURLIsClean(t *testing.T) {
	code := `test('opens card', async ({ page }) => {
  await page.getByRole('row').first().click()
  await page.waitForURL(/\/users\/card/, { timeout: 10000 })
  expect(page.url()).toContain('/users/card')
})
`
	if got := analyzeBlindWait("frontend/e2e/tests/admin/users.spec.ts", code); len(got) != 0 {
		t.Fatalf("после waitForURL проверка адреса законна: %+v", got)
	}
}

// «Редиректа быть не должно» — ждать нечего, требование waitForURL там бессмысленно.
func TestE2EBlindWait_NegativeURLAssertIsClean(t *testing.T) {
	code := `test('keeps authenticated user on page', async ({ page }) => {
  await page.goto(url + '/analytics')
  expect(page.url()).not.toContain('/onboarding')
})
`
	if got := analyzeBlindWait("frontend/e2e/tests/auth/stay.spec.ts", code); len(got) != 0 {
		t.Fatalf("отрицательная проверка адреса не находка: %+v", got)
	}
}

// Состояние не течёт между кейсами: навигация в предыдущем тесте не делает
// проверку в следующем нарушением.
func TestE2EBlindWait_NavigationStateResetsPerTest(t *testing.T) {
	code := `test('navigates', async ({ page }) => {
  await page.goto(url + '/a')
  await page.waitForURL(/\/a/)
})

test('checks url of already opened page', async ({ page }) => {
  expect(page.url()).toContain('/a')
})
`
	if got := analyzeBlindWait("frontend/e2e/tests/x.spec.ts", code); len(got) != 0 {
		t.Fatalf("состояние навигации должно сбрасываться на границе теста: %+v", got)
	}
}

// «Мы остались на той же странице» — проверка адреса, на который сами и шли:
// перехода тут нет, ждать нечего.
func TestE2EBlindWait_AssertingTheAddressWeNavigatedToIsClean(t *testing.T) {
	code := `test('keeps authenticated user on protected route', async ({ page }) => {
  await page.goto(baseUrl + '/analytics')
  await smartWait.forPageLoad()

  const currentUrl = page.url()
  expect(currentUrl).not.toContain('/onboarding')
  expect(currentUrl).toContain('/analytics')
})
`
	if got := analyzeBlindWait("frontend/e2e/tests/auth/stay.spec.ts", code); len(got) != 0 {
		t.Fatalf("проверка «остались на своей странице» не находка: %+v", got)
	}
}

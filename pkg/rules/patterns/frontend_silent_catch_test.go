package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestFrontendSilentCatchRule(t *testing.T) {
	rule := NewFrontendSilentCatchRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name: "logger only is forbidden",
			code: `try {
  await save()
} catch (err) {
  logger.error('Save failed', err)
}`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 1,
		},
		{
			name: "console only is forbidden",
			code: `try {
  await save()
} catch (err) {
  console.error(err)
}`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 1,
		},
		{
			name: "visible error state is valid",
			code: `try {
  await save()
} catch (err) {
  logger.error('Save failed', err)
  setSaveError('Изменения не сохранены')
}`,
			filename:  "frontend/admin-app/src/app/employees/page.tsx",
			wantCount: 0,
		},
		{
			name: "rethrow is valid",
			code: `try {
  await save()
} catch (err) {
  logger.error('Save failed', err)
  throw err
}`,
			filename:  "frontend/admin-app/src/lib/admin-api.ts",
			wantCount: 0,
		},
		{
			name: "test files are skipped",
			code: `try {
  await save()
} catch (err) {
  console.error(err)
}`,
			filename:  "frontend/admin-app/src/app/employees/page.test.tsx",
			wantCount: 0,
		},
		{
			name: "e2e helpers are skipped",
			code: `try {
  await cleanup()
} catch (err) {
  console.error(err)
}`,
			filename:  "frontend/e2e/utils/auth-helpers.ts",
			wantCount: 0,
		},
		{
			name: "e2e helpers are skipped from frontend root",
			code: `try {
  await cleanup()
} catch (err) {
  console.error(err)
}`,
			filename:  "e2e/utils/auth-helpers.ts",
			wantCount: 0,
		},
		{
			name: "jest setup is skipped",
			code: `try {
  mockFetch()
} catch (err) {
  console.error(err)
}`,
			filename:  "frontend/admin-app/jest.setup.js",
			wantCount: 0,
		},
	}

	tests = append(tests, []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name: "logger call inside a comment is not logging",
			code: `try {
  await save()
} catch (err) {
  // console.error(err) was too noisy
  setSaveError(String(err))
}`,
			filename:  "frontend/src/app/page.tsx",
			wantCount: 0,
		},
		{
			name: "feedback word inside a string is not feedback",
			code: `try {
  await save()
} catch (err) {
  console.error('will throw later', err)
}`,
			filename:  "frontend/src/app/page.tsx",
			wantCount: 1,
		},
	}...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), nil)
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d (%q)", v.Message, v.Line, v.Code)
				}
			}
		})
	}
}

// The finding points at the catch itself, and a brace inside a string neither
// stretches that block nor hides the next catch.
func TestFrontendSilentCatchRuleLines(t *testing.T) {
	code := `export async function load() {
  try {
    await fetchData()
  } catch (e) {
    console.error('failed', e)
    report(e)
    cleanup()
  }
}

export async function save() {
  try {
    await put()
  } catch (e) {
    console.error('bad brace {', e)
  }
}

export function Page() {
  const [error, setError] = useState('')
  async function other() {
    try { await x() } catch (e) { setError(String(e)) }
  }
  return null
}`
	ctx := core.NewFileContext("frontend/src/catch.tsx", ".", []byte(code), nil)
	violations := NewFrontendSilentCatchRule().AnalyzeFile(ctx)
	var lines []int
	for _, v := range violations {
		lines = append(lines, v.Line)
		if !strings.Contains(v.Code, "catch") {
			t.Errorf("line %d: code %q is not the catch line", v.Line, v.Code)
		}
	}
	if len(lines) != 2 || lines[0] != 4 || lines[1] != 14 {
		t.Errorf("violations at lines %v, want [4 14]", lines)
	}
}

// A file logger from createLogger is a logger like console: a catch that
// only calls log.error is silent. A catch that hands the error text back,
// calls the caller's handler or reloads, or guards a best-effort side
// channel (storage, analytics, consent) is not.
func TestFrontendSilentCatchNamedLogger(t *testing.T) {
	code := `const log = createLogger('settings')

export async function save() {
  try {
    await put()
  } catch (e) {
    log.error('save failed', e)
  }
  load().catch(e => log.error('load failed', e))
}

export function describe(err: unknown): string {
  try {
    return explain(err)
  } catch (e) {
    log.error('explain failed', e)
    return errorText(e)
  }
}

export async function refresh(onUnknown: () => void) {
  try {
    await sync()
  } catch (e) {
    log.error('sync failed', e)
    onUnknown()
  }
  try {
    await renew()
  } catch (e) {
    log.error('renew failed', e)
    window.location.reload()
  }
}

export function remember(key: string, value: string) {
  try {
    localStorage.setItem(key, value)
  } catch (e) {
    log.error('storage unavailable', e)
  }
}
`
	ctx := core.NewFileContext("frontend/src/lib/settings.ts", ".", []byte(code), nil)
	var lines []int
	for _, v := range NewFrontendSilentCatchRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	if len(lines) != 2 || lines[0] != 6 || lines[1] != 9 {
		t.Fatalf("want findings on lines 6 and 9, got %v", lines)
	}
}

// The ways a catch shows the failure or hands it back that the file loggers
// brought up: an error setter ending in Err, a screen switch, a message
// helper, a failure flag or key returned, a failed result, an error state
// with the literal in it; and a sign-out, best effort by design.
func TestFrontendSilentCatchHandledShapes(t *testing.T) {
	code := `const log = createLogger('cabinet')

async function a() { try { await x() } catch (err) { log.error('a', err); setFormErr(createErrorOf(err)) } }
async function b() { try { await x() } catch (err) { log.error('b', err); setShowMFAScreen(true) } }
async function c() { try { await x() } catch (err) { log.error('c', err); say(errorText(err, 'e.hold')) } }
async function d() { try { await x() } catch (err) { log.error('d', err); return false } }
async function e() { try { await x() } catch (err) { log.error('e', err); return 'lo.e.send' } }
async function f() { try { await x() } catch (error) { log.error('f', error); return ResultFactory.failure(wrap(error)) } }
async function g() { try { await x() } catch (err) { log.error('g', err); setCache(prev => ({ ...prev, status: 'error' })) } }
async function h() { try { await signOut() } catch (err) { log.error('h', err) } }
async function i() { try { await x() } catch (err) { log.error('i', err); return null } }
`
	ctx := core.NewFileContext("frontend/src/lib/cabinet.ts", ".", []byte(code), nil)
	var lines []int
	for _, v := range NewFrontendSilentCatchRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	if len(lines) != 1 || lines[0] != 11 {
		t.Fatalf("want one finding on line 11, got %v", lines)
	}
	analytics := core.NewFileContext("frontend/src/lib/analytics.ts", ".", []byte(`const log = createLogger('analytics')
async function send() { try { await post() } catch (err) { log.error('send', err) } }
`), nil)
	if found := NewFrontendSilentCatchRule().AnalyzeFile(analytics); len(found) != 0 {
		t.Fatalf("an analytics module is best effort, got %d findings", len(found))
	}
}

// A service worker registration is a side channel however its chain is
// broken across lines.
func TestFrontendSilentCatchSideChannelChain(t *testing.T) {
	code := `const log = createLogger('pwa')
export function register() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker
      .register('/sw.js')
      .then((registration) => {
        current = registration
      })
      .catch((error) => {
        log.error('Service worker registration failed', error)
      })
  }
}
`
	ctx := core.NewFileContext("frontend/src/lib/pwa.tsx", ".", []byte(code), nil)
	if found := NewFrontendSilentCatchRule().AnalyzeFile(ctx); len(found) != 0 {
		t.Fatalf("a service worker registration is best effort, got line %d", found[0].Line)
	}
}

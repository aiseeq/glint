package qarules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
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
			// Заголовок вкладки ставит приложение: другой заголовок роняет тест.
			name: "page title is produced by the app",
			code: `test('keeps the title', async ({ page }) => {
  await page.goto('/analytics/');
  await expect(page).toHaveTitle("Account — dashboard");
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

	tests = append(tests, []struct {
		name       string
		code       string
		expectTest string
	}{
		{
			// expect.soft — та же проверка, только не останавливает тест.
			name: "soft assertion on a specific element is an assertion",
			code: `test('soft assertions only', async ({ page }) => {
  await page.goto('/orders')
  await expect.soft(page.getByText('Order #1')).toBeVisible()
})`,
		},
		{
			name: "polled assertion is an assertion",
			code: `test('poll assertion', async ({ page }) => {
  await page.goto('/orders')
  await expect.poll(async () => (await page.request.get('/api/orders')).status()).toBe(200)
})`,
		},
		{
			// Однострочный тест закрывается на своей строке и не поглощает следующий.
			name: "one-line test does not swallow the next one",
			code: `test('real', async ({ page }) => { expect(await page.title()).toBe('Orders') })
test('empty page', async ({ page }) => { await expect(page.locator('body')).toBeVisible() })`,
			expectTest: "empty page",
		},
		{
			// if (row) ложно ровно тогда, когда строки нет — проверка до дела не доходит.
			name: "truthiness guard hides the only assertion",
			code: `test('guarded by truthy value', async ({ page }) => {
  const row = await page.$('tr')
  if (row) {
    expect(await row.textContent()).toBe('x')
  }
})`,
			expectTest: "guarded by truthy value",
		},
		{
			name: "comparison is not a truthiness guard",
			code: `test('threshold', async ({ page }) => {
  const count = await readCount(page)
  if (count > limit) {
    expect(count).toBe(3)
  }
})`,
		},
	}...)

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

// Спек без единого expect: HTTP-запрос сам по себе не падает на 4xx, поэтому такой
// тест сообщает только о том, что код не бросил исключение.
func TestUnfalsifiableTestCase_NoAssertionsAtAll(t *testing.T) {
	violations := NewUnfalsifiableTestCaseRule().AnalyzeFile(createUnfalsifiableContext("api.spec.ts", `import { test } from '@playwright/test'

test('reads health', async ({ request }) => {
  const response = await request.get('/api/health')
  console.log(response.status())
})
`))

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "no assertions at all")
	assert.Equal(t, "0", violations[0].Context["assertions"])
}

// Клик по несуществующему элементу роняет тест сам — такой спек находкой быть не должен.
func TestUnfalsifiableTestCase_InteractionCanFail(t *testing.T) {
	violations := NewUnfalsifiableTestCaseRule().AnalyzeFile(createUnfalsifiableContext("menu.spec.ts", `import { test } from '@playwright/test'

test('opens menu', async ({ page }) => {
  await page.goto('/dashboard')
  await page.locator('[data-testid="menu"]').click()
})
`))

	assert.Empty(t, violations)
}

// A handler test asserts the page holds a CSS class that the shared layout's
// stylesheet names on every page: the check passes whether the error block
// is rendered or not. A marker only the page itself renders is left alone.
func TestUnfalsifiableTestCase_GoAssertsUbiquitousMarker(t *testing.T) {
	sources := map[string]string{
		"admin/templates/layout.html": `<html><head><style>
    .callout-error { border-left-color: #ff4136; }
</style></head><body><nav>Transactions</nav>{{template "content" .}}</body></html>
`,
		"admin/templates/channels.html": `{{define "content"}}<article class="callout callout-error">{{.Error}}</article>{{end}}
`,
		"admin/channels_test.go": `package admin

func TestChannelsRejectsCountry(t *testing.T) {
	body := render(t)
	if !strings.Contains(body, "callout-error") {
		t.Fatal("expected an error")
	}
	if !strings.Contains(body, "<article class=\"callout callout-error\">") {
		t.Fatal("expected the error block")
	}
	assert.Contains(t, body, "Transactions")
}
`,
	}
	root, _ := rulestest.Module(t, sources)
	var files []*core.FileContext
	for _, name := range []string{"admin/channels_test.go", "admin/templates/channels.html", "admin/templates/layout.html"} {
		file, err := core.NewFileContextChecked(filepath.Join(root, name), root, []byte(sources[name]), core.DefaultConfig())
		require.NoError(t, err)
		if strings.HasSuffix(name, ".go") {
			fset := token.NewFileSet()
			syntax, err := parser.ParseFile(fset, file.Path, sources[name], parser.ParseComments)
			require.NoError(t, err)
			file.SetGoAST(fset, syntax)
		}
		files = append(files, file)
	}
	rule := NewUnfalsifiableTestCaseRule()
	rule.UseProjectFiles(files)
	var found []string
	for _, file := range files {
		found = append(found, patterntest.FoundLines(rule.AnalyzeFile(file))...)
	}
	assert.ElementsMatch(t, []string{"admin/channels_test.go:5", "admin/channels_test.go:11"}, found)
}

func TestUnfalsifiableTestCase_GoBodyOriginConservative(t *testing.T) {
	cases := []struct {
		name, decl string
		want       bool
	}{
		{"literal", `func probe() { x := "text"; strings.Contains(x, "shared-marker") }`, true},
		{"non-string-literal", `func probe() { x := 42; strings.Contains(x, "shared-marker") }`, false},
		{"non-builder-string-method", `type text string; func (text) String() string { return "plain" }; func probe() { var b text = "plain"; strings.Contains(b.String(), "shared-marker") }`, false},
		{"literal-concat", `func probe() { x := "a" + "b"; strings.Contains(x, "shared-marker") }`, true},
		{"multiple-literal-writes", `func probe() { var x string; x = "a"; x = "b"; strings.Contains(x, "shared-marker") }`, true},
		{"scan", `func probe(row interface{ Scan(...any) error }) { var x string; row.Scan(&x); strings.Contains(x, "shared-marker") }`, true},
		{"read-file", `func probe() { x, _ := os.ReadFile("x"); strings.Contains(string(x), "shared-marker") }`, true},
		{"read-file-copy-mutated", `func probe(body []byte) { x, _ := os.ReadFile("x"); copy(x, body); strings.Contains(string(x), "shared-marker") }`, false},
		{"read-file-reader-mutated", `func probe(body []byte) { x, _ := os.ReadFile("x"); source := bytes.NewReader(body); source.Read(x); strings.Contains(string(x), "shared-marker") }`, false},
		{"read-file-slice-aliased", `func probe(body []byte) { x, _ := os.ReadFile("x"); view := x[:]; copy(view, body); strings.Contains(string(x), "shared-marker") }`, false},
		{"read-file-index-mutated", `func probe() { x, _ := os.ReadFile("x"); x[0] = 1; strings.Contains(string(x), "shared-marker") }`, false},
		{"read-file-multi-result", `func probe() { data, err := disk.ReadFile("x"); strings.Contains(fmt.Sprint(err), "shared-marker"); _ = data }`, true},
		{"ioutil-read-file", `func probe() { x, _ := ioutil.ReadFile("x"); strings.Contains(string(x), "shared-marker") }`, true},
		{"sprint-literals", `func probe() { x := fmt.Sprintf("%s", "local"); strings.Contains(x, "shared-marker") }`, true},
		{"sprint-values", `func probe() { x := fmt.Sprint(12, "local"); strings.Contains(x, "shared-marker") }`, true},
		{"fmt-import-alias", `func probe() { x := printf.Sprintf("%s", "local"); strings.Contains(x, "shared-marker") }`, true},
		{"os-import-alias", `func probe() { x, _ := disk.ReadFile("x"); strings.Contains(string(x), "shared-marker") }`, true},
		{"builder-literal", `func probe() { var b strings.Builder; b.WriteString("local"); strings.Contains(b.String(), "shared-marker") }`, true},
		{"builder-parens", `func probe() { var b strings.Builder; (b).WriteString("local"); strings.Contains((b).String(), "shared-marker") }`, true},
		{"builder-byte-rune-literals", `func probe() { var b strings.Builder; b.WriteByte(60); b.WriteRune('x'); strings.Contains(b.String(), "shared-marker") }`, true},
		{"helper-result", `func probe() { x := render(); strings.Contains(x, "shared-marker") }`, false},
		{"parameter", `func probe(x string) { strings.Contains(x, "shared-marker") }`, false},
		{"named-result", `func probe() (x string) { x = "local"; strings.Contains(x, "shared-marker"); return }`, false},
		{"defaulted-parameter", `func probe(x string) { if x == "" { x = "fallback" }; strings.Contains(x, "shared-marker") }`, false},
		{"global", `var global = "local"; func probe() { strings.Contains(global, "shared-marker") }`, false},
		{"shadowed-inner-block", `var x = "body"; func probe() { { x := "local"; _ = x }; strings.Contains(x, "shared-marker") }`, false},
		{"shadowed-local-name", `func probe() { y := "body"; { y := "plain"; _ = y }; strings.Contains(y, "shared-marker") }`, false},
		{"closure-parameter-shadow", `func probe() { y := "body"; func(y string) { strings.Contains(y, "shared-marker") }("plain") }`, false},
		{"function-literal-body-write", `func probe(w *httptest.ResponseRecorder) { x := "plain"; f := func() { x = w.Body.String() }; f(); strings.Contains(x, "shared-marker") }`, false},
		{"outer-os-shadow-in-closure", `func probe() { os := localOS(); data, _ := os.ReadFile("x"); func() { strings.Contains(string(data), "shared-marker") }() }`, false},
		{"outer-string-shadow-in-closure", `func probe(w *httptest.ResponseRecorder, data []byte) { string := func([]byte) string { return w.Body.String() }; func() { strings.Contains(string(data), "shared-marker") }() }`, false},
		{"body-after-literal", `func probe(w *httptest.ResponseRecorder) { x := "local"; (x) = w.Body.String(); strings.Contains(x, "shared-marker") }`, false},
		{"address-escape", `func probe(data []byte) { x := "local"; json.Unmarshal(data, &x); strings.Contains(x, "shared-marker") }`, false},
		{"helper-address-escape", `func probe(resp *http.Response) { x := "local"; readInto(resp, &x); strings.Contains(x, "shared-marker") }; func readInto(resp *http.Response, s *string) {}`, false},
		{"scan-then-body", `func probe(row interface{ Scan(...any) error }, w *httptest.ResponseRecorder) { var x string; row.Scan(&x); x = w.Body.String(); strings.Contains(x, "shared-marker") }`, false},
		{"multi-result", `func probe() { var code, page = doReq(); _, _ = code, page; strings.Contains(page, "shared-marker") }`, false},
		{"short-multi-result", `func probe() { code, page := doReq(); _, _ = code, page; strings.Contains(page, "shared-marker") }`, false},
		{"short-reuse", `func probe() { page := "literal"; page, err := doReq(); _, _ = page, err; strings.Contains(page, "shared-marker") }`, false},
		{"builder-copy", `func probe(resp *http.Response) { var b strings.Builder; io.Copy(&b, resp.Body); strings.Contains(b.String(), "shared-marker") }`, false},
		{"builder-address-escape", `func probe() { var b strings.Builder; b.WriteString("plain"); keepBuilder(&b); strings.Contains(b.String(), "shared-marker") }`, false},
		{"builder-template", `func probe(tmpl *template.Template) { var b strings.Builder; tmpl.ExecuteTemplate(&b, "page", nil); strings.Contains(b.String(), "shared-marker") }`, false},
		{"builder-body-write", `func probe(w *httptest.ResponseRecorder) { var b strings.Builder; b.WriteString(w.Body.String()); strings.Contains(b.String(), "shared-marker") }`, false},
		{"builder-parens-body-write", `func probe(w *httptest.ResponseRecorder) { var b strings.Builder; (b).WriteString(w.Body.String()); strings.Contains((b).String(), "shared-marker") }`, false},
		{"builder-method-value", `func probe() { var b strings.Builder; write := (b).WriteString; write("local"); strings.Contains(b.String(), "shared-marker") }`, false},
		{"builder-write-body", `func probe(w *httptest.ResponseRecorder) { var b strings.Builder; b.Write(w.Body); strings.Contains(b.String(), "shared-marker") }`, false},
		{"buffer", `func probe(resp *http.Response) { var b bytes.Buffer; io.Copy(&b, resp.Body); strings.Contains(b.String(), "shared-marker") }`, false},
		{"body-concat", `func probe(w *httptest.ResponseRecorder) { x := "<p>" + w.Body.String(); strings.Contains(x, "shared-marker") }`, false},
		{"sprintf-body", `func probe(w *httptest.ResponseRecorder) { x := fmt.Sprintf("%s", w.Body); strings.Contains(x, "shared-marker") }`, false},
		{"pointer-write", `func probe(w *httptest.ResponseRecorder) { x := "local"; p := &x; *p = w.Body.String(); strings.Contains(x, "shared-marker") }`, false},
		{"closure-write", `func probe(w *httptest.ResponseRecorder) { x := "local"; t.Run("x", func(t *testing.T) { x = w.Body.String() }); strings.Contains(x, "shared-marker") }`, false},
		{"nested-closure-write", `func probe(w *httptest.ResponseRecorder) { x := "local"; t.Run("a", func(t *testing.T) { t.Run("b", func(t *testing.T) { x = w.Body.String() }) }); strings.Contains(x, "shared-marker") }`, false},
		{"range-assignment", `func probe(pages []string) { x := "local"; for _, x = range pages {}; strings.Contains(x, "shared-marker") }`, false},
		{"range-short-declare", `func probe(pages []string) { x := "local"; for _, x := range pages { strings.Contains(x, "shared-marker") } }`, false},
		{"write-cycle", `func probe() { x := "local"; x = x; strings.Contains(x, "shared-marker") }`, false},
		{"local-os-name", `func probe() { os := makeOS(); x, _ := os.ReadFile("x"); strings.Contains(string(x), "shared-marker") }`, false},
		{"builder-method-value-argument", `func probe(w *httptest.ResponseRecorder) { var b strings.Builder; b.WriteString("plain"); apply(b.WriteString, w.Body.String()); strings.Contains(b.String(), "shared-marker") }`, false},
		{"fmt-sscan-is-not-scan", `func probe(w *httptest.ResponseRecorder) { x := "plain"; _, _ = fmt.Sscan(w.Body.String(), &x); strings.Contains(x, "shared-marker") }`, false},
		{"shadowed-string-function", `func probe(w *httptest.ResponseRecorder) { string := func(s string) string { return w.Body.String() }; x := string("plain"); strings.Contains(x, "shared-marker") }`, false},
		{"package-level-string-shadow", `var string = func(b []byte) string { return "" }; func probe() { raw, _ := os.ReadFile("x"); strings.Contains(string(raw), "shared-marker") }`, false},
		{"unknown-declaration", `func probe() { var x string; strings.Contains(x, "shared-marker") }`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.want, bodyOriginSubjectKnown(t, tc.decl)) })
	}
}

func bodyOriginSubjectKnown(t *testing.T, declaration string) bool {
	t.Helper()
	src := `package sample
import ("bytes"; "fmt"; printf "fmt"; "io"; "io/ioutil"; "net/http";
"net/http/httptest"; "os"; disk "os"; "strings"; str "strings"; "encoding/json"; "html/template"; "testing")
func render() string { return "" }
func doReq() (int, string) { return 0, "" }
func apply(f func(string) (int, error), s string) { _, _ = f(s) }
func localOS() interface{ ReadFile(string) ([]byte, error) } { return nil }
` + declaration
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample_test.go", src, parser.SkipObjectResolution|parser.ParseComments)
	require.NoError(t, err)
	var fn *ast.FuncDecl
	var subject, marker ast.Expr
	ast.Inspect(file, func(n ast.Node) bool {
		if f, ok := n.(*ast.FuncDecl); ok && f.Name.Name == "probe" {
			fn = f
		}
		if call, ok := n.(*ast.CallExpr); ok {
			s, m, found := bodyMarkerArgs(call, bodyPackages(file).strings)
			if found {
				subject, marker = s, m
			}
		}
		return true
	})
	require.NotNil(t, fn)
	require.NotNil(t, subject)
	require.NotNil(t, marker)
	index := buildBodyOriginIndex(file, fn.Type, fn.Body, bodyPackages(file), nil)

	return index.isNonBody(subject)
}

func TestUnfalsifiableTestCase_GoBodyOriginSscanIsNotScan(t *testing.T) {
	src := `package sample
import "fmt"
func probe() { fmt.Sscan("plain") }`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample_test.go", src, parser.SkipObjectResolution)
	require.NoError(t, err)
	var call *ast.CallExpr
	ast.Inspect(file, func(n ast.Node) bool {
		if candidate, ok := n.(*ast.CallExpr); ok {
			call = candidate
		}
		return true
	})
	require.NotNil(t, call)
	index := buildBodyOriginIndex(file, nil, &ast.BlockStmt{}, bodyPackages(file), nil)
	assert.False(t, index.isScanCall(call))
}

func TestUnfalsifiableTestCase_GoBodyOriginShadowedStringsContains(t *testing.T) {
	src := `package sample
import "strings"
type fake struct{}
func (fake) Contains(string, string) bool { return false }
func probe() { strings := fake{}; strings.Contains("plain", "shared-marker") }`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample_test.go", src, parser.SkipObjectResolution)
	require.NoError(t, err)
	var fn *ast.FuncDecl
	var check *ast.CallExpr
	ast.Inspect(file, func(n ast.Node) bool {
		if f, ok := n.(*ast.FuncDecl); ok && f.Name.Name == "probe" {
			fn = f
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if _, _, found := bodyMarkerArgs(call, bodyPackages(file).strings); found {
				check = call
			}
		}
		return true
	})
	require.NotNil(t, fn)
	require.NotNil(t, check)
	index := buildBodyOriginIndex(file, fn.Type, fn.Body, bodyPackages(file), nil)
	assert.True(t, index.shadowsStringsContains(check))
}

func TestUnfalsifiableTestCase_GoBodyOriginMultiResultKeepsCall(t *testing.T) {
	src := `package sample
import "strings"
func doReq() (int, string) { return 0, "" }
func probe() { var code, page = doReq(); _, _ = code, page; strings.Contains(page, "shared-marker") }`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample_test.go", src, parser.SkipObjectResolution)
	require.NoError(t, err)
	var fn *ast.FuncDecl
	var subject ast.Expr
	ast.Inspect(file, func(n ast.Node) bool {
		if f, ok := n.(*ast.FuncDecl); ok && f.Name.Name == "probe" {
			fn = f
		}
		if call, ok := n.(*ast.CallExpr); ok {
			s, _, found := bodyMarkerArgs(call, bodyPackages(file).strings)
			if found {
				subject = s
			}
		}
		return true
	})
	require.NotNil(t, fn)
	index := buildBodyOriginIndex(file, fn.Type, fn.Body, bodyPackages(file), nil)
	assert.False(t, index.isNonBody(subject))
}

func BenchmarkUnfalsifiableTestCase_GoBodyOriginChecks(b *testing.B) {
	for _, count := range []int{2000, 8000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			var source strings.Builder
			source.WriteString("package sample\nimport \"strings\"\nfunc probe(x string) {\n")
			for range count {
				source.WriteString("strings.Contains(x, \"shared-marker\")\n")
			}
			source.WriteString("}\n")
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "sample_test.go", source.String(), parser.SkipObjectResolution)
			if err != nil {
				b.Fatal(err)
			}
			ctx := &core.FileContext{Path: "/project/sample_test.go", RelPath: "sample_test.go", GoAST: file, GoFileSet: fset}
			rule := NewUnfalsifiableTestCaseRule()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				analyzeGoBodyMarkerCalls(rule, ctx, ".shared-marker { color: red }")
			}
		})
	}
}

// A Go file of the package that does not parse, left out of the walk, may
// declare any name: the check of such a name stays a finding, and the
// unreadable file is not an error of the run.
func TestUnfalsifiableTestCase_GoMarkerUnparsedPackageFile(t *testing.T) {
	sources := map[string]string{
		"static/app.css": ".callout-error { color: red; }\n",
		"editor/page_test.go": `package editor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVariableOfUnparsedFile(t *testing.T) {
	fillPage()
	assert.Contains(t, lastBody, "callout-error") // WANT
	{
		lastBody := "plain"
		_ = lastBody
	}
}

func TestLocalDeclaredFirst(t *testing.T) {
	page := "plain"
	assert.Contains(t, page, "callout-error")
}
`,
	}
	unwalked := map[string]string{
		"editor/broken.go": `package editor

var lastBody string

func fillPage() { lastBody = "x" +
`,
	}
	assertProjectOriginFindings(t, sources, unwalked)
}

// In a file with a dot-import a name declared in the function only after the
// check is still the imported one where the check reads it.
func TestUnfalsifiableTestCase_GoMarkerDotImportDeclaredAfterCheck(t *testing.T) {
	sources := map[string]string{
		"static/app.css": ".callout-error { color: red; }\n",
		"editor/dot_test.go": `package editor

import (
	"testing"

	. "example.com/fixtures"
	"github.com/stretchr/testify/assert"
)

func TestDotImportedDeclaredAfter(t *testing.T) {
	Serve()
	assert.Contains(t, Page, "callout-error") // WANT
	Page := "plain"
	_ = Page
}
`,
	}
	assertProjectOriginFindings(t, sources, nil)
}

// Without a shared layout or stylesheet no body check is compared, so the
// package files are not read from disk.
func TestUnfalsifiableTestCase_GoMarkerNoSharedPageSkipsDisk(t *testing.T) {
	root, _ := rulestest.Module(t, map[string]string{
		"editor/page_test.go": "package editor\n",
		"editor/broken.go":    "package editor\nfunc (\n",
	})
	file, err := core.NewFileContextChecked(filepath.Join(root, "editor/page_test.go"), root, []byte("package editor\n"), core.DefaultConfig())
	require.NoError(t, err)
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, file.Path, "package editor\n", parser.SkipObjectResolution)
	require.NoError(t, err)
	file.SetGoAST(fset, syntax)
	rule := NewUnfalsifiableTestCaseRule()
	rule.UseProjectFiles([]*core.FileContext{file})
	assert.Empty(t, rule.packageNamesByDir)
	assert.Empty(t, rule.unknownPackageDirs)
	assert.Empty(t, rule.AnalyzeFile(file))
}

package qarules

import (
	"testing"
)

// A marker of the shared stylesheet found in a value that is not a response
// body — a database column, a file, a string the test built — says nothing
// about a rendered page. A body, or a value of unknown origin such as a
// helper's result, is still checked.
func TestUnfalsifiableTestCase_GoMarkerSubjectOrigin(t *testing.T) {
	sources := map[string]string{
		"static/app.css": "[data-text-size] { font-size: 1rem; }\n.callout-error { color: red; }\n",
		"editor/format_test.go": `package editor

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStoredLiteral(t *testing.T) {
	var stored string
	stored = ` + "`" + `<span data-text-size="16">red</span>` + "`" + `
	if !strings.Contains(stored, "data-text-size") {
		t.Fatal("lost")
	}
	assert.Contains(t, "<b data-text-size>", "data-text-size")
}

func TestScannedColumn(t *testing.T, db *sql.DB) {
	var insight string
	if err := db.QueryRow("SELECT insight FROM t").Scan(&insight); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(insight, "data-text-size") {
		t.Fatal("lost")
	}
}

func TestFileAndBuilt(t *testing.T) {
	raw, _ := os.ReadFile("fixture.html")
	assert.Contains(t, string(raw), "data-text-size")
	var b strings.Builder
	b.WriteString("<i data-text-size>")
	assert.Contains(t, b.String(), "callout-error")
	msg := fmt.Sprintf("<p class=%q>", "callout-error")
	assert.Contains(t, msg, "callout-error")
}

func TestRecorder(t *testing.T, h http.Handler) {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(w.Body.String(), "data-text-size") { // WANT
		t.Fatal("no size")
	}
	page := w.Body.String()
	assert.Contains(t, page, "callout-error") // WANT
}

func TestResponse(t *testing.T, url string) {
	resp, _ := http.Get(url)
	data, _ := io.ReadAll(resp.Body)
	body := string(data)
	if !strings.Contains(body, "callout-error") { // WANT
		t.Fatal("no error")
	}
}

func TestHelper(t *testing.T) {
	html := render(t)
	assert.Contains(t, html, "data-text-size") // WANT
}

func checkPage(t *testing.T, page string) {
	assert.Contains(t, page, "callout-error") // WANT
}

func render(t *testing.T) string { return "" }

// Review round 1: a value that starts as a literal but takes the body later
// is the body.
func TestTakesBodyLater(t *testing.T, w *httptest.ResponseRecorder, resp *http.Response, data []byte) {
	page := "<none>"
	_ = json.Unmarshal(data, &page)
	assert.Contains(t, page, "callout-error") // WANT
	other := ""
	readInto(resp, &other)
	assert.Contains(t, other, "callout-error") // WANT
	inner := ""
	t.Run("x", func(t *testing.T) { inner = w.Body.String() })
	assert.Contains(t, inner, "callout-error") // WANT
	var copied strings.Builder
	_, _ = io.Copy(&copied, resp.Body)
	assert.Contains(t, copied.String(), "callout-error") // WANT
	var rendered strings.Builder
	_ = tmpl.ExecuteTemplate(&rendered, "page", nil)
	assert.Contains(t, rendered.String(), "callout-error") // WANT
	assert.Contains(t, fmt.Sprintf("%s", w.Body), "callout-error") // WANT
	var code, fetched = doReq()
	_ = code
	if fetched == "" {
		fetched = "<empty>"
	}
	assert.Contains(t, fetched, "callout-error") // WANT
	held := ""
	p := &held
	*p = w.Body.String()
	assert.Contains(t, held, "callout-error") // WANT
}

var sharedPage = "<none>"

func TestSharedLiteral(t *testing.T) {
	assert.Contains(t, sharedPage, "callout-error") // WANT
}

func TestSharedBody(t *testing.T, data []byte) {
	_ = json.Unmarshal(data, &sharedPage)
}

func defaulted(t *testing.T, page string) {
	if page == "" {
		page = "<empty>"
	}
	assert.Contains(t, page, "callout-error") // WANT
}

func readInto(resp *http.Response, s *string) {}

func doReq() (int, string) { return 0, "" }

var tmpl *template.Template

// Review round 2: a name resolves to the declaration in scope at the check,
// not to any declaration of that name in the function.
func TestInnerShadowOfShared(t *testing.T) {
	assert.Contains(t, sharedPage, "callout-error") // WANT
	if len(sharedPage) > 0 {
		sharedPage := "<none>"
		_ = sharedPage
	}
}

func TestDeclaredAfterCheck(t *testing.T) {
	assert.Contains(t, sharedPage, "callout-error") // WANT
	sharedPage := "<none>"
	_ = sharedPage
}

func TestCapturedBody(t *testing.T, w *httptest.ResponseRecorder) {
	body := w.Body.String()
	t.Run("x", func(t *testing.T) {
		assert.Contains(t, body, "callout-error") // WANT
		for i := 0; i < 1; i++ {
			body := "<none>"
			_ = body
		}
	})
	t.Run("a", func(t *testing.T) {
		t.Run("b", func(t *testing.T) {
			page := w.Body.String()
			assert.Contains(t, page, "callout-error") // WANT
		})
	})
}

func TestBuilderAndParens(t *testing.T, w *httptest.ResponseRecorder) {
	var viaValue strings.Builder
	write := viaValue.WriteString
	_, _ = write(w.Body.String())
	assert.Contains(t, viaValue.String(), "callout-error") // WANT
	var paren strings.Builder
	(paren).WriteString(w.Body.String())
	assert.Contains(t, paren.String(), "callout-error") // WANT
	x := "<none>"
	(x) = w.Body.String()
	assert.Contains(t, x, "callout-error") // WANT
}

type fakeOS struct{ w *httptest.ResponseRecorder }

func (f fakeOS) ReadFile(string) ([]byte, error) { return f.w.Body.Bytes(), nil }

func TestLocalNamedLikePackage(t *testing.T, w *httptest.ResponseRecorder) {
	os := fakeOS{w}
	data, _ := os.ReadFile("x")
	assert.Contains(t, string(data), "callout-error") // WANT
}

func TestWriteCycle(t *testing.T, w *httptest.ResponseRecorder) {
	a := "<a>"
	b := a
	a = b
	a = w.Body.String()
	assert.Contains(t, b, "callout-error") // WANT
}

// Review round 1: what the origin check must still tell apart.
func TestOriginEdges(t *testing.T, w *httptest.ResponseRecorder, resp *http.Response, db *sql.DB) {
	legacy, _ := ioutil.ReadFile("fixture.html")
	assert.Contains(t, string(legacy), "callout-error")
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, resp.Body)
	assert.Contains(t, buf.String(), "callout-error") // WANT
	joined := "<p>" + w.Body.String()
	assert.Contains(t, joined, "callout-error") // WANT
	var col string
	_ = db.QueryRow("SELECT c FROM t").Scan(&col)
	col = w.Body.String()
	assert.Contains(t, col, "callout-error") // WANT
	var first, second = "<none>", w.Body.String()
	_ = first
	assert.Contains(t, second, "callout-error") // WANT
	var built strings.Builder
	built.WriteString(w.Body.String())
	assert.Contains(t, built.String(), "callout-error") // WANT
}
`,
	}
	assertOriginFindings(t, "editor/format_test.go", sources)
}

// assertOriginFindings runs the rule over a Go test file and the shared
// stylesheet and checks it reports exactly the lines marked // WANT.
func assertOriginFindings(t *testing.T, goFile string, sources map[string]string) {
	t.Helper()
	assertProjectOriginFindings(t, map[string]string{goFile: sources[goFile], "static/app.css": sources["static/app.css"]}, nil)
}

// A name in a write or a builder argument is the variable its own scope
// sees, not the one visible where the value is checked.
func TestUnfalsifiableTestCase_GoMarkerSubjectOriginWriteScope(t *testing.T) {
	sources := map[string]string{
		"static/app.css": "[data-text-size] { font-size: 1rem; }\n.callout-error { color: red; }\n",
		"editor/scope_test.go": `package editor

import (
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type text = string

func apply(f func(string) (int, error), s string) { _, _ = f(s) }

func TestBlockShadowWrite(t *testing.T, w *httptest.ResponseRecorder) {
	y := "plain"
	var x string
	{
		y := w.Body.String()
		x = y
	}
	_ = y
	assert.Contains(t, x, "callout-error") // WANT
}

func TestRangeShadowWrite(t *testing.T, w *httptest.ResponseRecorder) {
	y := "plain"
	var x string
	for _, y := range []string{w.Body.String()} {
		x = y
	}
	_ = y
	assert.Contains(t, x, "callout-error") // WANT
}

func TestIfInitShadowWrite(t *testing.T, w *httptest.ResponseRecorder) {
	y := "plain"
	var x string
	if y := w.Body.String(); y != "" {
		x = y
	}
	_ = y
	assert.Contains(t, x, "callout-error") // WANT
}

func TestSwitchInitShadowWrite(t *testing.T, w *httptest.ResponseRecorder) {
	y := "plain"
	var x string
	switch y := w.Body.String(); {
	default:
		x = y
	}
	_ = y
	assert.Contains(t, x, "callout-error") // WANT
}

func TestSelectShadowWrite(t *testing.T, w *httptest.ResponseRecorder) {
	y := "plain"
	var x string
	ch := make(chan string, 1)
	ch <- w.Body.String()
	select {
	case y := <-ch:
		x = y
	}
	_ = y
	assert.Contains(t, x, "callout-error") // WANT
}

func TestClosureParamWrite(t *testing.T, w *httptest.ResponseRecorder) {
	y := "plain"
	var x string
	func(y string) { x = y }(w.Body.String())
	_ = y
	assert.Contains(t, x, "callout-error") // WANT
}

func TestTypeSwitchWrite(t *testing.T, w *httptest.ResponseRecorder) {
	y := "plain"
	var x string
	switch y := any(w.Body.String()).(type) {
	case string:
		x = y
	}
	_ = y
	assert.Contains(t, x, "callout-error") // WANT
}

func TestBuilderShadowArg(t *testing.T, w *httptest.ResponseRecorder) {
	y := "plain"
	var b strings.Builder
	for _, y := range []string{w.Body.String()} {
		b.WriteString(y)
	}
	_ = y
	assert.Contains(t, b.String(), "callout-error") // WANT
}

func TestSprintShadowArg(t *testing.T, w *httptest.ResponseRecorder) {
	y := "plain"
	var x string
	{
		y := w.Body.String()
		x = fmt.Sprint(y)
	}
	_ = y
	assert.Contains(t, x, "callout-error") // WANT
}

func TestScopeControls(t *testing.T, w *httptest.ResponseRecorder) {
	y := w.Body.String()
	var x string
	{
		y := "plain"
		x = y
	}
	_ = y
	// A name declared twice in the function is not resolved: unknown, so
	// the finding stays even where the inner value is a literal.
	assert.Contains(t, x, "callout-error") // WANT
	var b strings.Builder
	apply(b.WriteString, w.Body.String())
	assert.Contains(t, b.String(), "callout-error") // WANT
	var scanned string
	_, _ = fmt.Sscan(w.Body.String(), &scanned)
	assert.Contains(t, scanned, "callout-error") // WANT
	string := func(b []byte) text { return w.Body.String() }
	raw, _ := os.ReadFile("fixture.html")
	assert.Contains(t, string(raw), "callout-error") // WANT
}

// Review round 4: a function literal used as a whole value, and a check
// inside a subtest of a function that shadows a package or builtin name.
func TestLiteralValues(t *testing.T, w *httptest.ResponseRecorder) {
	x := "plain"
	f := func() { x = w.Body.String() }
	f()
	assert.Contains(t, x, "callout-error") // WANT
	v := "plain"
	var g = func() { v = w.Body.String() }
	g()
	assert.Contains(t, v, "callout-error") // WANT
	y := "plain"
	var b strings.Builder
	h := func(y string) { b.WriteString(y) }
	h(w.Body.String())
	_ = y
	assert.Contains(t, b.String(), "callout-error") // WANT
	z := "plain"
	ch := make(chan func(), 1)
	ch <- func() { z = w.Body.String() }
	(<-ch)()
	assert.Contains(t, z, "callout-error") // WANT
}

type fakeFS struct{ w *httptest.ResponseRecorder }

func (f fakeFS) ReadFile(string) ([]byte, error) { return f.w.Body.Bytes(), nil }

func TestShadowSeenFromSubtest(t *testing.T, w *httptest.ResponseRecorder) {
	os := fakeFS{w}
	string := func(b []byte) text { return w.Body.String() }
	t.Run("page", func(t *testing.T) {
		data, _ := os.ReadFile("x")
		assert.Contains(t, string(data), "callout-error") // WANT
	})
}

func TestUniqueNamesStayKnown(t *testing.T, db interface{ Scan(...any) error }) {
	var insight string
	_ = db.Scan(&insight)
	t.Run("stored", func(t *testing.T) {
		assert.Contains(t, insight, "callout-error")
	})
	var built strings.Builder
	built.WriteString("<b>")
	built.WriteString(insight)
	assert.Contains(t, built.String(), "callout-error")
}
`,
	}
	assertOriginFindings(t, "editor/scope_test.go", sources)
}

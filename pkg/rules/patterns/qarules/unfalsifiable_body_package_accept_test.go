package qarules

import (
	"go/parser"
	"go/token"
	"os"
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

// A name a function declares once may still stand for something else where
// the check reads it: a variable of another file of the package, a name of a
// dot-imported package, a function the package names string. A check outside
// any function declaration is a check too, and a local strings anywhere in
// the function leaves strings.Contains unknown, not harmless.
func TestUnfalsifiableTestCase_GoMarkerSubjectPackageNames(t *testing.T) {
	sources := map[string]string{
		"static/app.css": ".callout-error { color: red; }\n",
		"editor/state_test.go": `package editor

import "net/http/httptest"

var lastBody string

func serve(w *httptest.ResponseRecorder) { lastBody = w.Body.String() }
`,
		"editor/page_test.go": `package editor

import (
	"net/http/httptest"
	"strings"
	"testing"

	. "example.com/fixtures"
	"github.com/stretchr/testify/assert"
)

func TestOtherFileVariable(t *testing.T) {
	w := httptest.NewRecorder()
	serve(w)
	assert.Contains(t, lastBody, "callout-error") // WANT
	if len(lastBody) > 0 {
		lastBody := "plain"
		_ = lastBody
	}
}

func TestOtherFileVariableShadowedByConst(t *testing.T) {
	w := httptest.NewRecorder()
	serve(w)
	t.Run("page", func(t *testing.T) {
		assert.Contains(t, lastBody, "callout-error") // WANT
	})
	{
		const lastBody = "plain"
		_ = lastBody
	}
}

func TestDotImportedVariable(t *testing.T) {
	w := httptest.NewRecorder()
	Serve(w)
	assert.Contains(t, Page, "callout-error") // WANT
	{
		Page := "plain"
		_ = Page
	}
}

var checkPage = func(t *testing.T, body string) {
	assert.Contains(t, body, "callout-error") // WANT
}

var pageCases = []struct {
	check func(t *testing.T, w *httptest.ResponseRecorder)
}{
	{check: func(t *testing.T, w *httptest.ResponseRecorder) {
		if !strings.Contains(w.Body.String(), "callout-error") { // WANT
			t.Fatal("no callout")
		}
	}},
}

func TestLocalStringsElsewhere(t *testing.T) {
	w := httptest.NewRecorder()
	if !strings.Contains(w.Body.String(), "callout-error") { // WANT
		t.Fatal("no callout")
	}
	t.Run("parts", func(t *testing.T) {
		strings := []string{"a"}
		_ = strings
	})
}

func TestAppendedBody(t *testing.T) {
	w := httptest.NewRecorder()
	page := "plain"
	page += w.Body.String()
	assert.Contains(t, page, "callout-error") // WANT
}

func TestLiteralOnly(t *testing.T) {
	wanted := "<p class=\"callout-error\">"
	assert.Contains(t, wanted, "callout-error")
}
`,
		"convert/state_test.go": `package convert

import (
	"net/http/httptest"

	"example.com/strtype"
)

var rec *httptest.ResponseRecorder

func string(b []byte) strtype.Str { return rec.Body.String() }
`,
		"convert/read_test.go": `package convert

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPackageFunctionNamedString(t *testing.T) {
	rec = httptest.NewRecorder()
	raw, _ := os.ReadFile("fixture.html")
	assert.Contains(t, string(raw), "callout-error") // WANT
}
`,
	}
	assertProjectOriginFindings(t, sources, nil)
}

// What the walk leaves out still declares names of the package, a byte slice
// read from a file can be overwritten with the body without an assignment,
// and in a file with a dot-import any name may be the imported one.
func TestUnfalsifiableTestCase_GoMarkerSubjectHiddenWrites(t *testing.T) {
	sources := map[string]string{
		"static/app.css": ".callout-error { color: red; }\n",
		"editor/dot_test.go": `package editor

import (
	"net/http/httptest"
	"testing"

	. "example.com/fixtures"
	"github.com/stretchr/testify/assert"
)

func setPage() { Page = httptest.NewRecorder().Body.String() }

func TestDotImportedShadowedInSiblingBlock(t *testing.T) {
	setPage()
	{
		Page := "plain"
		_ = Page
	}
	assert.Contains(t, Page, "callout-error") // WANT
}
`,
		"editor/page_test.go": `package editor

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVariableOfGeneratedFile(t *testing.T) {
	fillMock()
	assert.Contains(t, mockBody, "callout-error") // WANT
	{
		mockBody := "plain"
		_ = mockBody
	}
}

func TestBufferOverwrittenByCopy(t *testing.T) {
	raw, _ := os.ReadFile("fixture.html")
	copy(raw, httptest.NewRecorder().Body.Bytes())
	assert.Contains(t, string(raw), "callout-error") // WANT
}

func TestBufferFilledByRead(t *testing.T) {
	raw, _ := os.ReadFile("fixture.html")
	_, _ = httptest.NewRecorder().Body.Read(raw)
	assert.Contains(t, string(raw), "callout-error") // WANT
}

func TestBufferOverwrittenThroughAlias(t *testing.T) {
	raw, _ := os.ReadFile("fixture.html")
	view := raw[:]
	copy(view, httptest.NewRecorder().Body.Bytes())
	assert.Contains(t, string(raw), "callout-error") // WANT
}

func TestLocalStringsWithLiteralSubject(t *testing.T) {
	if !strings.Contains("<p class=\"callout-error\">", "callout-error") { // WANT
		t.Fatal("no callout")
	}
	t.Run("parts", func(t *testing.T) {
		strings := []string{"a"}
		_ = strings
	})
}

type page string

func (p page) check(t *testing.T) {
	func() { p := "plain"; _ = p }()
	assert.Contains(t, string(p), "callout-error") // WANT
}

func TestFileReadIntact(t *testing.T) {
	raw, _ := os.ReadFile("fixture.html")
	assert.Contains(t, string(raw), "callout-error")
}
`,
	}
	unwalked := map[string]string{
		"editor/zz.generated.go": `package editor

import "net/http/httptest"

var mockBody string

func fillMock() { mockBody = httptest.NewRecorder().Body.String() }
`,
	}
	assertProjectOriginFindings(t, sources, unwalked)
}

// assertProjectOriginFindings checks that the rule, given every file of
// sources, reports exactly the lines marked // WANT in the Go files. The
// unwalked files are on disk but not given to the rule, as files the walk
// excludes or skips as generated.
func assertProjectOriginFindings(t *testing.T, sources, unwalked map[string]string) {
	t.Helper()
	root, _ := rulestest.Module(t, sources)
	for name, content := range unwalked {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
	}
	var files []*core.FileContext
	var want []string
	for name, content := range sources {
		file, err := core.NewFileContextChecked(filepath.Join(root, name), root, []byte(content), core.DefaultConfig())
		require.NoError(t, err)
		if strings.HasSuffix(name, ".go") {
			fset := token.NewFileSet()
			syntax, err := parser.ParseFile(fset, file.Path, content, parser.SkipObjectResolution|parser.ParseComments)
			require.NoError(t, err)
			file.SetGoAST(fset, syntax)
			for i, line := range strings.Split(content, "\n") {
				if strings.Contains(line, "// WANT") {
					want = append(want, name+":"+strconv.Itoa(i+1))
				}
			}
		}
		files = append(files, file)
	}
	rule := NewUnfalsifiableTestCaseRule()
	rule.UseProjectFiles(files)
	var found []string
	for _, file := range files {
		found = append(found, patterntest.FoundLines(rule.AnalyzeFile(file))...)
	}
	assert.ElementsMatch(t, want, found)
}

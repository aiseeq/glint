package patterns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A make target exists to run one test and hands it a token; the test skips
// when the token is empty, and the target passes green with the check never
// run.
func TestSkippedTestWhenTargetEnvMissing(t *testing.T) {
	files := map[string]string{
		"makefiles/testing.mk": `test-reconcile:
  @set -a; . ./.env; set +a; \
    export RECON_TOKEN=$$(python3 tools/token.py); \
    cd backend && go test ./tests/recon/ -run TestReconcileBalances -count=1 -v
test-unit:
  cd backend && go test ./...
`,
		"backend/tests/recon/recon_test.go": `package recon

import (
	"os"
	"testing"
)

func TestReconcileBalances(t *testing.T) {
	token := os.Getenv("RECON_TOKEN")
	if token == "" {
		t.Skip("RECON_TOKEN is not set")
	}
	_ = token
}

func TestOptionalExport(t *testing.T) {
	if os.Getenv("EXPORT_URL") == "" {
		t.Skip("no export service")
	}
}
`,
	}
	rule := NewSkippedTestRule()
	var contexts []*core.FileContext
	for path, source := range files {
		if strings.HasSuffix(path, ".go") {
			contexts = append(contexts, rulestest.GoFile(t, path, source))
		} else {
			contexts = append(contexts, rulestest.TextFile(t, path, recipe(source)))
		}
	}
	rule.UseProjectFiles(contexts)
	var found []*core.Violation
	for _, ctx := range contexts {
		found = append(found, rule.AnalyzeFile(ctx)...)
	}
	assert.Equal(t, []string{"backend/tests/recon/recon_test.go:11"}, foundLines(found))
}

// A call through a function value in a test does not stop the check.
func TestSkippedTestEnvCheckOnFunctionValue(t *testing.T) {
	rule := NewSkippedTestRule()
	mk := rulestest.TextFile(t, "Makefile", recipe("test-x:\n  export X_TOKEN=1; go test ./... -run TestX\n"))
	goFile := rulestest.GoFile(t, "x_test.go", `package x

import "testing"

func TestX(t *testing.T) {
	get := func() string { return "" }
	v := get()
	if v == "" {
		t.Skip("no value")
	}
}
`)
	rule.UseProjectFiles([]*core.FileContext{mk, goFile})
	assert.Empty(t, rule.AnalyzeFile(goFile))
}

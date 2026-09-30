package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func ioutilFindings(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return NewDeprecatedIoutilRule().AnalyzeFile(rulestest.GoFile(t, "src/file.go", source))
}

func TestDeprecatedIoutilRule(t *testing.T) {
	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name:          "Import io/ioutil",
			code:          "package main\n\nimport _ \"io/ioutil\"\n",
			expectedCount: 1,
		},
		{
			name: "ioutil.ReadFile usage",
			code: `package main

import "io/ioutil"

func main() {
	data, _ := ioutil.ReadFile("test.txt")
	_ = data
}
`,
			expectedCount: 2, // import + function call
		},
		{
			name: "No ioutil usage - OK",
			code: `package main

import "os"

func main() {
	data, _ := os.ReadFile("test.txt")
	_ = data
}
`,
			expectedCount: 0,
		},
		{
			name: "ioutil in string literal - OK",
			code: `package main

import "fmt"

func main() { fmt.Println("Use os.ReadFile instead of ioutil.ReadFile") }
`,
			expectedCount: 0,
		},
		{
			name: "call after a string holding //",
			code: `package main

import (
	"io"
	"io/ioutil"
)

func read(r io.Reader) {
	u := "http://example.com"; data, _ := ioutil.ReadAll(r)
	_, _ = u, data
}
`,
			expectedCount: 2,
		},
		{
			name: "two calls on one line",
			code: `package main

import "io/ioutil"

func copyFile(src, dst string) {
	data, _ := ioutil.ReadFile(src); _ = ioutil.WriteFile(dst, data, 0o600)
}
`,
			expectedCount: 3,
		},
		{
			name: "aliased import",
			code: `package main

import legacy "io/ioutil"

func read(p string) { _, _ = legacy.ReadFile(p) }
`,
			expectedCount: 2,
		},
		{
			name: "other package whose name ends in ioutil",
			code: `package main

import "example.com/projecta/fsioutil"

func read() { _ = fsioutil.ReadFile("x") }
`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Len(t, ioutilFindings(t, tt.code), tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

func TestDeprecatedIoutilNonGoFile(t *testing.T) {
	rule := NewDeprecatedIoutilRule()

	ctx := core.NewFileContext("/src/file.ts", "/src", []byte(`import ioutil from "ioutil"`), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}

func TestDeprecatedIoutilSuggestions(t *testing.T) {
	tests := []struct {
		call        string
		suggestion  string
		replacement string
	}{
		{"ioutil.ReadAll(nil)", "Replace with io.ReadAll", "io.ReadAll"},
		{"ioutil.ReadFile(\"p\")", "Replace with os.ReadFile", "os.ReadFile"},
		{"ioutil.WriteFile(\"p\", nil, 0o600)", "Replace with os.WriteFile", "os.WriteFile"},
		{"ioutil.TempDir(\"\", \"test\")", "Replace with os.MkdirTemp", "os.MkdirTemp"},
		{"ioutil.TempFile(\"\", \"test\")", "Replace with os.CreateTemp", "os.CreateTemp"},
		{"ioutil.NopCloser(nil)", "Replace with io.NopCloser", "io.NopCloser"},
		{"ioutil.Discard", "Replace with io.Discard", "io.Discard"},
		// os.ReadDir returns []fs.DirEntry, not []fs.FileInfo: the call sites
		// change, so there is no mechanical replacement.
		{"ioutil.ReadDir(\"p\")", "Replace with os.ReadDir, which returns []fs.DirEntry instead of []fs.FileInfo", ""},
	}

	for _, tt := range tests {
		t.Run(tt.call, func(t *testing.T) {
			violations := ioutilFindings(t, "package main\n\nimport \"io/ioutil\"\n\nvar _ = "+tt.call+"\n")
			require.Len(t, violations, 2)
			use := violations[1]
			assert.Equal(t, tt.suggestion, use.Suggestion)
			assert.Equal(t, 5, use.Line)
			assert.Equal(t, 9, use.Column)
			if tt.replacement == "" {
				assert.NotContains(t, use.Context, "replacement")
			} else {
				assert.Equal(t, tt.replacement, use.Context["replacement"])
			}
		})
	}
}

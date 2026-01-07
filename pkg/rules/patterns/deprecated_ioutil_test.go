package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestDeprecatedIoutilRule(t *testing.T) {
	rule := NewDeprecatedIoutilRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name:          "Import io/ioutil",
			code:          `import "io/ioutil"`,
			expectedCount: 1,
		},
		{
			name: "ioutil.ReadFile usage",
			code: `package main
import "io/ioutil"
func main() {
	data, _ := ioutil.ReadFile("test.txt")
	_ = data
}`,
			expectedCount: 2, // import + function call
		},
		{
			name: "ioutil.ReadAll usage",
			code: `resp, _ := http.Get(url)
data, _ := ioutil.ReadAll(resp.Body)`,
			expectedCount: 1,
		},
		{
			name: "ioutil.WriteFile usage",
			code: `ioutil.WriteFile("test.txt", data, 0644)`,
			expectedCount: 1,
		},
		{
			name: "No ioutil usage - OK",
			code: `package main
import "os"
func main() {
	data, _ := os.ReadFile("test.txt")
	_ = data
}`,
			expectedCount: 0,
		},
		{
			name:          "ioutil in string literal - OK",
			code:          `fmt.Println("Use os.ReadFile instead of ioutil.ReadFile")`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/file.go", "/src", []byte(tt.code), core.DefaultConfig())
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
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
	rule := NewDeprecatedIoutilRule()

	tests := []struct {
		code       string
		suggestion string
	}{
		{
			code:       "data, _ := ioutil.ReadAll(r)",
			suggestion: "Replace with io.ReadAll",
		},
		{
			code:       "data, _ := ioutil.ReadFile(path)",
			suggestion: "Replace with os.ReadFile",
		},
		{
			code:       "ioutil.WriteFile(path, data, 0644)",
			suggestion: "Replace with os.WriteFile",
		},
		{
			code:       "files, _ := ioutil.ReadDir(path)",
			suggestion: "Replace with os.ReadDir",
		},
		{
			code:       "dir, _ := ioutil.TempDir(\"\", \"test\")",
			suggestion: "Replace with os.MkdirTemp",
		},
		{
			code:       "f, _ := ioutil.TempFile(\"\", \"test\")",
			suggestion: "Replace with os.CreateTemp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			ctx := core.NewFileContext("/src/file.go", "/src", []byte(tt.code), core.DefaultConfig())
			violations := rule.AnalyzeFile(ctx)
			if assert.Len(t, violations, 1) {
				assert.Equal(t, tt.suggestion, violations[0].Suggestion)
			}
		})
	}
}

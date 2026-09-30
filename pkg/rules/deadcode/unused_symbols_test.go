package deadcode

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestUnusedSymbolsRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "unused private function",
			code: `package main

func main() {}

func unusedHelper() {}`,
			wantViolations: 1,
		},
		{
			name: "used private function",
			code: `package main

func main() {
	helper()
}

func helper() {}`,
			wantViolations: 0,
		},
		{
			name: "unused private type",
			code: `package main

type unusedType struct{}

func main() {}`,
			wantViolations: 1,
		},
		{
			name: "used private type",
			code: `package main

type myType struct{}

func main() {
	var _ myType
}`,
			wantViolations: 0,
		},
		{
			name: "unused private constant",
			code: `package main

const unusedConst = 42

func main() {}`,
			wantViolations: 1,
		},
		{
			name: "used private constant",
			code: `package main

const myConst = 42

func main() {
	_ = myConst
}`,
			wantViolations: 0,
		},
		{
			name: "unused private variable",
			code: `package main

var unusedVar = "hello"

func main() {}`,
			wantViolations: 1,
		},
		{
			name: "used private variable",
			code: `package main

var myVar = "hello"

func main() {
	println(myVar)
}`,
			wantViolations: 0,
		},
		{
			name: "exported function - skip",
			code: `package main

func main() {}

func ExportedHelper() {}`,
			wantViolations: 0,
		},
		{
			name: "exported type - skip",
			code: `package main

type ExportedType struct{}

func main() {}`,
			wantViolations: 0,
		},
		{
			name: "init function - skip",
			code: `package main

func init() {}

func main() {}`,
			wantViolations: 0,
		},
		{
			name: "method - skip (might implement interface)",
			code: `package main

type myType struct{}

func (m *myType) unusedMethod() {}

func main() {
	var _ myType
}`,
			wantViolations: 0,
		},
		{
			name: "blank identifier - skip",
			code: `package main

var _ = func() {}

func main() {}`,
			wantViolations: 0,
		},
		{
			name: "multiple unused symbols",
			code: `package main

func unusedFunc1() {}
func unusedFunc2() {}
type unusedType struct{}
const unusedConst = 1

func main() {}`,
			wantViolations: 4,
		},
		{
			name: "function used in another function",
			code: `package main

func helper1() {
	helper2()
}

func helper2() {}

func main() {
	helper1()
}`,
			wantViolations: 0,
		},
		{
			name: "recursive function nobody else calls",
			code: `package main

func countdown(n int) int {
	if n == 0 {
		return 0
	}
	return countdown(n - 1)
}

func main() {}`,
			wantViolations: 1,
		},
		{
			name: "type only its own methods mention",
			code: `package main

type widget struct{ n int }

func (w *widget) size() int { return w.n }

func main() {}`,
			wantViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := analyzeUnusedSymbols(t, map[string]string{"main.go": tt.code})
			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)
		})
	}
}

func analyzeUnusedSymbols(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := NewUnusedSymbolsRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

func TestUnusedSymbolsCountsSiblingUsage(t *testing.T) {
	violations := analyzeUnusedSymbols(t, map[string]string{
		"main.go":  "package demo\n\nfunc helper() {}\n",
		"other.go": "package demo\n\nfunc Caller() { helper() }\n",
	})
	assert.Empty(t, violations, "helper is used from a sibling file of the same package")
}

func TestUnusedSymbolsCountsSiblingTestFileUsage(t *testing.T) {
	violations := analyzeUnusedSymbols(t, map[string]string{
		"main.go":      "package demo\n\nfunc testedHelper() {}\n",
		"demo_test.go": "package demo\n\nimport \"testing\"\n\nfunc TestOnly(t *testing.T) { testedHelper() }\n",
	})
	assert.Empty(t, violations, "a symbol used only by package tests is not dead code")
}

// A file the build leaves out on this platform still uses what it names: the
// typed load does not see it, the name scan does.
func TestUnusedSymbolsCountsBuildConstrainedSiblingUsage(t *testing.T) {
	violations := analyzeUnusedSymbols(t, map[string]string{
		"main.go":        "package demo\n\nfunc platformHelper() int { return 1 }\n",
		"other_plan9.go": "package demo\n\nfunc Caller() int { return platformHelper() }\n",
	})
	assert.Empty(t, violations)
}

// Repro: a directory held a build-ignored template next to real code, and the
// template was excluded from analysis. The rule reread the directory itself,
// tried to parse the template and replaced every finding of the package with
// a CRITICAL "analysis failed". Files outside the typed load are read only as
// text, never parsed.
func TestUnusedSymbolsIgnoresExcludedTemplateSibling(t *testing.T) {
	root, contexts := rulestest.Module(t, map[string]string{
		"p/a.go": "package p\n\nfunc helper() int { return 1 }\n\ntype thing struct{ n int }\n\nvar registry = map[string]int{}\n",
		"p/b.go": "package p\n\n// Use uses symbols from a.go.\nfunc Use() int { _ = registry; t := thing{n: 1}; return helper() + t.n }\n",
		"q/q.go": "package q\n\n// Q is exported.\nfunc Q() int { return 1 }\n\nfunc dead() {}\n",
	})
	template := "//go:build ignore\n\npackage main\n\nfunc main() {\n\t{{range .Items}}\n}\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "q", "gen.go"), []byte(template), 0o644))
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)

	violations, err := NewUnusedSymbolsRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "q/q.go", violations[0].File)
	assert.Contains(t, violations[0].Message, "'dead'")
	assert.NotEqual(t, core.SeverityCritical, violations[0].Severity)
}

// Repro: a project excluded "*_test.go" from analysis to keep test code out
// of its findings. The test files then never reached the rule, and every
// helper only the tests call was reported as dead. Excluding a file from the
// findings does not make its references disappear: the files of the package
// directory the typed load leaves out are read as text all the same.
func TestUnusedSymbolsCountsTestFileExcludedFromAnalysis(t *testing.T) {
	root, contexts := rulestest.Module(t, map[string]string{
		"p/amount.go":      "package p\n\nfunc parseAmount(s string) int { return len(s) }\n\nconst currentVersion = 1\n\nfunc dead() {}\n",
		"p/amount_test.go": "package p\n\nimport \"testing\"\n\nfunc TestParse(t *testing.T) { _ = parseAmount(\"1\") + currentVersion }\n",
	})
	analyzed := make([]*core.FileContext, 0, len(contexts))
	for _, fileCtx := range contexts {
		if !fileCtx.IsTestFile() {
			analyzed = append(analyzed, fileCtx)
		}
	}
	require.Len(t, analyzed, 1)
	project, err := core.LoadGoProject(root, analyzed, core.GoProjectOptions{})
	require.NoError(t, err)

	violations, err := NewUnusedSymbolsRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "'dead'")
}

func TestUnusedSymbolsRuleMetadata(t *testing.T) {
	rule := NewUnusedSymbolsRule()

	assert.Equal(t, "unused-symbol", rule.Name())
	assert.Equal(t, "deadcode", rule.Category())
	assert.Equal(t, core.SeverityLow, rule.DefaultSeverity())
	assert.NotContains(t, rule.Description(), "within their file")
}

func TestUnusedSymbolsSkipsTestFiles(t *testing.T) {
	violations := analyzeUnusedSymbols(t, map[string]string{
		"main.go":      "package main\n\nfunc main() {}\n",
		"main_test.go": "package main\n\nimport \"testing\"\n\nfunc unusedHelper() {}\n\nfunc TestSomething(t *testing.T) {}\n",
	})
	assert.Empty(t, violations, "Should skip test files")
}

package deadcode

import (
	"os"
	"path/filepath"
	"strconv"
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
			name: "unexported method no interface of the package declares",
			code: `package main

type myType struct{}

func (m *myType) unusedMethod() {}

func main() {
	var _ myType
}`,
			wantViolations: 1,
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
		"q/q.go": "package q\n\n// Q is exported.\nfunc Q() int { return 1 }\n\nfunc dead() {}\nfunc deadOther() {}\n",
	})
	template := "//go:build ignore\n\npackage main\n\nfunc main() {\n\t{{range .Items}}\n\t{{.deadOther}}\n}\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "q", "gen.go"), []byte(template), 0o644))
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
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
	project, err := core.LoadGoProject(root, analyzed, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
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

func TestUnusedSymbolsReportsUnusedTestHelpers(t *testing.T) {
	violations := analyzeUnusedSymbols(t, map[string]string{
		"main.go": "package main\n\nfunc main() {}\n",
		"main_test.go": `package main

import "testing"

func unusedHelper() {}
func calledHelper() {}
func TestMain(m *testing.M) {}
func TestSomething(t *testing.T) { calledHelper() }
func BenchmarkSomething(b *testing.B) {}
func FuzzSomething(f *testing.F) {}
func ExampleSomething() {}
func init() {}
type testType struct{}
func (testType) methodMayImplementInterface() {}
`,
		"other_test.go": "package main\n\nfunc TestAcrossFiles(t *testing.T) { calledHelper() }\n",
	})
	require.Len(t, violations, 1)
	assert.Equal(t, "main_test.go", violations[0].File)
	assert.Contains(t, violations[0].Message, "'unusedHelper'")
}

func TestUnusedSymbolsTestHelpersFollowPackageName(t *testing.T) {
	violations := analyzeUnusedSymbols(t, map[string]string{
		"main.go": `package sample

func packageHelper() {}
var _ = "deadExternal"
`,
		"main_test.go": `package sample

import "testing"

func packageTestCaller() { packageHelper() }
func deadInternal() {}
func TestCaller() { packageTestCaller() }
`,
		"external_test.go": `package sample_test

import sample "example.com/rulestest"
import "testing"

func deadExternal() {}
func liveExternal() {}
func TestExternal(t *testing.T) { liveExternal(); sample.Exported() }
var _ = "deadInternal"
// deadInternal
`,
	})
	require.Len(t, violations, 2)
	assert.Contains(t, violations[0].Message, "'deadExternal'")
	assert.Contains(t, violations[1].Message, "'deadInternal'")
}

func TestUnusedSymbolsCodeMentionsInTestFilesKeepHelperAlive(t *testing.T) {
	violations := analyzeUnusedSymbols(t, map[string]string{
		"main.go": `package sample

type receiver struct{}
func (receiver) methodMentionedBySelector() {}
func functionValue() {}
func selectorMentioned() {}
`,
		"main_test.go": `package sample

var _ = functionValue
func TestMentions(t *testing.T) {
	var r receiver
	r.methodMentionedBySelector()
	selectorMentioned()
}
`,
	})
	assert.Empty(t, violations)
}

func TestUnusedSymbolsTestTextDoesNotKeepSymbolsAlive(t *testing.T) {
	violations := analyzeUnusedSymbols(t, map[string]string{
		"main.go": `package sample

func deadByTextOnly() {}
`,
		"main_test.go": `package sample

const fixtureName = "deadByTextOnly"
// deadByTextOnly
`,
	})
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "'deadByTextOnly'")
}

func TestUnusedSymbolsMalformedTestFileStillUsesWordScan(t *testing.T) {
	root, contexts := rulestest.Module(t, map[string]string{
		"p/source.go": "package p\n\nfunc keptByMalformedFile() {}\nfunc dead() {}\n",
	})
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	broken, err := core.NewFileContextChecked(filepath.Join(root, "p", "broken_test.go"), root,
		[]byte("package p\n\nfunc broken( { keptByMalformedFile\n"), core.DefaultConfig())
	require.NoError(t, err)
	assert.Nil(t, broken.GoAST)
	project.Files = append(project.Files, broken)
	violations, err := NewUnusedSymbolsRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "'dead'")
}

// An unexported method can satisfy only an interface of its own package that
// declares it: without one and without a call, nothing reaches it.
func TestUnusedSymbolsReportsUnexportedMethodNeverCalled(t *testing.T) {
	violations := analyzeUnusedSymbols(t, map[string]string{
		"routing/factory.go": `package routing

type Router struct{}

type Factory struct{}

func (f *Factory) Build() *Router { return f.createRouter() }

func (f *Factory) createRouter() *Router { return &Router{} }

func (f *Factory) createCleanRouter() (*Router, error) {
	return f.createCleanRouter()
}

type closer interface{ closeAll() error }

type pool struct{}

func (p *pool) closeAll() error { return nil }

var _ closer = (*pool)(nil)

func (p *pool) String() string { return "pool" }
`,
	})
	require.Len(t, violations, 1)
	assert.Equal(t, 11, violations[0].Line)
	assert.Contains(t, violations[0].Message, "createCleanRouter")
}

// A //go:linkname directive binds a body-less declaration in another package
// to a function by its import path and name: the linker calls it, and no
// identifier anywhere names it. Both an ordinary function and a test helper
// pulled this way are alive; a function no directive names is still dead.
func TestUnusedSymbolsLinknameTargetIsAlive(t *testing.T) {
	violations := analyzeUnusedSymbols(t, map[string]string{
		"p/p.go":      "package p\n\nfunc linked() int { return 1 }\n\nfunc dead() {}\n",
		"p/p_test.go": "package p\n\nimport \"testing\"\n\nfunc linkedTest() int { return 2 }\n\nfunc TestP(t *testing.T) {}\n",
		"bridge/bridge.go": `package bridge

import _ "unsafe"

//go:linkname remote example.com/rulestest/p.linked
func remote() int

//go:linkname remoteTest example.com/rulestest/p.linkedTest
func remoteTest() int

// Call calls through the links.
func Call() int { return remote() + remoteTest() }
`,
	})
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "'dead'")
}

// Repro from a real project: a test declared a constant in its body that
// nothing read, and the compiler, unlike for an unused variable, said
// nothing. A constant declared in a function is checked in code and tests
// alike; one read anywhere after it, a later constant of its group included,
// is used.
func TestUnusedSymbolsReportsUnusedLocalConstants(t *testing.T) {
	violations := rulestest.RunRuleOnFiles(t, NewUnusedSymbolsRule(), map[string]string{
		"calc.go": `package calc

func Area(w int) int {
	const unused = 3
	const side = 2
	const (
		base  = 10
		twice = base * 2
	)
	return w * side * twice
}

func Loop(n int) int {
	const step = 1
	total := 0
	for i := 0; i < n; i++ {
		total += func() int { return step }()
	}
	return total
}

func Blank() {
	const _ = 1
}

func Kinds(n int) int {
	type local int
	const (
		read   = 1
		unread = 2
	)
	switch n {
	case 1:
		const inCase = 5
		return read
	}
	select {
	default:
		const inSelect = 6
	}
end:
	const labeled = 7
	_ = local(0)
	if n < 0 {
		goto end
	}
	return 0
}

func Weekdays() int {
	const (
		sunday = iota + 1
		monday
		tuesday
	)
	const scale = 2
	const (
		_  = iota
		kb = 1 << (10 * iota * scale)
		mb
	)
	const (
		first = iota
		second
	)
	const (
		one = 1
		alsoOne
	)
	const (
		zero = iota
		two  = iota * 2
	)
	const (
		low = iota
		mid
		high
	)
	const (
		_ = iota
		idle
		busy
	)
	return tuesday + int(mb) + alsoOne + two + low
}
`,
		"calc_test.go": `package calc

import "testing"

func TestArea(t *testing.T) {
	const ok = true
	const want = 12
	if got := Area(1); got != want {
		t.Fatal(got)
	}
}
`,
	})
	var places []string
	for _, v := range violations {
		places = append(places, filepath.Base(v.File)+":"+strconv.Itoa(v.Line))
	}
	// A group repeating an expression or counting with iota is one unit:
	// removing a constant read by none still changes or breaks the others.
	assert.ElementsMatch(t, []string{
		"calc.go:4", "calc_test.go:6",
		"calc.go:30", "calc.go:34", "calc.go:39", "calc.go:42",
		"calc.go:63", "calc.go:64", "calc.go:81", "calc.go:82",
	}, places)
}

// Package rulestest builds throwaway Go modules for rule tests, so that a test
// can state the source it cares about and get a loaded project back.
package rulestest

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

const defaultGoMod = "module example.com/rulestest\n\ngo 1.24\n"

// Module writes the given files into a fresh temporary directory, adding a
// go.mod when the caller did not provide one, and returns the module root
// together with the file contexts of its Go files in path order.
func Module(t *testing.T, files map[string]string) (string, []*core.FileContext) {
	t.Helper()
	root := t.TempDir()
	return root, ModuleIn(t, root, files)
}

// ModuleIn is Module in the given directory, for a test of a module root
// whose path matters (a name with glob metacharacters).
func ModuleIn(t *testing.T, root string, files map[string]string) []*core.FileContext {
	t.Helper()

	names := make([]string, 0, len(files)+1)
	for name := range files {
		names = append(names, name)
	}
	if _, ok := files["go.mod"]; !ok {
		names = append(names, "go.mod")
	}
	sort.Strings(names)

	var contexts []*core.FileContext
	for _, name := range names {
		content, ok := files[name]
		if !ok {
			content = defaultGoMod
		}
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

		ext := filepath.Ext(name)
		script := slices.Contains(core.TypeScriptExtensions, ext) || slices.Contains(core.JavaScriptExtensions, ext)
		if !strings.HasSuffix(name, ".go") && !core.IsTemplateName(name) && !script {
			continue
		}
		ctx, err := core.NewFileContextChecked(path, root, []byte(content), core.DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}

	return contexts
}

// Project loads the module written by Module as a typed Go project.
func Project(t *testing.T, files map[string]string) *core.GoProjectContext {
	t.Helper()
	return load(t, files, false)
}

// ProjectWithSSA loads the module and builds SSA for rules that need it.
func ProjectWithSSA(t *testing.T, files map[string]string) *core.GoProjectContext {
	t.Helper()
	return load(t, files, true)
}

// ProjectRunning loads the module with only the named files in the run, as
// glint check given those paths loads it: every package of the module is
// typed, and the rules report on the named files alone.
func ProjectRunning(t *testing.T, files map[string]string, run ...string) *core.GoProjectContext {
	t.Helper()
	root, contexts := Module(t, files)
	var running []*core.FileContext
	for _, ctx := range contexts {
		if slices.Contains(run, ctx.RelPath) {
			running = append(running, ctx)
		}
	}
	require.Len(t, running, len(run), "every file of the run is a Go file of the module")
	project, err := core.LoadGoProject(root, running, core.GoProjectOptions{ListPackages: ListPackages})
	require.NoError(t, err)
	return project
}

func load(t *testing.T, files map[string]string, withSSA bool) *core.GoProjectContext {
	t.Helper()
	root, contexts := Module(t, files)
	opts := core.GoProjectOptions{RequireSSA: withSSA}
	// SSA walks the import graph of the dependencies, which the in-process
	// load leaves out: an SSA test loads through packages.Load.
	if !withSSA {
		opts.ListPackages = ListPackages
	}
	project, err := core.LoadGoProject(root, contexts, opts)
	require.NoError(t, err)
	return project
}

// GoFile builds a file context with its Go syntax tree parsed, for rules that
// analyze one file at a time.
func GoFile(t *testing.T, path, source string) *core.FileContext {
	t.Helper()

	root := t.TempDir()
	full := filepath.Join(root, path)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(source), 0o644))

	ctx, err := core.NewFileContextChecked(full, root, []byte(source), core.DefaultConfig())
	require.NoError(t, err)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, full, source, parser.ParseComments)
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)

	return ctx
}

// TextFile builds a file context without parsing, for rules that work on lines
// — TypeScript, Markdown, SQL.
func TextFile(t *testing.T, path, source string) *core.FileContext {
	t.Helper()

	root := t.TempDir()
	full := filepath.Join(root, path)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(source), 0o644))

	ctx, err := core.NewFileContextChecked(full, root, []byte(source), core.DefaultConfig())
	require.NoError(t, err)
	return ctx
}

// SourceFileRuleLines runs a file rule on source parsed as Go when its path
// ends in .go, and as text otherwise, returning the finding lines.
func SourceFileRuleLines(t *testing.T, rule rules.Rule, path, source string) []int {
	t.Helper()
	if filepath.Ext(path) == ".go" {
		return GoFileRuleLines(t, rule, path, source)
	}
	return TextFileRuleLines(t, rule, path, source)
}

// InMemoryGoFile builds a file context for a path under projectRoot without
// writing anything to disk and attaches the syntax tree core's parser builds,
// so the rule sees exactly the path the test names. cfg may be nil.
func InMemoryGoFile(t *testing.T, path, projectRoot, source string, cfg *core.Config) *core.FileContext {
	t.Helper()

	ctx, err := core.NewFileContextChecked(path, projectRoot, []byte(source), cfg)
	require.NoError(t, err)

	fset, file, err := core.NewParser().ParseGoFile(path, []byte(source))
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)

	return ctx
}

// RunRuleOnProject runs a project rule once or a file rule on every file in
// the loaded Go project.
func RunRuleOnProject(t *testing.T, rule rules.Rule, project *core.GoProjectContext) []*core.Violation {
	t.Helper()
	if projectRule, ok := rule.(rules.GoProjectRule); ok {
		violations, err := projectRule.AnalyzeGoProject(project)
		require.NoError(t, err)
		return violations
	}
	var violations []*core.Violation
	for _, file := range project.Files {
		violations = append(violations, rule.AnalyzeFile(file)...)
	}
	return violations
}

// RunRuleOnFiles loads files as a typed Go project and runs the rule over it.
func RunRuleOnFiles(t *testing.T, rule rules.Rule, files map[string]string) []*core.Violation {
	t.Helper()
	return RunRuleOnProject(t, rule, Project(t, files))
}

// ProjectFilesRulePlaces runs a project-files rule on all files in a throwaway
// module and returns sorted file:line locations for its findings.
func ProjectFilesRulePlaces(t *testing.T, rule rules.ProjectFilesRule, files map[string]string) []string {
	t.Helper()
	root, _ := Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, file := range contexts {
		violations = append(violations, rule.AnalyzeFile(file)...)
	}
	return ViolationPlaces(violations)
}

// ProjectRulePlaces runs a project rule on files and returns sorted file:line
// locations for its findings.
func ProjectRulePlaces(t *testing.T, rule rules.GoProjectRule, files map[string]string) []string {
	t.Helper()
	return ViolationPlaces(RunRuleOnFiles(t, rule, files))
}

// GoProjectRuleLines runs a project rule on one Go source file and returns its finding lines.
func GoProjectRuleLines(t *testing.T, rule rules.GoProjectRule, path, source string) []int {
	t.Helper()
	return ViolationLines(RunRuleOnFiles(t, rule, map[string]string{path: source}))
}

// GoFileRuleLines runs a file rule on Go source and returns its finding lines.
func GoFileRuleLines(t *testing.T, rule rules.Rule, path, source string) []int {
	t.Helper()
	return ViolationLines(RunFileRuleOnGoFile(t, rule, path, source))
}

// TextFileRuleLines runs a file rule on text source and returns its finding lines.
func TextFileRuleLines(t *testing.T, rule rules.Rule, path, source string) []int {
	t.Helper()
	return ViolationLines(RunFileRuleOnTextFile(t, rule, path, source))
}

// TextFileRulePlaces runs a file rule on text source and returns sorted file:line locations.
func TextFileRulePlaces(t *testing.T, rule rules.Rule, path, source string) []string {
	t.Helper()
	return ViolationPlaces(RunFileRuleOnTextFile(t, rule, path, source))
}

// RunFileRuleOnGoFile runs a file rule on a parsed Go source file.
func RunFileRuleOnGoFile(t *testing.T, rule rules.Rule, path, source string) []*core.Violation {
	t.Helper()
	return rule.AnalyzeFile(GoFile(t, path, source))
}

// RunFileRuleOnTextFile runs a file rule on a text source file without parsing.
func RunFileRuleOnTextFile(t *testing.T, rule rules.Rule, path, source string) []*core.Violation {
	t.Helper()
	return rule.AnalyzeFile(TextFile(t, path, source))
}

// ViolationLines returns the source line of each finding in its original order.
func ViolationLines(violations []*core.Violation) []int {
	var lines []int
	for _, violation := range violations {
		lines = append(lines, violation.Line)
	}
	return lines
}

// ViolationPlaces returns file:line for each finding in sorted order.
func ViolationPlaces(violations []*core.Violation) []string {
	var places []string
	for _, violation := range violations {
		places = append(places, fmt.Sprintf("%s:%d", violation.File, violation.Line))
	}
	slices.Sort(places)
	return places
}

// SplitLines splits text at line feeds and omits a trailing empty line.
func SplitLines(source string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(source); i++ {
		if source[i] == '\n' {
			lines = append(lines, source[start:i])
			start = i + 1
		}
	}
	if start < len(source) {
		lines = append(lines, source[start:])
	}
	return lines
}

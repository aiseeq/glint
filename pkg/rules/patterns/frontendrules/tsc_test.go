package frontendrules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// globalTsc7 returns the global tsc 7 the rule runs, skipping the test when
// the machine has none.
func globalTsc7(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("tsc")
	if err != nil {
		t.Skip("tsc is not installed: the rule runs it")
	}
	out, err := exec.Command(path, "--version").Output()
	require.NoError(t, err)
	if !strings.Contains(string(out), "Version 7.") {
		t.Skipf("the global tsc is %s, the rule needs tsc 7", strings.TrimSpace(string(out)))
	}
	return path
}

// tscProject writes files under a fresh root with a fresh tool cache and
// installs tsc as the project's own tsc in node_modules/.bin.
func tscProject(t *testing.T, tsc string, files map[string]string) string {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	for name, content := range files {
		patterntest.WriteProjectFile(t, root, name, content)
	}
	if tsc != "" {
		installProjectTsc(t, root, tsc)
	}
	return root
}

func installProjectTsc(t *testing.T, root, tsc string) {
	t.Helper()
	bin := filepath.Join(root, "node_modules", ".bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	link := filepath.Join(bin, "tsc")
	require.NoError(t, os.RemoveAll(link))
	require.NoError(t, os.Symlink(tsc, link))
}

// tscContexts reads the files glint would analyze under root.
func tscContexts(t *testing.T, root string) []*core.FileContext {
	t.Helper()
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	return contexts
}

// tscFindings runs the rule over the root as a check does and returns
// "severity file:line message-head" lines, sorted.
func tscFindings(t *testing.T, root string) []string {
	t.Helper()
	contexts := tscContexts(t, root)
	rule := NewTscRule()
	require.NoError(t, rule.CheckTools(contexts))
	var found []string
	for _, ctx := range contexts {
		for _, v := range rule.AnalyzeFile(ctx) {
			head := v.Message
			if code, _, ok := strings.Cut(v.Message, ":"); ok && strings.HasPrefix(code, "TS") {
				head = code
			}
			found = append(found, fmt.Sprintf("%s %s:%d %s", v.Severity, v.File, v.Line, head))
		}
	}
	sort.Strings(found)
	return found
}

const strictTSConfig = `{
  // the project's settings
  "compilerOptions": {"strict": true, "module": "esnext", "moduleResolution": "bundler", "noEmit": true},
  "include": ["src"],
}
`

// A file a tsconfig compiles is checked with it by the project's tsc, and
// an error in a file it imports is the imported file's; a file no tsconfig
// compiles is checked strictly on its own, with the types of node.
func TestTscReportsTypeErrorsOfProgramsAndStandaloneFiles(t *testing.T) {
	tsc := globalTsc7(t)
	root := tscProject(t, tsc, map[string]string{
		"package.json":  `{"scripts": {"type-check": "tsc --noEmit"}}`,
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "import { double } from './math'\n\nexport const n: number = double('2')\n",
		"src/math.ts":   "export function double(x: number): number {\n  const s: string = x\n  return x * 2\n}\n",
		"src/fine.ts":   "export const ok = 1\n",
		"tools/run.ts":  "const args = process.argv.slice(2)\nfunction first(list) { return list[0] }\nconsole.log(first(args))\n",
	})

	assert.Equal(t, []string{
		"high src/main.ts:3 TS2345",
		"high src/math.ts:2 TS2322",
		"high tools/run.ts:2 TS7006",
	}, tscFindings(t, root))
}

// A tsconfig is not strict without strict, or with one of its checks off.
func TestTscReportsTsconfigWithoutStrict(t *testing.T) {
	tsc := globalTsc7(t)
	root := tscProject(t, tsc, map[string]string{
		"app/tsconfig.json":  `{"compilerOptions": {"noEmit": true}}`,
		"app/a.ts":           "export const a = 1\n",
		"lib/tsconfig.json":  `{"compilerOptions": {"strict": true, "strictNullChecks": false, "noEmit": true}}`,
		"lib/b.ts":           "export const b = 1\n",
		"good/tsconfig.json": `{"compilerOptions": {"strict": true, "noEmit": true}}`,
		"good/c.ts":          "export const c = 1\n",
	})

	found := tscFindings(t, root)
	require.Len(t, found, 2)
	assert.Contains(t, found[0], "high app/tsconfig.json:1 app/tsconfig.json does not make tsc strict (strict is not set)")
	assert.Contains(t, found[1], "high lib/tsconfig.json:1 lib/tsconfig.json does not make tsc strict (strictNullChecks is false)")
}

// stubTsc writes a tsc that answers --version, --showConfig and
// --listFilesOnly as the real one does and the type check with exit status
// status and no output.
func stubTsc(t *testing.T, real string, status int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tsc")
	script := fmt.Sprintf(`#!/bin/sh
case "$*" in
  *--showConfig*|*--listFilesOnly*) exec %q "$@" ;;
  *--version*) echo "Version 5.9.3"; exit 0 ;;
esac
exit %d
`, real, status)
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path
}

// A tsconfig the project's tsc builds and tsc 7 does not is medium: the
// project has to move before it takes the new compiler.
func TestTscReportsTsconfigTsc7DoesNotBuild(t *testing.T) {
	tsc := globalTsc7(t)
	root := tscProject(t, stubTsc(t, tsc, 0), map[string]string{
		"tsconfig.json": `{"compilerOptions": {"strict": true, "noEmit": true}}`,
		"main.ts":       "import './styles.css'\nexport const a = 1\n",
	})

	found := tscFindings(t, root)
	require.Len(t, found, 1)
	assert.Contains(t, found[0], "medium tsconfig.json:1 tsc 7 does not build tsconfig.json, which the project's tsc builds: 1 errors, main.ts(1,8): TS2882")
}

// The answer is cached: a second run does not ask tsc. A change of a file
// the program imports is a change of the input, so tsc runs again.
func TestTscCacheFollowsTheFilesOfTheProgram(t *testing.T) {
	tsc := globalTsc7(t)
	root := tscProject(t, tsc, map[string]string{
		"tsconfig.json":  strictTSConfig,
		"src/main.ts":    "import { two } from './lib/two'\nexport const n: number = two\n",
		"src/lib/two.ts": "export const two = 2\n",
	})
	assert.Empty(t, tscFindings(t, root))

	// A tsc that fails every check: what still passes comes from the cache.
	installProjectTsc(t, root, stubTsc(t, tsc, 3))
	assert.Empty(t, tscFindings(t, root))

	patterntest.WriteProjectFile(t, root, "src/lib/two.ts", "export const two = '2'\n")
	found := tscFindings(t, root)
	require.Len(t, found, 1)
	assert.Contains(t, found[0], "high tsconfig.json:1 tsc could not check tsconfig.json")
}

// A tsconfig needs the project's tsc and a TS file outside tsconfigs the
// global one; a root without TypeScript needs neither.
func TestTscCheckToolsNeedsTheTscOfEachProgram(t *testing.T) {
	tsc := globalTsc7(t)
	check := func(rule *TscRule, root string) error {
		contexts := tscContexts(t, root)
		return rule.CheckTools(contexts)
	}

	noLocal := tscProject(t, "", map[string]string{"tsconfig.json": strictTSConfig, "src/a.ts": "export const a = 1\n"})
	err := check(NewTscRule(), noLocal)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 tsconfigs have no tsc of their project")

	standalone := tscProject(t, "", map[string]string{"run.ts": "console.log(1)\n"})
	assert.NoError(t, check(NewTscRule(), standalone))
	missing := NewTscRule()
	missing.global = "tsc-that-is-not-installed"
	err = check(missing, standalone)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs the global tsc 7, which is not installed")

	plain := tscProject(t, tsc, map[string]string{"main.go": "package main\n"})
	assert.NoError(t, check(missing, plain))
}

// tsc continues a message on indented lines; an error of the program as a
// whole has no file; a failure without a reported error is an error of the run.
func TestTscDiagnosticsReadsTscOutput(t *testing.T) {
	dir := t.TempDir()
	script := func(body string) string {
		path := filepath.Join(t.TempDir(), "tsc")
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755))
		return path
	}
	reporting := script(`printf '%s\n' "src/a.ts(3,7): error TS2322: Type 'A' is not assignable to type 'B'." "  Types of property 'id' are incompatible." "error TS5102: Option 'baseUrl' has been removed."
exit 2
`)
	found, err := tscDiagnostics(reporting, dir)
	require.NoError(t, err)
	assert.Equal(t, []tscDiagnostic{
		{File: filepath.Join(dir, "src/a.ts"), Line: 3, Column: 7, Code: "TS2322", Message: "Type 'A' is not assignable to type 'B'. Types of property 'id' are incompatible."},
		{Code: "TS5102", Message: "Option 'baseUrl' has been removed."},
	}, found)

	_, err = tscDiagnostics(script("echo 'RangeError: Maximum call stack size exceeded' >&2\nexit 1\n"), dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed without reporting an error")
	assert.Contains(t, err.Error(), "Maximum call stack")
}

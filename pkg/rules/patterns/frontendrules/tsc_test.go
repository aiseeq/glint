package frontendrules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

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

func countedTsc(t *testing.T, real string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tsc")
	log := filepath.Join(t.TempDir(), "runs")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nexec %q \"$@\"\n", log, real)
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path, log
}

func editingTsc(t *testing.T, real, target string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tsc")
	log := filepath.Join(t.TempDir(), "runs")
	marker := filepath.Join(t.TempDir(), "edited")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %q
case "$*" in
  *--version*|*--showConfig*|*--listFilesOnly*) exec %q "$@" ;;
esac
%q "$@"
status=$?
if [ ! -e %q ]; then
  printf 'export const n: number = "edited"\n' > %q
  touch %q
fi
exit "$status"
`, log, real, real, marker, target, marker)
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path, log
}

func configEditingTsc(t *testing.T, real, target string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tsc")
	log := filepath.Join(t.TempDir(), "runs")
	marker := filepath.Join(t.TempDir(), "edited")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %q
case "$*" in
  *--listFiles*)
    %q "$@"
    status=$?
    if [ ! -e %q ]; then
      printf '%%s\n' '{"compilerOptions":{"strict":true,"noEmit":true,"noUnusedLocals":true},"include":["src"]}' > %q
      touch %q
    fi
    exit "$status"
    ;;
  *) exec %q "$@" ;;
esac
`, log, real, marker, target, marker, real)
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path, log
}

func tscRunCount(t *testing.T, log string) int {
	t.Helper()
	data, err := os.ReadFile(log)
	if os.IsNotExist(err) {
		return 0
	}
	require.NoError(t, err)
	return len(strings.Split(strings.TrimSpace(string(data)), "\n"))
}

func ageTscInputs(t *testing.T, root string, paths ...string) {
	t.Helper()
	old := time.Now().Add(-5 * time.Second)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		return os.Chtimes(path, old, old)
	})
	require.NoError(t, err)
	for _, path := range paths {
		require.NoError(t, os.Chtimes(path, old, old))
	}
}

func runCountedTsc(t *testing.T, root string) []string {
	t.Helper()
	return tscFindings(t, root)
}

func countedTscProject(t *testing.T, files map[string]string) (string, string, string) {
	t.Helper()
	real := globalTsc7(t)
	local, log := countedTsc(t, real)
	root := tscProject(t, local, files)
	return root, local, log
}

func TestTscStatCacheSkipsLaunches(t *testing.T) {
	root, local, log := countedTscProject(t, map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 1\n",
	})
	ageTscInputs(t, root, local)
	first := runCountedTsc(t, root)
	before := tscRunCount(t, log)
	require.Greater(t, before, 0)
	second := runCountedTsc(t, root)
	assert.Equal(t, first, second)
	assert.Equal(t, before, tscRunCount(t, log))
}

func TestTscStatCacheEditedFile(t *testing.T) {
	root, _, log := countedTscProject(t, map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 1\n",
	})
	assert.Empty(t, runCountedTsc(t, root))
	before := tscRunCount(t, log)
	patterntest.WriteProjectFile(t, root, "src/main.ts", "export const n: number = 'one'\n")
	found := runCountedTsc(t, root)
	assert.NotEmpty(t, found)
	assert.Greater(t, tscRunCount(t, log), before)
}

func TestTscStatCacheAddedFile(t *testing.T) {
	root, _, log := countedTscProject(t, map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 1\n",
	})
	assert.Empty(t, runCountedTsc(t, root))
	before := tscRunCount(t, log)
	patterntest.WriteProjectFile(t, root, "src/added.ts", "export const n: number = 'one'\n")
	found := runCountedTsc(t, root)
	assert.NotEmpty(t, found)
	assert.Greater(t, tscRunCount(t, log), before)
}

func TestTscStatCacheTsconfigChange(t *testing.T) {
	root, _, log := countedTscProject(t, map[string]string{
		"base.json":     `{"compilerOptions":{"strict":true,"noEmit":true},"include":["src"]}`,
		"tsconfig.json": `{"extends":"./base.json"}`,
		"src/main.ts":   "export const n: number = 1\n",
	})
	assert.Empty(t, runCountedTsc(t, root))
	before := tscRunCount(t, log)
	patterntest.WriteProjectFile(t, root, "base.json", `{"compilerOptions":{"noEmit":true},"include":["src"]}`)
	found := runCountedTsc(t, root)
	assert.NotEmpty(t, found)
	assert.Greater(t, tscRunCount(t, log), before)
}

func TestTsconfigChainExtendsArray(t *testing.T) {
	root := tscProject(t, "", map[string]string{
		"tsconfig.json":   `{"extends":["./base-first.json","./base-last.json"]}`,
		"base-first.json": `{"include":["from-first"]}`,
		"base-last.json":  `{"include":["src"],"exclude":["src/private"]}`,
	})
	chain, err := tsconfigChain(filepath.Join(root, "tsconfig.json"))
	require.NoError(t, err)
	assert.Equal(t, []string{
		filepath.Join(root, "tsconfig.json"),
		filepath.Join(root, "base-last.json"),
		filepath.Join(root, "base-first.json"),
	}, chain)
	scope, err := loadTSConfigScope(filepath.Join(root, "tsconfig.json"))
	require.NoError(t, err)
	covered, err := scope.covers(filepath.Join(root, "src", "main.ts"))
	require.NoError(t, err)
	assert.True(t, covered)
	covered, err = scope.covers(filepath.Join(root, "from-first", "main.ts"))
	require.NoError(t, err)
	assert.False(t, covered)
	covered, err = scope.covers(filepath.Join(root, "src", "private", "main.ts"))
	require.NoError(t, err)
	assert.False(t, covered)
}

func TestTsconfigChainPackageExtends(t *testing.T) {
	root := tscProject(t, "", map[string]string{
		"tsconfig.json": `{"extends":"@configs/base"}`,
		"node_modules/@configs/base/package.json":     `{"tsconfig":"./config/base.json"}`,
		"node_modules/@configs/base/config/base.json": `{"include":["src"],"exclude":["src/private"]}`,
	})
	config := filepath.Join(root, "tsconfig.json")
	chain, err := tsconfigChain(config)
	require.NoError(t, err)
	assert.Equal(t, []string{config, filepath.Join(root, "node_modules/@configs/base/config/base.json")}, chain)
	scope, err := loadTSConfigScope(config)
	require.NoError(t, err)
	baseDir := filepath.Join(root, "node_modules", "@configs", "base", "config")
	covered, err := scope.covers(filepath.Join(baseDir, "src", "main.ts"))
	require.NoError(t, err)
	assert.True(t, covered)
	covered, err = scope.covers(filepath.Join(baseDir, "src", "private", "main.ts"))
	require.NoError(t, err)
	assert.False(t, covered)
}

func TestTscStatCacheEditDuringRun(t *testing.T) {
	real := globalTsc7(t)
	root := tscProject(t, "", map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 1\n",
	})
	target := filepath.Join(root, "src", "main.ts")
	local, log := editingTsc(t, real, target)
	installProjectTsc(t, root, local)
	_ = runCountedTsc(t, root)
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Contains(t, string(data), `"edited"`)
	before := tscRunCount(t, log)
	assert.Greater(t, before, 0)
	found := runCountedTsc(t, root)
	assert.NotEmpty(t, found)
	assert.Greater(t, tscRunCount(t, log), before)
}

func TestTscStatCacheConfigEditDuringListing(t *testing.T) {
	real := globalTsc7(t)
	root := tscProject(t, "", map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 1\n",
	})
	config := filepath.Join(root, "tsconfig.json")
	local, log := configEditingTsc(t, real, config)
	installProjectTsc(t, root, local)
	_ = runCountedTsc(t, root)
	data, err := os.ReadFile(config)
	require.NoError(t, err)
	require.Contains(t, string(data), "noUnusedLocals")
	before := tscRunCount(t, log)
	_ = runCountedTsc(t, root)
	assert.Greater(t, tscRunCount(t, log), before)
}

func TestTscStatCacheAddedTypesPackage(t *testing.T) {
	real := globalTsc7(t)
	base := t.TempDir()
	root := filepath.Join(base, "project")
	require.NoError(t, os.MkdirAll(root, 0o755))
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	patterntest.WriteProjectFile(t, root, "tsconfig.json", strictTSConfig)
	patterntest.WriteProjectFile(t, root, "src/main.ts", "/// <reference path=\"../../node_modules/@types/existing/index.d.ts\" />\nexport const n: number = typedGlobal\n")
	patterntest.WriteProjectFile(t, base, "node_modules/@types/existing/package.json", `{"name":"@types/existing","version":"1.0.0","types":"index.d.ts"}`)
	patterntest.WriteProjectFile(t, base, "node_modules/@types/existing/index.d.ts", "declare const unrelatedGlobal: number\n")
	local, log := countedTsc(t, real)
	installProjectTsc(t, root, local)
	ageTscInputs(t, base, local)
	first := runCountedTsc(t, root)
	assert.NotEmpty(t, first)
	before := tscRunCount(t, log)
	patterntest.WriteProjectFile(t, base, "node_modules/@types/added/package.json", `{"name":"@types/added","version":"1.0.0","types":"index.d.ts"}`)
	patterntest.WriteProjectFile(t, base, "node_modules/@types/added/index.d.ts", "declare const typedGlobal: number\n")
	listed, err := exec.Command(real, "-p", filepath.Join(root, "tsconfig.json"), "--listFilesOnly").CombinedOutput()
	require.NoError(t, err, string(listed))
	require.Contains(t, string(listed), filepath.Join(base, "node_modules/@types/existing/index.d.ts"))
	_ = runCountedTsc(t, root)
	assert.Greater(t, tscRunCount(t, log), before)
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

func fullTscAnswer(t *testing.T, root string) []tscDiagnostic {
	t.Helper()
	tsc := filepath.Join(root, "node_modules", ".bin", "tsc")
	answer, err := tscDiagnostics(tsc, root, "-p", filepath.Join(root, "tsconfig.json"), "--noEmit", "--incremental", "false", "--pretty", "false")
	require.NoError(t, err)
	return answer
}

func projectFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, rel)
		}
		return nil
	})
	require.NoError(t, err)
	sort.Strings(files)
	return files
}

func TestTscIncrementalLeavesProjectClean(t *testing.T) {
	tsc := globalTsc7(t)
	root := tscProject(t, tsc, map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 1\n",
	})
	before := projectFiles(t, root)
	assert.Empty(t, tscFindings(t, root))
	patterntest.WriteProjectFile(t, root, "src/main.ts", "export const n: number = 'one'\n")
	assert.NotEmpty(t, tscFindings(t, root))
	assert.Equal(t, before, projectFiles(t, root))
}

func TestTscIncrementalFollowsEdits(t *testing.T) {
	tsc := globalTsc7(t)
	root := tscProject(t, tsc, map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 1\n",
	})
	for _, content := range []string{"export const n: number = 'one'\n", "export const n: number = 2\n"} {
		patterntest.WriteProjectFile(t, root, "src/main.ts", content)
		assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
	}
}

func TestTscIncrementalFollowsImportedJs(t *testing.T) {
	tsc := globalTsc7(t)
	root := tscProject(t, tsc, map[string]string{
		"tsconfig.json": `{
  "compilerOptions": {"strict": true, "allowJs": true, "module": "esnext", "moduleResolution": "bundler", "noEmit": true},
  "include": ["src"],
}
`,
		"src/a.ts": "import { value } from './b.js'\nexport const n: number = value\n",
		"src/b.js": "export const value = 1\n",
	})
	ageProjectTree(t, root)
	assert.Empty(t, tscFindings(t, root))
	patterntest.WriteProjectFile(t, root, "src/b.js", "export const value = 'one'\n")
	findings := tscFindings(t, root)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0], "high src/a.ts:2 TS2322")
}

func ageProjectTree(t *testing.T, root string) {
	t.Helper()
	old := time.Now().Add(-2 * time.Second)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, old, old)
	})
	require.NoError(t, err)
}

func incrementalTscAnswer(t *testing.T, root string) []tscDiagnostic {
	t.Helper()
	rule := NewTscRule()
	global, err := rule.globalTscBase()
	require.NoError(t, err)
	answer, err := runTscProgram(&tscProgram{config: filepath.Join(root, "tsconfig.json"), tsc: filepath.Join(root, "node_modules", ".bin", "tsc")}, global)
	require.NoError(t, err)
	return answer.Errors
}

func TestTscIncrementalCorruptBuildInfo(t *testing.T) {
	tsc := globalTsc7(t)
	root := tscProject(t, tsc, map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 1\n",
	})
	cache := os.Getenv("XDG_CACHE_HOME")
	assert.Empty(t, tscFindings(t, root))
	buildInfo, err := filepath.Glob(filepath.Join(cache, "glint", "tools", "tsc", "*.tsbuildinfo"))
	require.NoError(t, err)
	require.NotEmpty(t, buildInfo)
	require.NoError(t, os.WriteFile(buildInfo[0], []byte("not build info"), 0o600))
	patterntest.WriteProjectFile(t, root, "src/main.ts", "export const n: number = 'one'\n")
	assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
}

func TestTscIncrementalWorktreesApart(t *testing.T) {
	tsc := globalTsc7(t)
	files := map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 1\n",
	}
	left := tscProject(t, tsc, files)
	cache := os.Getenv("XDG_CACHE_HOME")
	right := tscProject(t, tsc, files)
	t.Setenv("XDG_CACHE_HOME", cache)
	patterntest.WriteProjectFile(t, left, "src/main.ts", "export const n: number = 'one'\n")
	assert.NotEmpty(t, tscFindings(t, left))
	assert.Empty(t, tscFindings(t, right))
	assert.Equal(t, fullTscAnswer(t, left), incrementalTscAnswer(t, left))
	assert.Equal(t, fullTscAnswer(t, right), incrementalTscAnswer(t, right))
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
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--tsBuildInfoFile" ]; then shift; printf '{}\n' > "$1"; fi
  shift
done
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

	patterntest.WriteProjectFile(t, root, "src/lib/two.ts", "export const two = '2'\n")
	ageTscInputs(t, root)
	found := tscFindings(t, root)
	require.Len(t, found, 1)
	assert.Contains(t, found[0], "high src/main.ts:2 TS2322")

	// Replacing the compiler invalidates its stat fingerprint.
	installProjectTsc(t, root, stubTsc(t, tsc, 3))
	found = tscFindings(t, root)
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

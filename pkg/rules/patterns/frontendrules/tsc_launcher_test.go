package frontendrules

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The other tests run the native tsc TestMain lays out; these run the tsc a
// consumer runs, from PATH as the tests started: npm installs it as a node
// launcher (#!/usr/bin/env node) that finds node on PATH and starts the
// compiler. Both the global tsc and the project's node_modules/.bin/tsc are
// that launcher, so --version, --showConfig, the project build, the type
// check of a file outside every tsconfig (--listFilesOnly and the check)
// and the global compiler mode all start it.

// launcherTsc7 gives the test the PATH the tests started with and returns
// its tsc 7; the version asked of it before is forgotten, so the rule asks
// it again.
func launcherTsc7(t *testing.T) string {
	t.Helper()
	t.Setenv("PATH", launcherPATH)
	tsc := globalTsc7(t)
	toolVersionsMu.Lock()
	delete(toolVersions, tsc)
	toolVersionsMu.Unlock()
	return tsc
}

func TestTscRunsTheNpmLauncherOfTheProjectAndTheGlobalTsc(t *testing.T) {
	tsc := launcherTsc7(t)
	root := tscProject(t, tsc, map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "import { double } from './math'\n\nexport const n: number = double('2')\n",
		"src/math.ts":   "export function double(x: number): number {\n  const s: string = x\n  return x * 2\n}\n",
		"tools/run.ts":  "const args = process.argv.slice(2)\nfunction first(list) { return list[0] }\nconsole.log(first(args))\n",
	})

	assert.Equal(t, []string{
		"high src/main.ts:3 TS2345",
		"high src/math.ts:2 TS2322",
		"high tools/run.ts:2 TS7006",
	}, tscFindings(t, root))

	// A changed file is checked again, by the project's launcher.
	patterntest.WriteProjectFile(t, root, "src/math.ts", "export function double(x: number): number {\n  return x * 2\n}\n")
	assert.Equal(t, []string{
		"high src/main.ts:3 TS2345",
		"high tools/run.ts:2 TS7006",
	}, tscFindings(t, root))
}

func TestTscGlobalCompilerRunsTheNpmLauncher(t *testing.T) {
	launcherTsc7(t)
	root := tscProject(t, "", map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 'one'\n",
	})

	contexts := tscContexts(t, root)
	rule := NewTscRule()
	require.NoError(t, rule.Configure(map[string]any{"compiler": "global"}))
	require.NoError(t, rule.CheckTools(contexts))
	var found []string
	for _, ctx := range contexts {
		for _, v := range rule.AnalyzeFile(ctx) {
			code, _, _ := strings.Cut(v.Message, ":")
			found = append(found, fmt.Sprintf("%s %s:%d %s", v.Severity, v.File, v.Line, code))
		}
	}
	sort.Strings(found)
	assert.Equal(t, []string{"high src/main.ts:1 TS2322"}, found)
}

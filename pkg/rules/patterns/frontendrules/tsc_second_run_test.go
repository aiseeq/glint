package frontendrules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func secondRunTsc(t *testing.T, version, name, source string) (string, string) {
	t.Helper()
	compiler := filepath.Join(t.TempDir(), name)
	log := filepath.Join(t.TempDir(), name+"-runs")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = --version ]; then printf 'Version %s\n'; exit 0; fi
case "$*" in
  *--showConfig*) printf '%%s\n' '{"compilerOptions":{"strict":true,"noEmit":true}}'; exit 0 ;;
esac
printf 'run\n' >> %q
previous=
for arg in "$@"; do
  if [ "$previous" = --tsBuildInfoFile ]; then printf '{}\n' > "$arg"; fi
  previous="$arg"
done
printf '%%b\n' %q
`, version, log, source)
	require.NoError(t, writeTestExecutable(compiler, []byte(script)))
	return compiler, log
}

func secondRunCount(t *testing.T, log string) int {
	t.Helper()
	data, err := os.ReadFile(log)
	if os.IsNotExist(err) {
		return 0
	}
	require.NoError(t, err)
	return strings.Count(string(data), "run\n")
}

func checkSecondRun(t *testing.T, localVersion, globalVersion string, want int, testName string) {
	t.Helper()
	root := t.TempDir()
	config := filepath.Join(root, "tsconfig.json")
	source := filepath.Join(root, "main.ts")
	require.NoError(t, os.WriteFile(config, []byte(`{"compilerOptions":{"strict":true,"noEmit":true},"files":["main.ts"]}`), 0o644))
	require.NoError(t, os.WriteFile(source, []byte("export const value = 1\n"), 0o644))
	local, localLog := secondRunTsc(t, localVersion, "local-tsc", source)
	global, globalLog := secondRunTsc(t, globalVersion, "global-tsc", source)
	answer, err := runTscProgram(&tscProgram{config: config, tsc: local}, globalTscInfo{path: global})
	require.NoError(t, err)
	require.Empty(t, answer.Errors)
	require.Empty(t, answer.TSC7)
	require.Equal(t, 1, secondRunCount(t, localLog), testName+" project tsc runs")
	require.Equal(t, want-1, secondRunCount(t, globalLog), testName+" global tsc runs")
}

func TestTscSecondRunSameVersionSkip(t *testing.T) {
	t.Parallel()
	checkSecondRun(t, "7.0.2", "7.0.2", 1, t.Name())
}

func TestTscSecondRunTypeScript5KeepsTwoRuns(t *testing.T) {
	t.Parallel()
	checkSecondRun(t, "5.9.3", "7.0.2", 2, t.Name())
}

func TestTscSecondRunDifferentVersionKeepsTwoRuns(t *testing.T) {
	t.Parallel()
	checkSecondRun(t, "7.0.1", "7.0.2", 2, t.Name())
}

package perf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGlint writes a glint stand-in that sleeps, prints stderr and exits as
// the body says, and counts its runs in a file next to it.
func fakeGlint(t *testing.T, body string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	path := filepath.Join(dir, "glint")
	script := "#!/usr/bin/env bash\necho run >> " + runs + "\n" + body + "\n"
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path, runs
}

func runWarmCheck(t *testing.T, glint string, env ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", "warm-check.sh", t.TempDir())
	cmd.Env = append(append(os.Environ(), "GLINT="+glint), env...)
	out, err := cmd.Output()
	if exit, ok := err.(*exec.ExitError); ok {
		return string(out), exit.ExitCode()
	}
	require.NoError(t, err)
	return string(out), 0
}

func runCount(t *testing.T, runs string) int {
	t.Helper()
	data, err := os.ReadFile(runs)
	require.NoError(t, err)
	return strings.Count(string(data), "run")
}

func TestWarmCheckPrintsMedianOfFiveRuns(t *testing.T) {
	glint, runs := fakeGlint(t, "sleep 0.05")
	out, code := runWarmCheck(t, glint)
	require.Equal(t, 0, code)
	ms, err := strconv.Atoi(strings.TrimSpace(out))
	require.NoError(t, err, "one number on stdout: %q", out)
	assert.GreaterOrEqual(t, ms, 50)
	assert.Equal(t, 5, runCount(t, runs))
}

// Findings make glint exit 1 without an Error: line: the run counts.
func TestWarmCheckCountsARunWithFindings(t *testing.T) {
	glint, runs := fakeGlint(t, "echo 'medium: something' >&2; exit 1")
	out, code := runWarmCheck(t, glint)
	require.Equal(t, 0, code)
	assert.Regexp(t, `^\d+\n$`, out)
	assert.Equal(t, 5, runCount(t, runs))
}

// A real failure prints Error: and ends the measure with glint's code.
func TestWarmCheckFailsOnGlintError(t *testing.T) {
	glint, runs := fakeGlint(t, "echo 'Error: load failed' >&2; exit 1")
	out, code := runWarmCheck(t, glint)
	assert.Equal(t, 1, code)
	assert.Empty(t, out)
	assert.Equal(t, 1, runCount(t, runs))
}

// A slower glint gives fewer runs, never a timeout and never "no data".
func TestWarmCheckStopsAtTheBudget(t *testing.T) {
	glint, runs := fakeGlint(t, "sleep 1.1")
	out, code := runWarmCheck(t, glint, "GLINT_WARM_BUDGET_S=2")
	require.Equal(t, 0, code)
	ms, err := strconv.Atoi(strings.TrimSpace(out))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, ms, 1100)
	assert.Equal(t, 2, runCount(t, runs))
}

// A long first run shrinks the budget to the limit minus that run: the
// command still ends within the limit on the day of the measure.
func TestWarmCheckLongRunShrinksTheBudget(t *testing.T) {
	glint, runs := fakeGlint(t, "sleep 1.1")
	_, code := runWarmCheck(t, glint, "GLINT_WARM_BUDGET_S=3", "GLINT_WARM_LIMIT_S=2")
	require.Equal(t, 0, code)
	assert.Equal(t, 1, runCount(t, runs))
}

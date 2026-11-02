package main

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/deadcode"
)

// writeReportScopeModule writes a module where a project rule judges a.go by
// what b.go does: b.go calls one export of a.go and leaves the other unused,
// a.go carries a suppression that silences nothing, and b.go has an unused
// export of its own, so a run over one file has findings the other lacks.
func writeReportScopeModule(t *testing.T, root string) {
	t.Helper()
	writeModuleFile(t, root, "go.mod", "module example.com/scope\n\ngo 1.24\n")
	writeModuleFile(t, root, ".glint.yaml", "version: 1\n")
	writeModuleFile(t, root, "internal/a/a.go", `package a

// Used is called from package b.
func Used() int { return 1 } //nolint:unused-internal-export // kept for the plugin API

// Dead is called by nobody.
func Dead() int { return 2 }
`)
	writeModuleFile(t, root, "internal/b/b.go", `package b

import "example.com/scope/internal/a"

// Sum adds the exported value.
func Sum() int { return a.Used() + 1 }

// Spare is called by nobody.
func Spare() int { return 3 }
`)
	writeModuleFile(t, root, "cmd/run/main.go", `package main

import "example.com/scope/internal/b"

func main() { println(b.Sum()) }
`)
}

// scopeFindings runs glint over paths as the check command does, with the result
// cache in cacheDir ("" runs without a cache), and returns "file:line rule".
func scopeFindings(t *testing.T, cacheDir string, paths ...string) []string {
	t.Helper()
	withFlags(t, "", "unused-internal-export", "stale-suppression")
	if cacheDir != "" {
		t.Setenv("GLINT_CACHE_DIR", cacheDir)
	}
	roots, err := analysisRoots(paths)
	require.NoError(t, err)
	var found []string
	for _, root := range roots {
		cfg, enabledRules, err := loadConfig(root.dir)
		require.NoError(t, err)
		prepared, err := prepareScopedAnalysis(core.NewGoProjectLoader(), root, cfg, enabledRules, cacheDir != "")
		require.NoError(t, err)
		rules.ResetState(enabledRules)
		violations, panics, err := analyzePrepared(prepared, enabledRules, cfg)
		require.NoError(t, err)
		require.Empty(t, panics)
		if prepared.cache != nil {
			require.NoError(t, prepared.cache.save())
		}
		violations, suppressions := core.SplitSuppressions(violations)
		stale, err := staleSuppressions(enabledRules, deadcode.StaleSuppressionRun{
			Contexts: prepared.contexts, Suppressions: suppressions, Config: cfg, WholeRoot: root.wholeRoot(),
		})
		require.NoError(t, err)
		for _, v := range append(violations, stale...) {
			file := v.File
			if !filepath.IsAbs(file) {
				file = filepath.Join(root.dir, file)
			}
			found = append(found, fmt.Sprintf("%s:%d %s", file, v.Line, v.Rule))
		}
	}
	slices.Sort(found)
	return found
}

// only keeps the findings of the files under prefix.
func only(found []string, prefix string) []string {
	var kept []string
	for _, f := range found {
		if strings.HasPrefix(f, prefix) {
			kept = append(kept, f)
		}
	}
	return kept
}

// A run over some files reports what the full run reports for them, the
// suppressions in them included: the cross-file rule judges a.go by b.go
// though b.go is outside the run.
func TestReportScopeMatchesTheFullRunFilteredToTheScope(t *testing.T) {
	root := t.TempDir()
	writeReportScopeModule(t, root)
	a := filepath.Join(root, "internal/a/a.go")
	b := filepath.Join(root, "internal/b/b.go")

	full := scopeFindings(t, "", root)
	require.NotEmpty(t, only(full, a), "a.go must have findings, or the test proves nothing")
	assert.Contains(t, full, a+":4 stale-suppression")
	assert.Contains(t, full, a+":7 unused-internal-export")
	assert.Contains(t, full, b+":9 unused-internal-export")

	assert.Equal(t, only(full, a), scopeFindings(t, "", a))
	assert.Equal(t, only(full, b), scopeFindings(t, "", b))
}

// Partial runs over other files and full runs, one after another over one
// cache directory, give what the same runs give without a cache.
func TestReportScopeCacheSequenceMatchesUncachedRuns(t *testing.T) {
	root := t.TempDir()
	writeReportScopeModule(t, root)
	a := filepath.Join(root, "internal/a/a.go")
	b := filepath.Join(root, "internal/b/b.go")
	cache := t.TempDir()

	for _, paths := range [][]string{{a}, {b}, {root}, {a}, {root}} {
		want := scopeFindings(t, "", paths...)
		assert.Equal(t, want, scopeFindings(t, cache, paths...), "run over %v", paths)
	}
}

// The scope is the same files however the path is spelled: absolute,
// relative to the working directory, or with a leading ./.
func TestReportScopeIgnoresHowThePathIsSpelled(t *testing.T) {
	root := t.TempDir()
	writeReportScopeModule(t, root)
	t.Chdir(root)
	want := scopeFindings(t, "", filepath.Join(root, "internal/a/a.go"))
	require.NotEmpty(t, want)
	for _, path := range []string{"internal/a/a.go", "./internal/a/a.go"} {
		assert.Equal(t, want, scopeFindings(t, "", path), path)
	}
}

// Files of two roots in one run: each root reports what a run over its own
// file reports.
func TestReportScopeKeepsEachRootToItsOwnFiles(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	writeReportScopeModule(t, first)
	writeReportScopeModule(t, second)
	a1 := filepath.Join(first, "internal/a/a.go")
	b2 := filepath.Join(second, "internal/b/b.go")

	both := scopeFindings(t, "", a1, b2)
	assert.Equal(t, scopeFindings(t, "", a1), only(both, first))
	assert.Equal(t, scopeFindings(t, "", b2), only(both, second))
}

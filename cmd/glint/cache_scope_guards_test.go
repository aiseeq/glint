package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/dbrules"
	"github.com/stretchr/testify/require"
)

func TestWholeRootRuleSubsetPreservesCachedRootFindings(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	path := filepath.Join(root, "a.ts")
	cfg := core.DefaultConfig()
	newRule := func(name string) *indexedFindingRule {
		r := newIndexedFindingRule()
		r.BaseRule = rules.NewBaseRule(name, "patterns", "test indexed results", core.SeverityMedium)
		return r
	}
	files := func(content string) []*core.FileContext {
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return []*core.FileContext{core.NewFileContext(path, root, []byte(content), cfg)}
	}
	run := func(contexts []*core.FileContext, selected []rules.Rule, all bool) core.ViolationList {
		cache := openRootCache(root, nil, cfg, false)
		require.NotNil(t, cache)
		cache.keyProject("unchanged-go-inputs", nil, selected, "")
		rootRules := selected
		if all {
			rootRules = append(rules.GetEnabled(cfg), selected...)
		}
		found, panics, err := analyzeProjectContained(contexts, contexts, selected, rootRules, cfg, nil, cache)
		require.NoError(t, err)
		require.Empty(t, panics)
		require.NoError(t, cache.save())
		return found
	}
	firstA, firstB := newRule("test-root-a"), newRule("test-root-b")
	original := files("export const a = 1\n")
	first := run(original, []rules.Rule{firstA, firstB}, true)
	require.Len(t, first, 2)
	require.Equal(t, 1, firstB.indexCalls)
	partial := newRule("test-root-a")
	run(files("export const a = 2\n"), []rules.Rule{partial}, false)
	require.Equal(t, 1, partial.indexCalls)
	lastA, lastB := newRule("test-root-a"), newRule("test-root-b")
	original = files("export const a = 1\n")
	got := run(original, []rules.Rule{lastA, lastB}, true)
	require.Zero(t, lastA.indexCalls)
	require.Zero(t, lastB.indexCalls)
	require.Zero(t, lastB.fileCalls)
	uncached, panics, err := analyzeProjectContained(original, original,
		[]rules.Rule{newRule("test-root-a"), newRule("test-root-b")}, nil, cfg, nil, nil)
	require.NoError(t, err)
	require.Empty(t, panics)
	require.Equal(t, fingerprint(uncached), fingerprint(got))
}

func TestRootInputsWithNoAnalyzedFiles(t *testing.T) {
	for _, scenario := range []string{"empty", "unrecognized", "markdown", "scope"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("GLINT_CACHE_DIR", t.TempDir())
			runRoot := analysisRoot{dir: root, scopes: []string{root}}
			if scenario == "unrecognized" {
				require.NoError(t, os.WriteFile(filepath.Join(root, "data.bin"), []byte("data"), 0o600))
			}
			if scenario == "markdown" {
				require.NoError(t, os.WriteFile(filepath.Join(root, "README.md"), []byte("# Example\n"), 0o600))
			}
			if scenario == "scope" {
				scope := filepath.Join(root, "empty")
				require.NoError(t, os.Mkdir(scope, 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(root, "outside.go"), []byte("package demo\n"), 0o600))
				runRoot.scopes = []string{scope}
			}
			cfg := core.DefaultConfig()
			list := []rules.Rule{dbrules.NewSQLChildRowsIncludeVoidedParentRule()}
			run := func(cached bool) core.ViolationList {
				prepared, err := prepareScopedAnalysis(core.NewGoProjectLoader(), runRoot, cfg, list, cached)
				require.NoError(t, err)
				if scenario == "markdown" {
					require.Len(t, prepared.rootFiles, 1)
				} else {
					require.Empty(t, prepared.rootFiles)
				}
				found, panics, err := analyzePrepared(prepared, list, cfg)
				require.NoError(t, err)
				require.Empty(t, panics)
				return found
			}
			uncached := run(false)
			var cached core.ViolationList
			require.NotPanics(t, func() { cached = run(true) })
			require.Equal(t, fingerprint(uncached), fingerprint(cached))
		})
	}
}

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/require"
)

type configIndexedFindingRule struct{ *indexedFindingRule }

func (r *configIndexedFindingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	r.fileCalls++
	return []*core.Violation{r.CreateViolation(ctx.RelPath, 2, "configured finding")}
}

// This checks cache keys through analyzeProjectContained, whose project
// indexes run on parallel workers (runProjectFileIndexes), so it stays in the
// race build.
func TestRootCacheConfigAndReportSettings(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	source := `package repo
func report() {}
`
	writeModuleFile(t, root, "report.go", source)
	writeConfig := func(content string) {
		require.NoError(t, os.WriteFile(filepath.Join(root, ".glint.yaml"), []byte(content), 0o600))
	}
	baseConfig := `version: 1
categories:
  patterns:
    enabled: true
`
	writeConfig(baseConfig)
	newRules := func() []*configIndexedFindingRule {
		return []*configIndexedFindingRule{
			{indexedFindingRule: &indexedFindingRule{BaseRule: rules.NewBaseRule("cache-config-exception", "patterns", "test config exception cache", core.SeverityMedium)}},
			{indexedFindingRule: &indexedFindingRule{BaseRule: rules.NewBaseRule("cache-config-severity", "patterns", "test config severity cache", core.SeverityMedium)}},
		}
	}
	run := func(useCache bool, reportSettings bool) (core.ViolationList, *resultCache, []*configIndexedFindingRule) {
		t.Helper()
		cfg, err := core.LoadConfigWithDefaults(root)
		require.NoError(t, err)
		if reportSettings {
			cfg.Settings.Output, cfg.Settings.MinSeverity, cfg.Settings.FailOn = "summary", "high", "low"
		}
		contexts := []*core.FileContext{core.NewFileContext(filepath.Join(root, "report.go"), root, []byte(source), cfg)}
		require.NoError(t, core.ParseGoFiles(root, contexts, false))
		checks := newRules()
		var cache *resultCache
		if useCache {
			cache = openRootCache(root, nil, cfg, false)
			require.NotNil(t, cache)
		}
		rootRules := append(rules.GetEnabled(cfg), checks[0], checks[1])
		found, panics, err := analyzeProjectContained(contexts, contexts, []rules.Rule{checks[0], checks[1]}, rootRules, cfg, nil, cache)
		require.NoError(t, err)
		require.Empty(t, panics)
		if cache != nil {
			require.NoError(t, cache.save())
		}
		return found, cache, checks
	}

	_, _, firstRules := run(true, false)
	require.Equal(t, 1, firstRules[0].fileCalls)
	require.Equal(t, 1, firstRules[1].fileCalls)

	writeConfig(`version: 1
categories:
  patterns:
    enabled: true
    rules:
      cache-config-exception:
        exceptions:
          - file: report.go
            function: report
            reason: synthetic exception
`)
	cachedException, _, exceptionRules := run(true, false)
	uncachedException, _, _ := run(false, false)
	require.Equal(t, fingerprint(uncachedException), fingerprint(cachedException))
	exceptionFindings, exceptionSuppressions := core.SplitSuppressions(cachedException)
	require.Len(t, exceptionFindings, 1)
	require.Equal(t, "cache-config-severity", exceptionFindings[0].Rule)
	require.Len(t, exceptionSuppressions, 1)
	require.Equal(t, "cache-config-exception", exceptionSuppressions[0].Rule)
	require.Equal(t, 1, exceptionRules[0].fileCalls)
	require.Equal(t, 1, exceptionRules[1].fileCalls)
	// Report-only settings leave the root rules reusable.
	_, reportCache, reportRules := run(true, true)
	require.True(t, reportCache.rootRuleReusable(reportRules[0]))
	require.True(t, reportCache.rootRuleReusable(reportRules[1]))
	require.Zero(t, reportRules[0].fileCalls)
	require.Zero(t, reportRules[1].fileCalls)

	writeConfig(`version: 1
categories:
  patterns:
    enabled: true
    rules:
      cache-config-exception:
        exceptions:
          - file: report.go
            function: report
            reason: synthetic exception
      cache-config-severity:
        severity: high
`)
	cachedSeverity, _, severityRules := run(true, false)
	uncachedSeverity, _, _ := run(false, false)
	require.Equal(t, fingerprint(uncachedSeverity), fingerprint(cachedSeverity))
	severityFindings, severitySuppressions := core.SplitSuppressions(cachedSeverity)
	require.Len(t, severityFindings, 1)
	require.Equal(t, "high", severityFindings[0].Severity.String())
	require.Len(t, severitySuppressions, 1)
	require.Equal(t, 1, severityRules[0].fileCalls)
	require.Equal(t, 1, severityRules[1].fileCalls)
	_, reportCache, reportRules = run(true, true)
	require.True(t, reportCache.rootRuleReusable(reportRules[0]))
	require.True(t, reportCache.rootRuleReusable(reportRules[1]))
	require.Zero(t, reportRules[0].fileCalls)
	require.Zero(t, reportRules[1].fileCalls)
}

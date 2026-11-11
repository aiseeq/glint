package main

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/frontendrules"
	"github.com/aiseeq/glint/pkg/rules/patterns/qarules"
	"github.com/aiseeq/glint/pkg/rules/patterns/shellrules"
)

// countingRule reports one finding per file and counts how often it runs.
type countingRule struct {
	*rules.BaseRule
	calls        atomic.Int32
	readsOthers  bool
	contextValue int
}

type indexedFindingRule struct {
	*rules.BaseRule
	indexCalls int
	fileCalls  int
	value      string
}

func (r *indexedFindingRule) ResetState()                         { r.indexCalls = 0 }
func (r *indexedFindingRule) UseProjectFiles([]*core.FileContext) { r.indexCalls++ }
func (*indexedFindingRule) RootFilesOnlyProjectFiles()            {}
func (r *indexedFindingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	r.fileCalls++
	return []*core.Violation{r.CreateViolation(ctx.RelPath, 1, "indexed finding "+r.value)}
}

type excludedInputFindingRule struct{ *indexedFindingRule }

func (*excludedInputFindingRule) ProjectFilesCacheExclusion() string {
	return "depends on external state"
}

type diskInputFindingRule struct{ *indexedFindingRule }

func (*diskInputFindingRule) ReadsOtherFiles() bool { return true }

type externalToolFindingRule struct{ *indexedFindingRule }

func (*externalToolFindingRule) CheckTools([]*core.FileContext) error { return nil }

func runIndexedCached(t *testing.T, dir string, rule rules.Rule, root, run []*core.FileContext) core.ViolationList {
	t.Helper()
	return runIndexedCachedRoot(t, dir, "/project", rule, root, run)
}

func runIndexedCachedRoot(t *testing.T, dir, projectRoot string, rule rules.Rule, root, run []*core.FileContext) core.ViolationList {
	t.Helper()
	cache, err := openResultCache(dir, projectRoot, "", "build", "stamp")
	require.NoError(t, err)
	cache.keyProject("test-inputs", nil, []rules.Rule{rule}, "")
	cfg := core.DefaultConfig()
	rootRules := append(rules.GetEnabled(cfg), rule)
	got, panics, err := analyzeProjectContained(run, root, []rules.Rule{rule}, rootRules, cfg, nil, cache)
	require.NoError(t, err)
	require.Empty(t, panics)
	require.NoError(t, cache.save())
	return got
}

func runIndexedUncached(t *testing.T, rule rules.Rule, root, run []*core.FileContext) core.ViolationList {
	t.Helper()
	cfg := core.DefaultConfig()
	rootRules := append(rules.GetEnabled(cfg), rule)
	got, panics, err := analyzeProjectContained(run, root, []rules.Rule{rule}, rootRules, cfg, nil, nil)
	require.NoError(t, err)
	require.Empty(t, panics)
	return got
}

func newIndexedFindingRule() *indexedFindingRule {
	return &indexedFindingRule{BaseRule: rules.NewBaseRule("indexed-finding", "patterns", "test indexed results", core.SeverityMedium)}
}

func newIndexedFindingRuleWithValue(value string) *indexedFindingRule {
	rule := newIndexedFindingRule()
	rule.value = value
	return rule
}

func TestProjectFileRuleFindingsAreReusedForUnchangedRoot(t *testing.T) {
	dir := t.TempDir()
	root := []*core.FileContext{goContext(t, "a.go", "package a\n"), goContext(t, "b.go", "package b\n")}
	firstRule := newIndexedFindingRule()
	want := runIndexedCached(t, dir, firstRule, root, root)
	require.Equal(t, 1, firstRule.indexCalls)
	require.Equal(t, 2, firstRule.fileCalls)

	secondRule := newIndexedFindingRule()
	got := runIndexedCached(t, dir, secondRule, root, root)
	assert.Equal(t, fingerprint(want), fingerprint(got))
	assert.Zero(t, secondRule.indexCalls, "the hit skips building the index")
	assert.Zero(t, secondRule.fileCalls, "the hit skips the per-file rule")
}

func TestPartialProjectFileRunDoesNotReplaceWholeRootFindings(t *testing.T) {
	dir := t.TempDir()
	root := []*core.FileContext{goContext(t, "a.go", "package a\n"), goContext(t, "b.go", "package b\n")}
	full := newIndexedFindingRule()
	want := runIndexedCached(t, dir, full, root, root)

	changed := []*core.FileContext{root[0], goContext(t, "b.go", "package b // changed\n")}
	partialRule := newIndexedFindingRule()
	partial := runIndexedCached(t, dir, partialRule, changed, []*core.FileContext{changed[0]})
	require.Len(t, partial, 1)
	assert.Equal(t, 1, partialRule.indexCalls, "changed root input reruns on a partial request")

	lastRule := newIndexedFindingRule()
	got := runIndexedCached(t, dir, lastRule, changed, changed)
	assert.Equal(t, fingerprint(want), fingerprint(got))
	assert.Equal(t, 1, lastRule.indexCalls, "partial result was not written as a whole-root result")
	assert.Equal(t, fingerprint(runIndexedUncached(t, newIndexedFindingRule(), changed, changed)), fingerprint(got))
}

func TestProjectFilesWithExternalInputsMatchUncachedResults(t *testing.T) {
	root := []*core.FileContext{goContext(t, "a.go", "package a\n")}
	for _, test := range []struct {
		name string
		make func(value string) rules.Rule
	}{
		{name: "environment, git, time, or external file", make: func(value string) rules.Rule {
			return &excludedInputFindingRule{indexedFindingRule: newIndexedFindingRuleWithValue(value)}
		}},
		{name: "disk files and symlink targets", make: func(value string) rules.Rule {
			return &diskInputFindingRule{indexedFindingRule: newIndexedFindingRuleWithValue(value)}
		}},
		{name: "external program", make: func(value string) rules.Rule {
			return &externalToolFindingRule{indexedFindingRule: newIndexedFindingRuleWithValue(value)}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			first := test.make("old input")
			runIndexedCached(t, dir, first, root, root)
			second := test.make("changed input")
			got := runIndexedCached(t, dir, second, root, root)
			want := runIndexedUncached(t, test.make("changed input"), root, root)
			assert.Equal(t, fingerprint(want), fingerprint(got))
		})
	}
}

func TestProjectFilesCacheRulesAreExplicitlyAudited(t *testing.T) {
	for _, category := range rules.Categories() {
		for _, rule := range rules.GetByCategory(category) {
			if _, ok := rule.(rules.ProjectFilesRule); !ok {
				continue
			}
			name := rule.Name()
			if _, ok := rule.(rules.RootFilesAndCacheInputs); ok {
				assert.True(t, rootProjectRuleCacheable(rule), "%s declares its external inputs", name)
				continue
			}
			_, external := rule.(rules.ExternalToolRule)
			_, excluded := rule.(rules.ProjectFilesCacheExclusion)
			reader, readsOtherFiles := rule.(rules.ReadsOtherFiles)
			if readsOtherFiles && reader.ReadsOtherFiles() || external || excluded {
				assert.False(t, rootProjectRuleCacheable(rule), "%s has external inputs", name)
				if exclusion, ok := rule.(rules.ProjectFilesCacheExclusion); ok {
					assert.NotEmpty(t, exclusion.ProjectFilesCacheExclusion(), "%s must explain its exclusion", name)
				}
				continue
			}
			assert.Implements(t, (*rules.RootFilesOnlyProjectFiles)(nil), rule, "%s must declare root-only inputs", name)
			assert.True(t, rootProjectRuleCacheable(rule), "%s is audited for root-only inputs", name)
		}
	}
}

func newCountingRule(name string, readsOthers bool) *countingRule {
	return &countingRule{
		BaseRule:     rules.NewBaseRule(name, "patterns", "counts its runs", core.SeverityMedium),
		readsOthers:  readsOthers,
		contextValue: 7,
	}
}

func (r *countingRule) ReadsOtherFiles() bool { return r.readsOthers }

func (r *countingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	r.calls.Add(1)
	v := r.CreateViolation(ctx.RelPath, 1, "seen "+ctx.Lines[0])
	v.WithContext("count", r.contextValue)
	v.WithContext("pattern", "counting")
	return []*core.Violation{v}
}

func runCached(t *testing.T, dir, stamp string, contexts []*core.FileContext, list []rules.Rule) (core.ViolationList, *resultCache) {
	t.Helper()
	cache, err := openResultCache(dir, "/project", "", "build", stamp)
	require.NoError(t, err)
	violations, err := analyzeFiles(contexts, list, core.DefaultConfig(), nil, cache)
	require.NoError(t, err)
	require.NoError(t, cache.save())
	return violations, cache
}

func TestResultCacheUnchangedSaveTouchesWithoutReplacing(t *testing.T) {
	dir := t.TempDir()
	rule := newCountingRule("counting-local", false)
	contexts := []*core.FileContext{goContext(t, "a.go", "package a\n")}
	first, firstCache := runCached(t, dir, "stamp", contexts, []rules.Rule{rule})
	before, err := os.Stat(firstCache.path)
	require.NoError(t, err)
	beforeBytes, err := os.ReadFile(firstCache.path)
	require.NoError(t, err)

	secondCache, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	second, err := analyzeFiles(contexts, []rules.Rule{rule}, core.DefaultConfig(), nil, secondCache)
	require.NoError(t, err)
	oldTime := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(secondCache.path, oldTime, oldTime))
	require.NoError(t, secondCache.save())

	after, err := os.Stat(secondCache.path)
	require.NoError(t, err)
	afterBytes, err := os.ReadFile(secondCache.path)
	require.NoError(t, err)
	assert.True(t, os.SameFile(before, after), "unchanged cache keeps its inode")
	assert.Equal(t, beforeBytes, afterBytes, "unchanged cache keeps its contents")
	assert.True(t, after.ModTime().After(oldTime), "unchanged cache is touched for LRU pruning")
	assert.Equal(t, fingerprint(first), fingerprint(second))

	changed := []*core.FileContext{goContext(t, "a.go", "package a // changed\n")}
	third, changedCache := runCached(t, dir, "stamp", changed, []rules.Rule{rule})
	changedInfo, err := os.Stat(changedCache.path)
	require.NoError(t, err)
	assert.False(t, os.SameFile(after, changedInfo), "changed findings replace the cache")
	uncached, err := analyzeFiles(changed, []rules.Rule{newCountingRule("counting-local", false)}, core.DefaultConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, fingerprint(uncached), fingerprint(third), "cached findings match a full run")
}

func TestCacheFingerprintSetsRoundTripAndDeduplicate(t *testing.T) {
	shared := map[string]string{"rule-a": "fingerprint-a", "rule-b": "fingerprint-b"}
	other := map[string]string{"rule-a": "fingerprint-a", "rule-c": "fingerprint-c"}
	contents := cacheContents{Stamp: "stamp", Entries: map[string]cacheEntry{
		"a.go": {Fingerprints: maps.Clone(shared)},
		"b.go": {Fingerprints: maps.Clone(shared)},
		"c.go": {Fingerprints: maps.Clone(other)},
	}}
	var expandedBytes, compactBytes bytes.Buffer
	require.NoError(t, gob.NewEncoder(&expandedBytes).Encode(contents))
	compact := compactCacheFingerprints(contents)
	require.Len(t, compact.FingerprintSets, 2)
	require.NoError(t, gob.NewEncoder(&compactBytes).Encode(compact))
	assert.Less(t, compactBytes.Len(), expandedBytes.Len(), "shared fingerprint maps are serialized once")
	require.NoError(t, expandCacheFingerprints(&compact))
	assert.Nil(t, compact.FingerprintSets)
	assert.Equal(t, contents, compact)
}

func TestResultCacheReusesFindingsOfUnchangedFiles(t *testing.T) {
	dir := t.TempDir()
	local := newCountingRule("counting-local", false)
	reader := newCountingRule("counting-reader", true)
	list := []rules.Rule{local, reader}
	contexts := []*core.FileContext{
		goContext(t, "a.go", "package a\n"),
		goContext(t, "b.go", "package b\n"),
	}

	first, _ := runCached(t, dir, "stamp-1", contexts, list)
	require.Equal(t, int32(2), local.calls.Load())

	second, cache := runCached(t, dir, "stamp-1", contexts, list)
	assert.Equal(t, int32(2), local.calls.Load(), "an unchanged file is not analyzed again")
	assert.Equal(t, int32(4), reader.calls.Load(), "a rule that reads other files always runs")
	assert.Equal(t, 2, cache.reused)
	assert.Equal(t, fingerprint(first), fingerprint(second))
	for _, v := range second {
		assert.IsType(t, 0, v.Context["count"], "context values keep their type")
	}

	second[0].Message = "changed by a caller"
	third, _ := runCached(t, dir, "stamp-1", contexts, list)
	assert.Equal(t, fingerprint(first), fingerprint(third), "callers get copies, not the stored findings")

	contexts[1] = goContext(t, "b.go", "package b // edited\n")
	runCached(t, dir, "stamp-1", contexts, list)
	assert.Equal(t, int32(3), local.calls.Load(), "only the edited file is analyzed again")

	runCached(t, dir, "stamp-2", contexts, list)
	assert.Equal(t, int32(5), local.calls.Load(), "another stamp discards the cache")
}

func TestResultCacheInvalidatesOnlyRulesWithChangedFingerprint(t *testing.T) {
	dir := t.TempDir()
	rule := newCountingRule("fingerprinted", false)
	ctx := []*core.FileContext{goContext(t, "a.go", "package a\n")}
	run := func(fingerprint string) core.ViolationList {
		cache, err := openResultCache(dir, "/project", "", "build", "stamp")
		require.NoError(t, err)
		cache.ruleFingerprints[reflect.TypeFor[countingRule]().PkgPath()] = fingerprint
		got, err := analyzeFiles(ctx, []rules.Rule{rule}, core.DefaultConfig(), nil, cache)
		require.NoError(t, err)
		require.NoError(t, cache.save())
		return got
	}

	first := run("package-A")
	firstInfo, err := os.Stat(stampedResultCachePath(dir, "/project", "build", "stamp"))
	require.NoError(t, err)
	second := run("package-B")
	secondInfo, err := os.Stat(stampedResultCachePath(dir, "/project", "build", "stamp"))
	require.NoError(t, err)
	assert.False(t, os.SameFile(firstInfo, secondInfo), "a changed rule fingerprint replaces the cache")
	assert.Equal(t, fingerprint(first), fingerprint(second))
	uncached, err := analyzeFiles(ctx, []rules.Rule{newCountingRule("fingerprinted", false)}, core.DefaultConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, fingerprint(uncached), fingerprint(second), "changed rule findings match a full run")
	assert.Equal(t, int32(2), rule.calls.Load(), "a package change reruns its findings")
	third := run("package-B")
	assert.Equal(t, fingerprint(second), fingerprint(third))
	assert.Equal(t, int32(2), rule.calls.Load(), "the rebuilt package now reuses its findings")
}

func TestResultCacheChangedStampRewritesAndMatchesUncached(t *testing.T) {
	dir := t.TempDir()
	ctx := []*core.FileContext{goContext(t, "a.go", "package a\n")}
	rule := newCountingRule("counting-local", false)
	first, cache := runCached(t, dir, "config-A", ctx, []rules.Rule{rule})
	firstInfo, err := os.Stat(cache.path)
	require.NoError(t, err)
	second, nextCache := runCached(t, dir, "config-B", ctx, []rules.Rule{newCountingRule("counting-local", false)})
	secondInfo, err := os.Stat(nextCache.path)
	require.NoError(t, err)
	assert.False(t, os.SameFile(firstInfo, secondInfo), "a changed config stamp replaces the cache")
	assert.Equal(t, fingerprint(first), fingerprint(second))
	uncached, err := analyzeFiles(ctx, []rules.Rule{newCountingRule("counting-local", false)}, core.DefaultConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, fingerprint(uncached), fingerprint(second), "changed config findings match a full run")
}

func TestResultCacheEmitsOnlyEnabledRuleFindings(t *testing.T) {
	dir := t.TempDir()
	removed := newCountingRule("removed-rule", false)
	active := newCountingRule("active-rule", false)
	ctx := []*core.FileContext{goContext(t, "a.go", "package a\n")}
	runCached(t, dir, "stamp", ctx, []rules.Rule{removed})
	got, _ := runCached(t, dir, "stamp", ctx, []rules.Rule{active})
	require.Len(t, got, 1)
	assert.Equal(t, active.Name(), got[0].Rule)
}

func TestRestrictedRunPreservesFullRunCache(t *testing.T) {
	dir := t.TempDir()
	contexts := []*core.FileContext{goContext(t, "a.go", "package a\n"), goContext(t, "b.go", "package b\n")}
	full := newCountingRule("full-rule", false)
	restricted := newCountingRule("restricted-rule", true)
	run := func(stamp string, rule *countingRule) *resultCache {
		_, cache := runCached(t, dir, stamp, contexts, []rules.Rule{rule})
		return cache
	}

	first := run("loader", full)
	assert.Zero(t, first.reused)
	assert.Equal(t, int32(2), full.calls.Load())

	second, err := openResultCache(dir, "/project", "", "build", "loader")
	require.NoError(t, err)
	_, err = analyzeFiles(contexts, []rules.Rule{restricted}, core.DefaultConfig(), nil, second)
	require.NoError(t, err)
	require.NoError(t, second.save())
	assert.Equal(t, int32(2), restricted.calls.Load())

	third := run("loader", full)
	assert.Equal(t, 2, third.reused, "the full run reuses its original file findings")
	assert.Equal(t, int32(2), full.calls.Load())
}

func TestRestrictedRunCacheDoesNotReuseChangedFile(t *testing.T) {
	dir := t.TempDir()
	contexts := []*core.FileContext{goContext(t, "a.go", "package a\n"), goContext(t, "b.go", "package b\n")}
	rule := newCountingRule("full-rule", false)
	run := func(files []*core.FileContext, stamp string) *resultCache {
		_, cache := runCached(t, dir, stamp, files, []rules.Rule{rule})
		return cache
	}

	run(contexts, "loader")
	restricted, err := openResultCache(dir, "/project", "", "build", "loader")
	require.NoError(t, err)
	require.NoError(t, restricted.save())
	changed := []*core.FileContext{goContext(t, "a.go", "package a // edited\n"), contexts[1]}
	third := run(changed, "loader")
	assert.Equal(t, 1, third.reused, "only the unchanged file is reused")
	assert.Equal(t, int32(3), rule.calls.Load(), "the edited file is analyzed again after the restricted run")
}

func TestFullRunDropsDeletedFileFromCache(t *testing.T) {
	dir := t.TempDir()
	rule := newCountingRule("full-rule", false)
	a := goContext(t, "a.go", "package a\n")
	b := goContext(t, "b.go", "package b\n")

	first, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	first.rootRunComplete = true
	_, err = analyzeFiles([]*core.FileContext{a, b}, []rules.Rule{rule}, core.DefaultConfig(), nil, first)
	require.NoError(t, err)
	require.NoError(t, first.save())

	second, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	second.rootRunComplete = true
	_, err = analyzeFiles([]*core.FileContext{a}, []rules.Rule{rule}, core.DefaultConfig(), nil, second)
	require.NoError(t, err)
	require.NoError(t, second.save())

	third, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	assert.NotContains(t, third.previous, "b.go", "a complete full-root save drops deleted files")
}

func TestNewRootCacheUsesBinaryHashWithoutBuildManifest(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	previous := cacheBuildManifest
	cacheBuildManifest = ""
	t.Cleanup(func() { cacheBuildManifest = previous })

	cache, err := newRootCache("/project", "", core.DefaultConfig(), false)
	require.NoError(t, err)
	binary, err := executableHash()
	require.NoError(t, err)
	want := buildTag(binary)
	assert.Equal(t, want, cache.build)
	assert.Equal(t, "result cache key: binary hash "+want+" (build without verified fingerprints)", cache.keyDescription)
	assert.Empty(t, cache.ruleFingerprints)
}

func TestResultCacheDirUsesGLINTCacheDir(t *testing.T) {
	userCache := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "results")
	t.Setenv("XDG_CACHE_HOME", userCache)
	t.Setenv("GLINT_CACHE_DIR", cacheDir)

	cache, err := newRootCache("/project", "", core.DefaultConfig(), false)
	require.NoError(t, err)
	require.NoError(t, cache.save())
	assert.Equal(t, cacheDir, filepath.Dir(cache.path))
	assert.FileExists(t, cache.path)
	assert.NoDirExists(t, filepath.Join(userCache, "glint"))
}

func TestResultCacheDirDefaultsToUserCacheWhenGLINTCacheDirIsEmpty(t *testing.T) {
	userCache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", userCache)
	t.Setenv("GLINT_CACHE_DIR", "")

	dir, err := resultCacheDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(userCache, "glint", "results"), dir)
}

func TestResultCacheDirRejectsRelativeGLINTCacheDir(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", "relative/cache")

	dir, err := resultCacheDir()
	require.Error(t, err)
	assert.Empty(t, dir)
	assert.ErrorContains(t, err, "GLINT_CACHE_DIR must be an absolute path")
}

func TestProjectCacheFingerprintCoversRuleStateDependencies(t *testing.T) {
	dir := t.TempDir()
	consumer := newProjectStubRule()
	indexer := frontendrules.NewTSPathNotRoutedRule()
	ruleset := []rules.Rule{indexer, consumer}
	open := func(indexFingerprint string) *resultCache {
		cache, err := openResultCache(dir, "/project", "", "build", "stamp")
		require.NoError(t, err)
		cache.ruleFingerprints[reflect.TypeFor[frontendrules.TSPathNotRoutedRule]().PkgPath()] = indexFingerprint
		cache.ruleFingerprints[reflect.TypeFor[projectStubRule]().PkgPath()] = "consumer-v1"
		return cache
	}
	first := open("index-v1")
	first.keyProject("inputs", []string{consumer.Name()}, ruleset, "")
	first.storeProject(nil, nil, map[string][]byte{indexer.Name(): []byte("old index")})
	require.NoError(t, first.save())

	second := open("index-v2")
	hit := second.keyProject("inputs", []string{consumer.Name()}, ruleset, "")
	require.NotNil(t, hit, "unchanged project inputs retain per-rule cache entries")
	assert.False(t, second.projectRuleReusable(consumer), "a changed index producer invalidates dependent project findings")
	assert.False(t, second.projectStateReusable(indexer), "a changed producer cannot restore its old RuleState")
}

func TestProjectCacheReportsPartialRuleHits(t *testing.T) {
	first := newProjectStubRule()
	second := &projectStubRule{BaseRule: rules.NewBaseRule("project-stub-2", "patterns", "another project rule", core.SeverityMedium)}
	cache := &resultCache{
		ruleFingerprints: map[string]string{reflect.TypeFor[projectStubRule]().PkgPath(): "code-v1"},
	}
	ruleNames := []string{first.Name(), second.Name()}
	cache.keyProject("inputs", ruleNames, []rules.Rule{first, second}, "")
	previous := make(map[string]string, len(cache.projectFingerprints))
	maps.Copy(previous, cache.projectFingerprints)
	previous[second.Name()] = "stale-code"
	cache.previousProject = &projectEntry{Inputs: "inputs", Fingerprints: previous}
	cache.keyProject("inputs", ruleNames, []rules.Rule{first, second}, "")
	assert.Equal(t, "1 cached, 1 rerun", cache.projectState())
}

func TestProjectCacheFullScopeServesPartialRun(t *testing.T) {
	rule := newProjectStubRule()
	previous := &projectEntry{Inputs: "inputs", Scope: "", Fingerprints: map[string]string{rule.Name(): "code-v1"}}
	cache := &resultCache{
		previousProject:  previous,
		build:            "code-v1",
		ruleFingerprints: map[string]string{reflect.TypeFor[projectStubRule]().PkgPath(): "code-v1"},
	}
	assert.Same(t, previous, cache.keyProject("inputs", []string{rule.Name()}, []rules.Rule{rule}, "file-a"))
	previous.Fingerprints = maps.Clone(cache.projectFingerprints)
	assert.Same(t, previous, cache.keyProject("inputs", []string{rule.Name()}, []rules.Rule{rule}, "file-a"))
	assert.Zero(t, cache.projectRulesRerun)

	full := core.Violation{Rule: rule.Name(), File: "file-a", Message: "a"}
	other := core.Violation{Rule: rule.Name(), File: "file-b", Message: "b"}
	cache.projectHit.Violations = map[string][]core.Violation{rule.Name(): {full, other}}
	got := inRun(core.ViolationListOf(cache.projectFindings([]rules.Rule{rule})), []*core.FileContext{goContext(t, "file-a", "package a\n")})
	assert.Equal(t, fingerprint(core.ViolationList{&full}), fingerprint(got))
}

func TestProjectCachePartialScopesDoNotShareOrUpgrade(t *testing.T) {
	rule := newProjectStubRule()
	previous := &projectEntry{Inputs: "inputs", Scope: "file-a"}
	cache := &resultCache{previousProject: previous}
	assert.Nil(t, cache.keyProject("inputs", []string{rule.Name()}, []rules.Rule{rule}, ""), "partial data cannot satisfy a full run")
	assert.Nil(t, cache.keyProject("inputs", []string{rule.Name()}, []rules.Rule{rule}, "file-b"), "partial areas cannot satisfy one another")
}

// A partial run stores its project findings under its scope, so they never
// come back as the findings of a full run.
func TestProjectCachePartialRunIsNotStoredAsFull(t *testing.T) {
	rule := newProjectStubRule()
	partial := &resultCache{}
	partial.keyProject("inputs", []string{rule.Name()}, []rules.Rule{rule}, "file-a")
	partial.storeProject(nil, nil, map[string][]byte{})
	assert.Nil(t, partial.currentProject, "a partial scope is not stored")
}

func TestProjectCachePartialRunPreservesFullEntry(t *testing.T) {
	rule := newProjectStubRule()
	full := &projectEntry{
		Inputs:       "inputs",
		Fingerprints: map[string]string{rule.Name(): "fingerprint"},
		Violations:   map[string][]core.Violation{rule.Name(): {{Rule: rule.Name(), File: "a.go"}}},
	}
	partial := &resultCache{previousProject: full}
	partial.keyProject("inputs", []string{rule.Name()}, []rules.Rule{rule}, "file-a")
	partial.storeProject(nil, nil, map[string][]byte{})

	require.Same(t, full, partial.currentProject)
	assert.Empty(t, full.Scope)
	assert.Len(t, full.Violations[rule.Name()], 1)
}

func TestProjectCacheFullRunReplacesFindingsWithNewFingerprint(t *testing.T) {
	rule := newProjectStubRule()
	previous := &projectEntry{
		Inputs:       "inputs",
		Rules:        []string{rule.Name()},
		Fingerprints: map[string]string{rule.Name(): "old"},
		Violations:   map[string][]core.Violation{rule.Name(): {{Rule: rule.Name(), Message: "old finding"}}},
	}
	cache := &resultCache{previousProject: previous, ruleFingerprints: map[string]string{reflect.TypeFor[projectStubRule]().PkgPath(): "new"}}
	cache.keyProject("inputs", []string{rule.Name()}, []rules.Rule{rule}, "")
	newFingerprint := cache.projectFingerprints[rule.Name()]
	newFinding := &core.Violation{Rule: rule.Name(), Message: "new finding"}
	cache.storeProject(core.ViolationList{newFinding}, nil, map[string][]byte{})

	require.NotNil(t, cache.currentProject)
	assert.Equal(t, newFingerprint, cache.currentProject.Fingerprints[rule.Name()])
	assert.Equal(t, "new finding", cache.currentProject.Violations[rule.Name()][0].Message)

	next := &resultCache{previousProject: cache.currentProject, ruleFingerprints: map[string]string{reflect.TypeFor[projectStubRule]().PkgPath(): "new"}}
	next.keyProject("inputs", []string{rule.Name()}, []rules.Rule{rule}, "")
	assert.True(t, next.projectRuleReusable(rule), "the next full run reuses the refreshed entry")
	assert.Equal(t, "1 cached, 0 rerun", next.projectState())
}

func TestProjectCachePartialRuleSetLeavesFullEntryUntouched(t *testing.T) {
	rule := newProjectStubRule()
	other := &projectStubRule{BaseRule: rules.NewBaseRule("project-stub-2", "patterns", "another project rule", core.SeverityMedium)}
	previous := &projectEntry{
		Inputs:       "inputs",
		Rules:        []string{rule.Name(), other.Name()},
		Fingerprints: map[string]string{rule.Name(): "old", other.Name(): "other"},
		Violations:   map[string][]core.Violation{rule.Name(): {{Rule: rule.Name(), Message: "full finding"}}},
	}
	cache := &resultCache{previousProject: previous}
	cache.keyProject("inputs", []string{rule.Name()}, []rules.Rule{rule}, "")
	cache.storeProject(nil, nil, map[string][]byte{})

	assert.Same(t, previous, cache.currentProject, "a strict subset of the cached rules must leave the entry untouched")
}

// Files the run did not analyze and rules it did not execute keep their
// findings for unchanged inputs.
func TestResultCacheKeepsUnanalyzedFilesAndMergesRules(t *testing.T) {
	dir := t.TempDir()
	first := newCountingRule("counting-first", false)
	second := newCountingRule("counting-second", false)
	a := goContext(t, "a.go", "package a\n")
	b := goContext(t, "b.go", "package b\n")

	runCached(t, dir, "stamp", []*core.FileContext{a, b}, []rules.Rule{first})
	runCached(t, dir, "stamp", []*core.FileContext{a}, []rules.Rule{second})
	_, cache := runCached(t, dir, "stamp", []*core.FileContext{a}, []rules.Rule{first, second})

	assert.Equal(t, int32(1), second.calls.Load())
	assert.Equal(t, int32(2), first.calls.Load(), "a.go keeps its findings of the first rule")
	assert.Equal(t, 1, cache.reused)
	assert.Contains(t, cache.previous, "b.go", "a file the run did not analyze is preserved")
}

// Every registered rule's findings survive the cache unchanged, and a second
// run over the same files analyzes nothing with a file-local rule.
func TestResultCacheRoundTripsEveryRule(t *testing.T) {
	dir := t.TempDir()
	allRules := rules.All()
	contexts := sampleContexts(t, 4)

	rules.ResetState(allRules)
	first, _ := runCached(t, dir, "stamp", contexts, allRules)
	require.NotEmpty(t, first)
	rules.ResetState(allRules)
	second, cache := runCached(t, dir, "stamp", contexts, allRules)

	assert.Equal(t, fingerprint(first), fingerprint(second))
	assert.Equal(t, len(contexts), cache.reused)
}

func TestOpenResultCacheReportsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	cache, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cache.path, []byte("not a cache"), 0o600))

	_, err = openResultCache(dir, "/project", "", "build", "stamp")
	require.Error(t, err)
}

// The cache directory stays bounded: caches of another glint build (their
// stamp can never match this one) and of an old file layout go once no run can
// still be writing them, caches unused for maxAge go, then the least recently
// used ones until the total fits maxBytes. Leftover temporary files of a
// crashed save go too; files of other kinds stay.
func TestPruneResultCachesBoundsTheDirectory(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	limits := cacheLimits{maxAge: 7 * 24 * time.Hour, grace: 10 * time.Minute, maxBytes: 250, foreignAge: 24 * time.Hour}
	files := []struct {
		name string
		age  time.Duration
		size int
	}{
		{"aa-build1.gob", time.Hour, 100},           // own build, recent: kept
		{"bb-build1.gob", 2 * time.Hour, 100},       // own build: kept within the size limit
		{"cc-build1.gob", 3 * time.Hour, 100},       // own build, oldest of three: evicted by size
		{"dd-build1.gob", 8 * 24 * time.Hour, 10},   // own build, unused for 8 days: removed
		{"ee-build0.gob", time.Hour, 10},            // another build: removed
		{"ff-build0.gob", time.Minute, 10},          // another build writing right now: kept
		{"0123456789abcdef.gob", 2 * time.Hour, 10}, // old layout without a build: removed
		{".results-123", time.Hour, 10},             // a crashed save: removed
		{".results-456", time.Minute, 10},           // a save in progress: kept
		{"notes.txt", 40 * 24 * time.Hour, 10},      // not a cache: kept
	}
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		require.NoError(t, os.WriteFile(path, make([]byte, f.size), 0o600))
		require.NoError(t, os.Chtimes(path, now.Add(-f.age), now.Add(-f.age)))
	}

	require.NoError(t, pruneResultCaches(dir, now, "build1", limits))

	left, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, entry := range left {
		names = append(names, entry.Name())
	}
	assert.ElementsMatch(t, []string{"aa-build1.gob", "bb-build1.gob", "ff-build0.gob", ".results-456", "notes.txt"}, names)
}

// A cache another process removes between the listing and the removal is no
// error: two runs may prune the same directory at once.
func TestPruneResultCachesToleratesConcurrentRemoval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aa-build0.gob")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	old := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(path, old, old))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))

	require.NoError(t, pruneCacheEntries(dir, entries, time.Now(), "build1", defaultCacheLimits))
}

// A cache is named after its root and the glint build that wrote it, and
// reading it marks it used, so the size limit evicts what nobody reads.
func TestResultCacheNamesItsBuildAndMarksUse(t *testing.T) {
	dir := t.TempDir()
	cache, err := openResultCache(dir, "/project", "", "build1", "stamp")
	require.NoError(t, err)
	assert.Contains(t, cache.path, "-build1-s")
	assert.True(t, strings.HasSuffix(cache.path, ".gob"), cache.path)
	require.NoError(t, cache.save())
	old := time.Now().Add(-5 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(cache.path, old, old))

	_, err = openResultCache(dir, "/project", "", "build1", "stamp")
	require.NoError(t, err)
	info, err := os.Stat(cache.path)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), info.ModTime(), time.Minute)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NoError(t, pruneCacheEntries(dir, entries, time.Now(), "build2", defaultCacheLimits))
	assert.FileExists(t, cache.path, "a recent cache hit survives pruning")
}

func TestProjectCacheDoesNotLookLikeAnotherRootCacheBuild(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeProjectCache(projectCachePath(dir, "/project", "build", "inputs"), projectEntry{Inputs: "inputs"}))
	cache, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	assert.Equal(t, "file", cache.rootMiss)

	otherBuild := stampedResultCachePath(dir, "/project", "other", "stamp")
	require.NoError(t, os.WriteFile(otherBuild, []byte("cache"), 0o600))
	cache, err = openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	assert.Equal(t, "build", cache.rootMiss)
}

func TestStampedRootCacheMissAndPruning(t *testing.T) {
	dir := t.TempDir()
	old, err := openResultCache(dir, "/project", "", "build", "config-old")
	require.NoError(t, err)
	old.current["a.go"] = cacheEntry{}
	require.NoError(t, old.save())

	current, err := openResultCache(dir, "/project", "", "build", "config-new")
	require.NoError(t, err)
	assert.Equal(t, "stamp", current.rootMiss)
	current.current["a.go"] = cacheEntry{}
	require.NoError(t, current.save())

	oldTime := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(old.path, oldTime, oldTime))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	limits := cacheLimits{maxAge: time.Hour, grace: time.Minute, maxBytes: 1 << 30, foreignAge: time.Hour}
	require.NoError(t, pruneCacheEntries(dir, entries, time.Now(), "build", limits))
	assert.NoFileExists(t, old.path, "an expired stamped variant is pruned")
	assert.FileExists(t, current.path, "the current stamped variant remains")
}

func TestPureTypeScriptRootRulesAreCachedWithoutProjectKey(t *testing.T) {
	dir := t.TempDir()
	root := []*core.FileContext{
		{RelPath: "a.ts", Content: []byte("export const a = 1\n")},
		{RelPath: "b.ts", Content: []byte("export const b = 2\n")},
	}
	cfg := core.DefaultConfig()
	enabled := rules.GetEnabled(cfg)
	var cachedRule rules.Rule
	for _, rule := range enabled {
		if rootProjectRuleCacheable(rule) {
			cachedRule = rule
			break
		}
	}
	require.NotNil(t, cachedRule, "the registry must include a cacheable root project-file rule")

	first, err := openResultCache(dir, "/typescript-root", "", "build", "stamp")
	require.NoError(t, err)
	keyRootFileCache(first, root, enabled, cfg, true)
	assert.True(t, first.rootRunComplete)
	first.storeRootProjectResults(map[string]core.ViolationList{
		cachedRule.Name(): {&core.Violation{Rule: cachedRule.Name(), File: "a.ts", Message: "cached"}},
	})
	require.NotNil(t, first.currentProject)
	require.NoError(t, first.save())

	second, err := openResultCache(dir, "/typescript-root", "", "build", "stamp")
	require.NoError(t, err)
	keyRootFileCache(second, root, enabled, cfg, true)
	assert.False(t, second.projectKeyed, "a pure TypeScript run does not key a Go project")
	assert.True(t, second.rootRuleReusable(cachedRule), "the second full run reuses the root-rule finding")
	assert.Len(t, second.rootRuleFindings[cachedRule.Name()]["a.ts"], 1)
}

func TestProjectCacheKeepsDifferentInputsAcrossSequentialAndConcurrentSaves(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		name := "sequential"
		if concurrent {
			name = "concurrent"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			save := func(inputs string) {
				cache, err := openResultCache(dir, "/project", "", "build", "stamp")
				require.NoError(t, err)
				cache.keyProject(inputs, nil, nil, "")
				cache.currentProject = &projectEntry{Inputs: inputs, Scope: "", Violations: map[string][]core.Violation{"marker": {{Message: inputs}}}}
				require.NoError(t, cache.save())
			}
			if concurrent {
				var wg sync.WaitGroup
				for _, inputs := range []string{"inputs-a", "inputs-b"} {
					wg.Add(1)
					go func(inputs string) { defer wg.Done(); save(inputs) }(inputs)
				}
				wg.Wait()
			} else {
				save("inputs-a")
				save("inputs-b")
			}
			for _, inputs := range []string{"inputs-a", "inputs-b"} {
				cache, err := openResultCache(dir, "/project", "", "build", "stamp")
				require.NoError(t, err)
				assert.NotNil(t, cache.keyProject(inputs, nil, nil, ""), inputs)
				assert.Equal(t, inputs, cache.projectHit.Violations["marker"][0].Message)
			}
		})
	}
}

func TestPartialProjectRunDoesNotReuseFindingsFromDifferentInputs(t *testing.T) {
	dir := t.TempDir()
	full, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	full.keyProject("inputs-off", []string{"project-rule"}, nil, "")
	full.currentProject = &projectEntry{Inputs: "inputs-off", Scope: "", Violations: map[string][]core.Violation{"project-rule": {{File: "a.go", Message: "old mode"}}}}
	require.NoError(t, full.save())

	partial, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	assert.Nil(t, partial.keyProject("inputs-work", []string{"other-rule"}, nil, "b.go"))
	partial.storeProject(nil, nil, nil)
	assert.Nil(t, partial.currentProject, "a partial run with different inputs is not stored")
}

func TestProjectCacheInputsAndBuildAreIsolated(t *testing.T) {
	dir := t.TempDir()
	for _, inputs := range []string{"use-a", "use-b"} {
		cache, err := openResultCache(dir, "/project", "", "build-old", "stamp")
		require.NoError(t, err)
		cache.keyProject(inputs, nil, nil, "")
		cache.currentProject = &projectEntry{Inputs: inputs}
		require.NoError(t, cache.save())
	}
	assert.NotEqual(t, projectCachePath(dir, "/project", "build-old", "use-a"), projectCachePath(dir, "/project", "build-old", "use-b"))
	for _, inputs := range []string{"use-a", "use-b"} {
		cache, err := openResultCache(dir, "/project", "", "build-old", "stamp")
		require.NoError(t, err)
		assert.NotNil(t, cache.keyProject(inputs, nil, nil, ""))
	}
	newBuild, err := openResultCache(dir, "/project", "", "build-new", "stamp")
	require.NoError(t, err)
	assert.Nil(t, newBuild.keyProject("use-a", nil, nil, ""), "a new build cannot use the old build's record")
}

func TestProjectCacheKeepsOnlyEightNewestInputVariants(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 10)
	base := time.Now().Add(-24 * time.Hour)
	for i := range paths {
		for previous := range i {
			if _, err := os.Stat(paths[previous]); errors.Is(err, fs.ErrNotExist) {
				continue
			} else {
				require.NoError(t, err)
			}
			stamp := base.Add(time.Duration(previous) * time.Second)
			require.NoError(t, os.Chtimes(paths[previous], stamp, stamp))
		}
		inputs := fmt.Sprintf("inputs-%02d", i)
		paths[i] = projectCachePath(dir, "/project", "build", inputs)
		err := writeProjectCache(paths[i], projectEntry{Inputs: inputs, Violations: map[string][]core.Violation{"marker": {{Message: inputs}}}})
		require.NoError(t, err)
	}
	for i, path := range paths {
		if i < 2 {
			assert.NoFileExists(t, path, "old input variant %d was evicted", i)
		} else {
			assert.FileExists(t, path, "recent input variant %d was retained", i)
		}
	}
	cache, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	assert.NotNil(t, cache.keyProject("inputs-09", nil, nil, ""))
	assert.Equal(t, "inputs-09", cache.projectHit.Violations["marker"][0].Message)
}

// Variants written within the grace period stay over the limit: another run
// may be reading them.
func TestProjectCacheVariantLimitSparesRecentFiles(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, maxProjectCacheVariants+2)
	for i := range paths {
		paths[i] = projectCachePath(dir, "/project", "build", fmt.Sprintf("inputs-%02d", i))
		require.NoError(t, writeProjectCache(paths[i], projectEntry{Inputs: fmt.Sprintf("inputs-%02d", i)}))
	}
	for _, path := range paths {
		assert.FileExists(t, path)
	}
}

func TestResultCacheFullHitDoesNotRewriteCacheFiles(t *testing.T) {
	dir := t.TempDir()
	first, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	first.keyProject("inputs", nil, nil, "")
	first.currentProject = &projectEntry{Inputs: "inputs", Violations: map[string][]core.Violation{"marker": {{Message: "cached"}}}}
	require.NoError(t, first.save())
	projectPath := projectCachePath(dir, "/project", "build", "inputs")

	second, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	assert.NotNil(t, second.keyProject("inputs", nil, nil, ""))
	second.current = second.previous
	rootBefore, err := os.Stat(second.path)
	require.NoError(t, err)
	projectBefore, err := os.Stat(projectPath)
	require.NoError(t, err)
	rootBytesBefore, err := os.ReadFile(second.path)
	require.NoError(t, err)
	projectBytesBefore, err := os.ReadFile(projectPath)
	require.NoError(t, err)

	require.NoError(t, second.save())
	rootAfter, err := os.Stat(second.path)
	require.NoError(t, err)
	projectAfter, err := os.Stat(projectPath)
	require.NoError(t, err)
	rootBytesAfter, err := os.ReadFile(second.path)
	require.NoError(t, err)
	projectBytesAfter, err := os.ReadFile(projectPath)
	require.NoError(t, err)
	assert.True(t, os.SameFile(rootBefore, rootAfter), "unchanged root cache should only be marked used")
	assert.True(t, os.SameFile(projectBefore, projectAfter), "unchanged project cache should not be rewritten")
	assert.Equal(t, rootBytesBefore, rootBytesAfter)
	assert.Equal(t, projectBytesBefore, projectBytesAfter)
	assert.Equal(t, projectBefore.ModTime(), projectAfter.ModTime(), "a project cache hit already marked the file used")
}

func TestCorruptProjectCacheWarnsAndReportsCorruptMiss(t *testing.T) {
	dir := t.TempDir()
	path := projectCachePath(dir, "/project", "build", "inputs")
	require.NoError(t, os.WriteFile(path, []byte("not a project cache"), 0o600))
	cache, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = writer
	assert.Nil(t, cache.keyProject("inputs", nil, nil, ""))
	os.Stderr = oldStderr
	require.NoError(t, writer.Close())
	warning, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	assert.Contains(t, string(warning), "warning: project result cache "+path+" not used:")
	assert.Equal(t, "corrupt", cache.projectMiss)
	assert.Nil(t, cache.previousProject)
}

func TestProjectCacheScopeMismatchHasScopeMissReason(t *testing.T) {
	dir := t.TempDir()
	first, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	first.keyProject("inputs", nil, nil, "file-a.go")
	first.currentProject = &projectEntry{Inputs: "inputs", Scope: "file-a.go"}
	require.NoError(t, first.save())

	second, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	assert.Nil(t, second.keyProject("inputs", nil, nil, "file-b.go"))
	assert.Equal(t, "scope", second.projectMiss)
}

func TestPruneCacheEvictsOldForeignFilesBeforeRecentCache(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	files := []struct {
		name string
		age  time.Duration
	}{
		{"old-dev-1.gob", time.Hour}, {"old-dev-2.gob", 2 * time.Hour},
		{"installed-recent.gob", 5 * time.Minute},
	}
	for _, file := range files {
		path := filepath.Join(dir, file.name)
		require.NoError(t, os.WriteFile(path, make([]byte, 60), 0o600))
		stamp := now.Add(-file.age)
		require.NoError(t, os.Chtimes(path, stamp, stamp))
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	limits := cacheLimits{maxAge: 7 * 24 * time.Hour, grace: 10 * time.Minute, foreignAge: 24 * time.Hour, maxBytes: 60}
	require.NoError(t, pruneCacheEntries(dir, entries, now, "installed", limits))
	assert.NoFileExists(t, filepath.Join(dir, "old-dev-1.gob"))
	assert.NoFileExists(t, filepath.Join(dir, "old-dev-2.gob"))
	assert.FileExists(t, filepath.Join(dir, "installed-recent.gob"))
}

// analyzeCachedRoot runs one root through the check pipeline with the cache,
// as runCheck does.
func analyzeCachedRoot(t *testing.T, root string, list []rules.Rule) (*preparedRoot, core.ViolationList) {
	t.Helper()
	cfg := core.DefaultConfig()
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, list, true)
	require.NoError(t, err)
	require.NotNil(t, prepared.cache)
	rootRules := append(rules.GetEnabled(cfg), list...)
	violations, panics, err := analyzeProjectContained(prepared.contexts, prepared.rootFiles, list, rootRules, cfg, prepared.project, prepared.cache)
	require.Empty(t, panics)
	require.NoError(t, err)
	require.NoError(t, prepared.cache.save())
	return prepared, violations
}

// While no input of the typed load changes, the project is not loaded and its
// findings come from the cache; the Go files still get their syntax trees. A
// frontend edit changes no input, a Go edit anywhere in the module does.
func TestProjectCacheSkipsTheLoadWhileGoInputsAreUnchanged(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	module := t.TempDir()
	writeModuleFile(t, module, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, module, "svc/check.go", "package svc\n\nfunc Value() int { return 1 }\n")
	writeModuleFile(t, module, "lib/lib.go", "package lib\n\nvar X = 1\n")
	writeModuleFile(t, module, "svc/web/app.ts", "export const a = 1\n")
	root := filepath.Join(module, "svc")
	rule := newProjectStubRule()
	rule.findings = []*core.Violation{rule.CreateViolation("check.go", 3, "finding")}
	list := []rules.Rule{rule}

	first, want := analyzeCachedRoot(t, root, list)
	require.NotNil(t, first.project)
	require.Equal(t, 1, rule.projectCalls)
	require.Len(t, want, 1)

	second, got := analyzeCachedRoot(t, root, list)
	assert.Nil(t, second.project, "unchanged inputs are not loaded")
	assert.Equal(t, 1, rule.projectCalls)
	assert.Equal(t, fingerprint(want), fingerprint(got))
	for _, ctx := range second.contexts {
		if ctx.IsGoFile() {
			assert.NotNil(t, ctx.GoAST, "%s keeps its syntax tree for the file rules", ctx.RelPath)
		}
	}

	writeModuleFile(t, root, "web/app.ts", "export const a = 2\n")
	analyzeCachedRoot(t, root, list)
	assert.Equal(t, 1, rule.projectCalls, "a frontend edit leaves the typed load as it was")

	writeModuleFile(t, module, "lib/lib.go", "package lib\n\nvar X = 2\n")
	third, _ := analyzeCachedRoot(t, root, list)
	assert.NotNil(t, third.project)
	assert.Equal(t, 2, rule.projectCalls, "a Go edit outside the analyzed files still reloads")
}

func TestTypedProjectLoadIsRequiredOnlyForAnalyzedFrontendFiles(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	goRoot := t.TempDir()
	writeModuleFile(t, goRoot, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, goRoot, "check.go", "package svc\n\nfunc Value() int { return 1 }\n")
	typedRule := &typedProjectStubRule{BaseRule: rules.NewBaseRule("typed-project-stub", "patterns", "test typed project rule", core.SeverityMedium)}
	list := []rules.Rule{typedRule}

	first, _ := analyzeCachedRoot(t, goRoot, list)
	assert.Nil(t, first.project)
	assert.Empty(t, first.enabledRules, "a Go-only root omits the typed file rule")
	second, _ := analyzeCachedRoot(t, goRoot, list)
	assert.Nil(t, second.project, "a Go-only root does not load a typed project")
	assert.Equal(t, []bool{false, false}, typedRule.requirements)

	frontendOnlyRoot := t.TempDir()
	writeModuleFile(t, frontendOnlyRoot, "go.mod", "module example.com/frontendonly\n\ngo 1.24\n")
	writeModuleFile(t, frontendOnlyRoot, "check.go", "package frontendonly\n\nfunc Value() int { return 1 }\n")
	writeModuleFile(t, frontendOnlyRoot, "app.ts", "export const value = 1\n")
	frontendOnlyRule := &typedProjectStubRule{BaseRule: rules.NewBaseRule("typed-project-stub", "patterns", "test typed project rule", core.SeverityMedium)}
	firstFrontendOnly, _ := analyzeCachedRoot(t, frontendOnlyRoot, []rules.Rule{frontendOnlyRule})
	assert.Nil(t, firstFrontendOnly.project)
	assert.Empty(t, firstFrontendOnly.enabledRules, "TypeScript without mux omits the typed file rule")
	secondFrontendOnly, _ := analyzeCachedRoot(t, frontendOnlyRoot, []rules.Rule{frontendOnlyRule})
	assert.Nil(t, secondFrontendOnly.project, "TypeScript without mux does not force a typed load")
	assert.Equal(t, []bool{false, false}, frontendOnlyRule.requirements)

	tsRoot := t.TempDir()
	writeModuleFile(t, tsRoot, "go.mod", "module example.com/typed\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.1\n")
	writeModuleFile(t, tsRoot, "vendor/modules.txt", "# github.com/gorilla/mux v1.8.1\n## explicit; go 1.24\ngithub.com/gorilla/mux\n")
	writeModuleFile(t, tsRoot, "vendor/github.com/gorilla/mux/mux.go", "package mux\ntype Router struct{}\nfunc (*Router) HandleFunc(string, any) {}\n")
	writeModuleFile(t, tsRoot, "router.go", "package typed\nimport \"github.com/gorilla/mux\"\nvar router *mux.Router\nfunc init() { router.HandleFunc(\"/api/known\", nil) }\n")
	writeModuleFile(t, tsRoot, "app.ts", "fetch('/api/missing')\n")
	tsRule := &typedProjectStubRule{BaseRule: rules.NewBaseRule("typed-project-stub", "patterns", "test typed project rule", core.SeverityMedium)}
	tsList := []rules.Rule{tsRule}
	tsFirst, _ := analyzeCachedRoot(t, tsRoot, tsList)
	require.NotNil(t, tsFirst.project)
	assert.Equal(t, []rules.Rule{tsRule}, tsFirst.enabledRules)
	tsSecond, _ := analyzeCachedRoot(t, tsRoot, tsList)
	assert.Nil(t, tsSecond.project, "a root with analyzed TypeScript reuses its typed findings")
	assert.Equal(t, []bool{true, true}, tsRule.requirements)
	assert.Equal(t, "1 cached, 0 rerun", tsSecond.cache.projectState())
}

func TestTSPathRoutesAreCachedAndInvalidatedByGoInputs(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	writeModuleFile(t, root, "go.mod", "module example.com/routes\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.1\n")
	writeModuleFile(t, root, "vendor/modules.txt", "# github.com/gorilla/mux v1.8.1\n## explicit; go 1.24\ngithub.com/gorilla/mux\n")
	writeModuleFile(t, root, "vendor/github.com/gorilla/mux/mux.go", "package mux\ntype Router struct{}\nfunc (*Router) HandleFunc(string, any) {}\n")
	writeModuleFile(t, root, "backend/routes.go", "package backend\nimport \"github.com/gorilla/mux\"\nfunc Register(router *mux.Router) { router.HandleFunc(\"/api/known\", nil) }\n")
	writeModuleFile(t, root, "frontend/api.ts", "fetch('/api/known')\nfetch('/api/missing')\n")
	rule := frontendrules.NewTSPathNotRoutedRule()
	list := []rules.Rule{rule}

	first, firstFindings := analyzeCachedRoot(t, root, list)
	require.NotNil(t, first.project)
	assert.Len(t, firstFindings, 1)
	assert.Equal(t, "No backend route for /api/missing", firstFindings[0].Message)
	state, err := rule.CacheProjectFiles()
	require.NoError(t, err)
	assert.Contains(t, string(state), "/api/known", "cached route paths survive serialization")

	second, secondFindings := analyzeCachedRoot(t, root, list)
	assert.Nil(t, second.project, "cached routes avoid a typed load")
	assert.Equal(t, fingerprint(firstFindings), fingerprint(secondFindings))
	assert.Equal(t, "1 cached, 0 rerun", second.cache.projectState())

	writeModuleFile(t, root, "backend/routes.go", "package backend\nimport \"github.com/gorilla/mux\"\nfunc Register(router *mux.Router) { router.HandleFunc(\"/api/known\", nil); router.HandleFunc(\"/api/missing\", nil) }\n")
	third, thirdFindings := analyzeCachedRoot(t, root, list)
	assert.NotNil(t, third.project, "a Go route edit invalidates the route cache")
	assert.Empty(t, thirdFindings)
}

type typedProjectStubRule struct {
	*rules.BaseRule
	requirements []bool
}

func (r *typedProjectStubRule) NeedsTypedGoProject(files []*core.FileContext) bool {
	needed := false
	for _, file := range files {
		if file.IsGoFile() && slices.Contains(file.GoImports, "github.com/gorilla/mux") {
			needed = needed || frontendFilesPresent(files)
		}
	}
	r.requirements = append(r.requirements, needed)
	return needed
}

func (r *typedProjectStubRule) TypedGoProjectImports() []string {
	return []string{"github.com/gorilla/mux"}
}

func frontendFilesPresent(files []*core.FileContext) bool {
	for _, file := range files {
		if file.IsTypeScriptFile() || file.IsJavaScriptFile() {
			return true
		}
	}
	return false
}

func (r *typedProjectStubRule) AnalyzeFile(*core.FileContext) []*core.Violation { return nil }

// The project findings are those of the project rules that ran: a run with
// another rule selection (--rule) loads the project and runs its own rules
// instead of taking the other rule's findings.
func TestProjectCacheKeysOnTheProjectRulesThatRan(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	module := t.TempDir()
	writeModuleFile(t, module, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, module, "svc/check.go", "package svc\n\nfunc Value() int { return 1 }\n")
	root := filepath.Join(module, "svc")
	first := newProjectStubRule()
	first.findings = []*core.Violation{first.CreateViolation("check.go", 3, "first finding")}
	second := &projectStubRule{BaseRule: rules.NewBaseRule("project-stub-2", "patterns", "another project rule", core.SeverityMedium)}
	second.findings = []*core.Violation{second.CreateViolation("check.go", 3, "second finding")}

	analyzeCachedRoot(t, root, []rules.Rule{first})
	prepared, got := analyzeCachedRoot(t, root, []rules.Rule{second})
	assert.NotNil(t, prepared.project, "another rule selection loads the project")
	assert.Equal(t, 1, second.projectCalls)
	require.Len(t, got, 1)
	assert.Equal(t, "project-stub-2", got[0].Rule)

	analyzeCachedRoot(t, root, []rules.Rule{second})
	assert.Equal(t, 1, second.projectCalls, "the same selection reuses its findings")
}

// A root without a cache of its own, a fresh worktree, starts from the cache
// of the same root in the main worktree: its unchanged files are not analyzed
// again. It then keeps a cache of its own and leaves the main one as it was.
func TestResultCacheStartsFromTheMainWorktree(t *testing.T) {
	dir := t.TempDir()
	rule := newCountingRule("counting-local", false)
	contexts := []*core.FileContext{goContext(t, "a.go", "package a\n"), goContext(t, "b.go", "package b\n")}
	run := func(root, seed, stamp string, contexts []*core.FileContext) *resultCache {
		cache, err := openResultCache(dir, root, seed, "build", stamp)
		require.NoError(t, err)
		_, err = analyzeFiles(contexts, []rules.Rule{rule}, core.DefaultConfig(), nil, cache)
		require.NoError(t, err)
		require.NoError(t, cache.save())
		return cache
	}

	run("/main", "", "stamp", contexts)
	require.Equal(t, int32(2), rule.calls.Load())

	edited := []*core.FileContext{contexts[0], goContext(t, "b.go", "package b // edited\n")}
	cache := run("/wt", "/main", "stamp", edited)
	assert.Equal(t, int32(3), rule.calls.Load(), "only the file the worktree changed is analyzed")
	assert.Equal(t, 1, cache.reused)

	run("/main", "", "stamp", contexts)
	assert.Equal(t, int32(3), rule.calls.Load(), "the main worktree keeps its cache")

	run("/other", "/main", "stamp-2", contexts)
	assert.Equal(t, int32(5), rule.calls.Load(), "a cache of another stamp is no start")
}

// The severity filter, the failure threshold and the output format apply to
// the findings after analysis: a gate run and a json run share one cache.
func TestCacheStampIgnoresReportOnlySettings(t *testing.T) {
	base := core.DefaultConfig()
	stamp := func(cfg *core.Config) string {
		got, err := cacheStamp(cfg, false, false, "core")
		require.NoError(t, err)
		return got
	}
	report := core.DefaultConfig()
	report.Settings.MinSeverity, report.Settings.FailOn, report.Settings.Output = "high", "critical", "json"
	assert.Equal(t, stamp(base), stamp(report))

	excluded := core.DefaultConfig()
	excluded.Settings.Exclude = append(excluded.Settings.Exclude, "generated/**")
	assert.NotEqual(t, stamp(base), stamp(excluded), "what is analyzed stays in the stamp")

	severity := core.DefaultConfig()
	category := severity.Categories["patterns"]
	category.SeverityOverride = "high"
	severity.Categories["patterns"] = category
	assert.NotEqual(t, stamp(base), stamp(severity), "severity overrides change stored findings")
}

// ts-test-outside-typecheck follows tsconfig "extends" on the disk, also out
// of the root: a change there alone left its old finding cached with the root.
func TestTSConfigReaderStaysOutOfTheRootFilesCache(t *testing.T) {
	assert.False(t, rootProjectRuleCacheable(frontendrules.NewTSTestOutsideTypecheckRule()))
}

type inputCountingRule struct {
	*rules.BaseRule
	calls int
}

func (*inputCountingRule) ReadsOtherFiles() bool { return true }
func (*inputCountingRule) CacheInputs(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "schema.txt"))
	return string(data), err
}
func (r *inputCountingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	r.calls++
	data, err := os.ReadFile(filepath.Join(ctx.ProjectRoot, "schema.txt"))
	if err != nil {
		return nil
	}
	return []*core.Violation{r.CreateViolation(ctx.RelPath, 1, string(data))}
}

func TestJSEnvCacheInputsInvalidatesFileFindings(t *testing.T) {
	root, dir := t.TempDir(), t.TempDir()
	path := filepath.Join(root, ".env")
	ctx := core.NewFileContext(filepath.Join(root, "api.test.ts"), root, []byte("test('x', async () => {\n  test.skip(!process.env.LIVE, 'live')\n  await fetch('https://api.ratesbank.io/data')\n})\n"), core.DefaultConfig())
	key := func() string {
		value, err := qarules.NewJSTestExternalServiceRule().CacheInputs(root)
		require.NoError(t, err)
		return value
	}
	empty := key()
	first, _ := runCached(t, dir, "stamp", []*core.FileContext{ctx}, []rules.Rule{qarules.NewJSTestExternalServiceRule()})
	require.Empty(t, first)
	second, _ := runCached(t, dir, "stamp", []*core.FileContext{ctx}, []rules.Rule{qarules.NewJSTestExternalServiceRule()})
	require.Empty(t, second)
	require.NoError(t, os.WriteFile(path, []byte("LIVE=1\n"), 0o600))
	added := key()
	assert.NotEqual(t, empty, added)
	third, _ := runCached(t, dir, "stamp", []*core.FileContext{ctx}, []rules.Rule{qarules.NewJSTestExternalServiceRule()})
	require.Len(t, third, 1)
	uncached, err := analyzeFiles([]*core.FileContext{ctx}, []rules.Rule{qarules.NewJSTestExternalServiceRule()}, core.DefaultConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, fingerprint(uncached), fingerprint(third))
	require.NoError(t, os.WriteFile(path, []byte("LIVE=2\n"), 0o600))
	changed := key()
	assert.NotEqual(t, added, changed)
	require.NoError(t, os.Rename(path, filepath.Join(root, ".env.test")))
	assert.NotEqual(t, changed, key())
	require.NoError(t, os.Remove(filepath.Join(root, ".env.test")))
	assert.Equal(t, empty, key())
}

func TestModelCacheInputsInvalidatesFileFindings(t *testing.T) {
	root, dir := t.TempDir(), t.TempDir()
	path := filepath.Join(root, "approved")
	write := func(text string) { require.NoError(t, os.WriteFile(path, []byte(text), 0o600)) }
	newRule := func() *shellrules.ModelNotApprovedRule {
		rule := shellrules.NewModelNotApprovedRule()
		require.NoError(t, rule.Configure(map[string]any{"approved_file": path}))
		return rule
	}
	ctx := core.NewFileContext(filepath.Join(root, "run.sh"), root, []byte("claude --model sonnet\n"), core.DefaultConfig())
	write("sonnet claude-sonnet\n")
	firstRule := newRule()
	firstKey, err := firstRule.CacheInputs(root)
	require.NoError(t, err)
	first, _ := runCached(t, dir, "stamp", []*core.FileContext{ctx}, []rules.Rule{firstRule})
	require.Empty(t, first)
	second, _ := runCached(t, dir, "stamp", []*core.FileContext{ctx}, []rules.Rule{newRule()})
	require.Empty(t, second)
	write("opus claude-opus\n")
	changed := newRule()
	changedKey, err := changed.CacheInputs(root)
	require.NoError(t, err)
	assert.NotEqual(t, firstKey, changedKey)
	third, _ := runCached(t, dir, "stamp", []*core.FileContext{ctx}, []rules.Rule{changed})
	require.Len(t, third, 1)
	uncached, err := analyzeFiles([]*core.FileContext{ctx}, []rules.Rule{newRule()}, core.DefaultConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, fingerprint(uncached), fingerprint(third))
	write("opus claude-opus\n# comment\n")
	commentKey, err := newRule().CacheInputs(root)
	require.NoError(t, err)
	assert.NotEqual(t, changedKey, commentKey)
	require.NoError(t, os.Remove(path))
	_, err = newRule().CacheInputs(root)
	require.Error(t, err)
}

func TestCacheInputsInvalidatesFileFindings(t *testing.T) {
	root, dir := t.TempDir(), t.TempDir()
	path := filepath.Join(root, "schema.txt")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))
	ctx := core.NewFileContext(filepath.Join(root, "a.go"), root, []byte("package a\n"), core.DefaultConfig())
	rule := &inputCountingRule{BaseRule: rules.NewBaseRule("input-counting", "patterns", "test", core.SeverityMedium)}
	list := []rules.Rule{rule}
	first, _ := runCached(t, dir, "stamp", []*core.FileContext{ctx}, list)
	second, _ := runCached(t, dir, "stamp", []*core.FileContext{ctx}, list)
	assert.Equal(t, 1, rule.calls)
	assert.Equal(t, fingerprint(first), fingerprint(second))
	require.NoError(t, os.WriteFile(path, []byte("new"), 0o600))
	third, _ := runCached(t, dir, "stamp", []*core.FileContext{ctx}, list)
	assert.Equal(t, 2, rule.calls)
	assert.NotEqual(t, fingerprint(first), fingerprint(third))
	uncached, err := analyzeFiles([]*core.FileContext{ctx}, list, core.DefaultConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, fingerprint(uncached), fingerprint(third))
}

type indexedInputCountingRule struct {
	*indexedFindingRule
	inputCalls int
}

func (*indexedInputCountingRule) ReadsOtherFiles() bool { return true }
func (r *indexedInputCountingRule) CacheInputs(string) (string, error) {
	r.inputCalls++
	return "input", nil
}

func TestCacheInputsDoesNotCacheProjectFilesRule(t *testing.T) {
	dir := t.TempDir()
	rule := &indexedInputCountingRule{indexedFindingRule: newIndexedFindingRule()}
	contexts := []*core.FileContext{goContext(t, "a.go", "package a\n")}
	list := []rules.Rule{rule}
	runCached(t, dir, "stamp", contexts, list)
	runCached(t, dir, "stamp", contexts, list)
	assert.Equal(t, 2, rule.fileCalls)
	assert.Zero(t, rule.inputCalls)
}

type projectInputCountingRule struct {
	*inputCountingRule
	inputCalls int
}

func (r *projectInputCountingRule) CacheInputs(string) (string, error) {
	r.inputCalls++
	return "input", nil
}
func (*projectInputCountingRule) AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error) {
	return nil, nil
}
func (*projectInputCountingRule) RequiresSSA() bool { return false }

func TestCacheInputsDoesNotCacheGoProjectRule(t *testing.T) {
	root, dir := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "schema.txt"), []byte("value"), 0o600))
	ctx := core.NewFileContext(filepath.Join(root, "a.go"), root, []byte("package a\n"), core.DefaultConfig())
	rule := &projectInputCountingRule{inputCountingRule: &inputCountingRule{BaseRule: rules.NewBaseRule("project-input", "patterns", "test", core.SeverityMedium)}}
	list := []rules.Rule{rule}
	runCached(t, dir, "stamp", []*core.FileContext{ctx}, list)
	runCached(t, dir, "stamp", []*core.FileContext{ctx}, list)
	assert.Equal(t, 2, rule.calls)
	assert.Zero(t, rule.inputCalls)
}

// A rule keys its findings by the very bytes it reads them from: a change of
// the input after the first read does not move the key of the same run.
func TestCacheInputsKeyTheBytesReadOncePerRun(t *testing.T) {
	root := t.TempDir()
	js := qarules.NewJSTestExternalServiceRule()
	before, err := js.CacheInputs(root)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, ".env"), []byte("LIVE=1\n"), 0o600))
	after, err := js.CacheInputs(root)
	require.NoError(t, err)
	assert.Equal(t, before, after, "env files")

	path := filepath.Join(root, "approved")
	require.NoError(t, os.WriteFile(path, []byte("sonnet claude-sonnet\n"), 0o600))
	model := shellrules.NewModelNotApprovedRule()
	require.NoError(t, model.Configure(map[string]any{"approved_file": path}))
	before, err = model.CacheInputs(root)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("opus claude-opus\n"), 0o600))
	after, err = model.CacheInputs(root)
	require.NoError(t, err)
	assert.Equal(t, before, after, "approved list")
}

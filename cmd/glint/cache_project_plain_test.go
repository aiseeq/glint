//go:build !race

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/frontendrules"
)

// These tests exercise in-memory or on-disk cache bookkeeping. They do not
// start stateless analysis or Walker workers in the test process.

func TestProjectCacheFingerprintCoversRuleStateDependencies(t *testing.T) {
	dir := t.TempDir()
	indexer := frontendrules.NewTSPathNotRoutedRule()
	consumer := &projectCacheIndexConsumer{projectStubRule: newProjectStubRule(), indexName: indexer.Name()}
	ruleset := []rules.Rule{indexer, consumer}
	open := func(indexFingerprint string) *resultCache {
		cache, err := openResultCache(dir, "/project", "", "build", "stamp")
		require.NoError(t, err)
		cache.ruleFingerprints[reflect.TypeFor[frontendrules.TSPathNotRoutedRule]().PkgPath()] = indexFingerprint
		cache.ruleFingerprints[reflect.TypeFor[projectCacheIndexConsumer]().PkgPath()] = "consumer-v1"
		return cache
	}
	first := open("index-v1")
	first.keyProject("", "inputs", []string{consumer.Name()}, ruleset, "")
	first.storeProject(nil, nil, map[string][]byte{indexer.Name(): []byte("old index")})
	require.NoError(t, first.save())

	second := open("index-v2")
	hit := second.keyProject("", "inputs", []string{consumer.Name()}, ruleset, "")
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
	cache.keyProject("", "inputs", ruleNames, []rules.Rule{first, second}, "")
	previous := make(map[string]string, len(cache.projectFingerprints))
	maps.Copy(previous, cache.projectFingerprints)
	previous[second.Name()] = "stale-code"
	cache.previousProject = &projectEntry{Inputs: "inputs", Fingerprints: previous}
	cache.keyProject("", "inputs", ruleNames, []rules.Rule{first, second}, "")
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
	assert.Same(t, previous, cache.keyProject("", "inputs", []string{rule.Name()}, []rules.Rule{rule}, "file-a"))
	previous.Fingerprints = maps.Clone(cache.projectFingerprints)
	assert.Same(t, previous, cache.keyProject("", "inputs", []string{rule.Name()}, []rules.Rule{rule}, "file-a"))
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
	assert.Nil(t, cache.keyProject("", "inputs", []string{rule.Name()}, []rules.Rule{rule}, ""), "partial data cannot satisfy a full run")
	assert.Nil(t, cache.keyProject("", "inputs", []string{rule.Name()}, []rules.Rule{rule}, "file-b"), "partial areas cannot satisfy one another")
}

// A partial run stores its project findings under its scope, so they never
// come back as the findings of a full run.
func TestProjectCachePartialRunIsNotStoredAsFull(t *testing.T) {
	rule := newProjectStubRule()
	partial := &resultCache{}
	partial.keyProject("", "inputs", []string{rule.Name()}, []rules.Rule{rule}, "file-a")
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
	partial.keyProject("", "inputs", []string{rule.Name()}, []rules.Rule{rule}, "file-a")
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
	cache.keyProject("", "inputs", []string{rule.Name()}, []rules.Rule{rule}, "")
	newFingerprint := cache.projectFingerprints[rule.Name()]
	newFinding := &core.Violation{Rule: rule.Name(), Message: "new finding"}
	cache.storeProject(core.ViolationList{newFinding}, nil, map[string][]byte{})

	require.NotNil(t, cache.currentProject)
	assert.Equal(t, newFingerprint, cache.currentProject.Fingerprints[rule.Name()])
	assert.Equal(t, "new finding", cache.currentProject.Violations[rule.Name()][0].Message)

	next := &resultCache{previousProject: cache.currentProject, ruleFingerprints: map[string]string{reflect.TypeFor[projectStubRule]().PkgPath(): "new"}}
	next.keyProject("", "inputs", []string{rule.Name()}, []rules.Rule{rule}, "")
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
	cache.keyProject("", "inputs", []string{rule.Name()}, []rules.Rule{rule}, "")
	cache.storeProject(nil, nil, map[string][]byte{})

	assert.Same(t, previous, cache.currentProject, "a strict subset of the cached rules must leave the entry untouched")
}

func TestProjectCacheScopeMismatchHasScopeMissReason(t *testing.T) {
	dir := t.TempDir()
	first, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	first.keyProject("", "inputs", nil, nil, "file-a.go")
	first.currentProject = &projectEntry{Inputs: "inputs", Scope: "file-a.go"}
	require.NoError(t, first.save())

	second, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	assert.Nil(t, second.keyProject("", "inputs", nil, nil, "file-b.go"))
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

// These direct cache tests inspect keys, persisted entries, and eviction.
// They do not invoke file analysis or Glint worker pools.

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

func TestPartialProjectRunDoesNotReuseFindingsFromDifferentInputs(t *testing.T) {
	dir := t.TempDir()
	full, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	full.keyProject("", "inputs-off", []string{"project-rule"}, nil, "")
	full.currentProject = &projectEntry{Inputs: "inputs-off", Scope: "", Violations: map[string][]core.Violation{"project-rule": {{File: "a.go", Message: "old mode"}}}}
	require.NoError(t, full.save())

	partial, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	assert.Nil(t, partial.keyProject("", "inputs-work", []string{"other-rule"}, nil, "b.go"))
	partial.storeProject(nil, nil, nil)
	assert.Nil(t, partial.currentProject, "a partial run with different inputs is not stored")
}

func TestProjectCacheInputsAndBuildAreIsolated(t *testing.T) {
	dir := t.TempDir()
	for _, inputs := range []string{"use-a", "use-b"} {
		cache, err := openResultCache(dir, "/project", "", "build-old", "stamp")
		require.NoError(t, err)
		cache.keyProject("", inputs, nil, nil, "")
		cache.currentProject = &projectEntry{Inputs: inputs}
		require.NoError(t, cache.save())
	}
	assert.NotEqual(t, projectCachePath(dir, "/project", "build-old", "use-a"), projectCachePath(dir, "/project", "build-old", "use-b"))
	for _, inputs := range []string{"use-a", "use-b"} {
		cache, err := openResultCache(dir, "/project", "", "build-old", "stamp")
		require.NoError(t, err)
		assert.NotNil(t, cache.keyProject("", inputs, nil, nil, ""))
	}
	newBuild, err := openResultCache(dir, "/project", "", "build-new", "stamp")
	require.NoError(t, err)
	assert.Nil(t, newBuild.keyProject("", "use-a", nil, nil, ""), "a new build cannot use the old build's record")
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
	assert.NotNil(t, cache.keyProject("", "inputs-09", nil, nil, ""))
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
	first.keyProject("", "inputs", nil, nil, "")
	first.currentProject = &projectEntry{Inputs: "inputs", Violations: map[string][]core.Violation{"marker": {{Message: "cached"}}}}
	require.NoError(t, first.save())
	projectPath := projectCachePath(dir, "/project", "build", "inputs")

	second, err := openResultCache(dir, "/project", "", "build", "stamp")
	require.NoError(t, err)
	assert.NotNil(t, second.keyProject("", "inputs", nil, nil, ""))
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

//go:build !race

package main

import (
	"bytes"
	"encoding/gob"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/qarules"
	"github.com/aiseeq/glint/pkg/rules/patterns/shellrules"
)

// These cache/config checks exercise cache primitives and rule metadata only.
// TestResultCacheUnchangedSaveTouchesWithoutReplacing calls statelessRun.execute
// with one file, so that analysis has only one worker.

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

	goRule := qarules.NewTestExternalServiceRule()
	before, err = goRule.CacheInputs(root)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, ".env"), []byte("LIVE=2\n"), 0o600))
	after, err = goRule.CacheInputs(root)
	require.NoError(t, err)
	assert.Equal(t, before, after, "env files of the Go rule")
	changed, err := qarules.NewTestExternalServiceRule().CacheInputs(root)
	require.NoError(t, err)
	assert.NotEqual(t, before, changed, "a new run reads the edited env file")

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

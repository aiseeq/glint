//go:build !race

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/frontendrules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// These cache and configuration tests do not start file-analysis workers or
// a Walker in the test process.

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
	rulestest.IsolateUserCache(t, userCache)
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
	rulestest.IsolateUserCache(t, userCache)
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

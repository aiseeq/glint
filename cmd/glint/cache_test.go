package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// countingRule reports one finding per file and counts how often it runs.
type countingRule struct {
	*rules.BaseRule
	calls        atomic.Int32
	readsOthers  bool
	contextValue int
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
	cache, err := openResultCache(dir, "/project", "build", stamp)
	require.NoError(t, err)
	violations, err := analyzeFiles(contexts, list, core.DefaultConfig(), nil, cache)
	require.NoError(t, err)
	require.NoError(t, cache.save())
	return violations, cache
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

// Files the run did not analyze drop out of the cache; rules the run did not
// execute keep their findings for an unchanged file.
func TestResultCacheKeepsOnlyAnalyzedFilesAndMergesRules(t *testing.T) {
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
	assert.NotContains(t, cache.previous, "b.go", "a file the run did not analyze is dropped")
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
	cache, err := openResultCache(dir, "/project", "build", "stamp")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cache.path, []byte("not a cache"), 0o600))

	_, err = openResultCache(dir, "/project", "build", "stamp")
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
	limits := cacheLimits{maxAge: 7 * 24 * time.Hour, grace: 10 * time.Minute, maxBytes: 250}
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
	cache, err := openResultCache(dir, "/project", "build1", "stamp")
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(cache.path, "-build1.gob"), cache.path)
	require.NoError(t, cache.save())
	old := time.Now().Add(-5 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(cache.path, old, old))

	_, err = openResultCache(dir, "/project", "build1", "stamp")
	require.NoError(t, err)
	info, err := os.Stat(cache.path)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), info.ModTime(), time.Minute)
}

// analyzeCachedRoot runs one root through the check pipeline with the cache,
// as runCheck does.
func analyzeCachedRoot(t *testing.T, root string, list []rules.Rule) (*preparedRoot, core.ViolationList) {
	t.Helper()
	cfg := core.DefaultConfig()
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, list, true)
	require.NoError(t, err)
	require.NotNil(t, prepared.cache)
	violations, err := analyzeProject(prepared.contexts, list, cfg, prepared.project, prepared.cache)
	require.NoError(t, err)
	require.NoError(t, prepared.cache.save())
	return prepared, violations
}

// While no input of the typed load changes, the project is not loaded and its
// findings come from the cache; the Go files still get their syntax trees. A
// frontend edit changes no input, a Go edit anywhere in the module does.
func TestProjectCacheSkipsTheLoadWhileGoInputsAreUnchanged(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
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

// The project findings are those of the project rules that ran: a run with
// another rule selection (--rule) loads the project and runs its own rules
// instead of taking the other rule's findings.
func TestProjectCacheKeysOnTheProjectRulesThatRan(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
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

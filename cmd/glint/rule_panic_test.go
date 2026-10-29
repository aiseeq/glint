package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/output"
	"github.com/aiseeq/glint/pkg/rules"
)

type panickingProjectRule struct{ *projectStubRule }

func (r *panickingProjectRule) AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error) {
	r.projectCalls++
	panic("project boom")
}

type findingFileRule struct{ *rules.BaseRule }

func (r *findingFileRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() {
		return nil
	}
	return []*core.Violation{r.CreateViolation(ctx.RelPath, 1, "file finding")}
}

// One rule's panic is a bug in that rule: the other rules' findings survive,
// the panic is named with its rule and file, and the run still fails.
func TestAnalyzeKeepsTheOtherFindingsWhenARulePanics(t *testing.T) {
	root := writeAnalysisModule(t, "package check\n")
	projectRule := &panickingProjectRule{&projectStubRule{BaseRule: rules.NewBaseRule("project-boom", "patterns", "panics", core.SeverityLow)}}
	fileBoom := &panickingRule{rules.NewBaseRule("boom-rule", "patterns", "panics", core.SeverityLow)}
	fileRule := &findingFileRule{rules.NewBaseRule("finding-rule", "patterns", "finds", core.SeverityLow)}
	list := []rules.Rule{projectRule, fileBoom, fileRule}
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, core.DefaultConfig(), list, false)
	require.NoError(t, err)

	violations, panics, err := analyzeProjectContained(prepared.contexts, prepared.contexts, list, core.DefaultConfig(), prepared.project, nil)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "finding-rule", violations[0].Rule)
	require.Len(t, panics, 2, "%v", panics)
	assert.Equal(t, []string{"boom-rule", "project-boom"}, panics.rules())
	assert.Contains(t, panics.Error(), "check.go")

	_, err = analyzeProject(prepared.contexts, list, core.DefaultConfig(), prepared.project, nil)
	require.Error(t, err, "the strict analysis used by fix still fails on a panic")
}

// The cache keeps no result of a run with a panic: the next run would take the
// panicked rule's missing findings for "nothing found".
func TestRulePanicIsNotCached(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	module := t.TempDir()
	writeModuleFile(t, module, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, module, "svc/check.go", "package svc\n\nfunc Value() int { return 1 }\n")
	root := filepath.Join(module, "svc")
	projectRule := &panickingProjectRule{newProjectStubRule()}
	fileBoom := &panickingRule{rules.NewBaseRule("boom-rule", "patterns", "panics", core.SeverityLow)}
	list := []rules.Rule{projectRule, fileBoom}

	for run := 1; run <= 2; run++ {
		cfg := core.DefaultConfig()
		prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, list, true)
		require.NoError(t, err)
		require.NotNil(t, prepared.project, "run %d loads the project: nothing was cached", run)
		_, panics, err := analyzeProjectContained(prepared.contexts, prepared.contexts, list, cfg, prepared.project, prepared.cache)
		require.NoError(t, err)
		require.Len(t, panics, 2, "run %d: both rules run again and panic again", run)
		require.NoError(t, prepared.cache.save())
	}
	assert.Equal(t, 2, projectRule.projectCalls)
}

// Every format says which rules panicked: an empty list of findings is not
// "no issues" when a rule did not finish.
func TestOutputNamesThePanickedRules(t *testing.T) {
	stats := output.Stats{FilesAnalyzed: 1, RulesPanicked: []string{"boom-rule"}}
	for _, format := range core.OutputFormats {
		var buf bytes.Buffer
		require.NoError(t, writeResults(&buf, format, nil, stats), format)
		assert.Contains(t, buf.String(), "boom-rule", format)
		assert.NotContains(t, buf.String(), "No issues found!", format)
	}
}

type panickingIndexRule struct{ *findingFileRule }

func (r *panickingIndexRule) UseProjectFiles([]*core.FileContext) { panic("index boom") }
func (r *panickingIndexRule) ResetState()                         {}

// A rule that panics while it indexes the project files is a rule panic too:
// the run names it, skips its file analysis and keeps the other findings.
func TestAnalyzeKeepsTheOtherFindingsWhenIndexingPanics(t *testing.T) {
	root := writeAnalysisModule(t, "package check\n")
	indexBoom := &panickingIndexRule{&findingFileRule{rules.NewBaseRule("index-boom", "patterns", "panics", core.SeverityLow)}}
	fileRule := &findingFileRule{rules.NewBaseRule("finding-rule", "patterns", "finds", core.SeverityLow)}
	list := []rules.Rule{indexBoom, fileRule}
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, core.DefaultConfig(), list, false)
	require.NoError(t, err)

	violations, panics, err := analyzeProjectContained(prepared.contexts, prepared.contexts, list, core.DefaultConfig(), prepared.project, nil)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "finding-rule", violations[0].Rule)
	assert.Equal(t, []string{"index-boom"}, panics.rules())
	assert.Contains(t, panics.Error(), "index boom")
}

type panickingCacheRule struct{ *findingFileRule }

func (r *panickingCacheRule) UseProjectFiles([]*core.FileContext) {}
func (r *panickingCacheRule) ResetState()                         {}
func (r *panickingCacheRule) CacheProjectFiles() ([]byte, error)  { panic("cache boom") }
func (r *panickingCacheRule) RestoreProjectFiles([]byte) error    { return nil }

// A panic while the index is saved leaves the project entry unstored: the
// next run loads the project again instead of reusing a partial entry.
func TestProjectFilesCachePanicIsNotCached(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	module := t.TempDir()
	writeModuleFile(t, module, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, module, "svc/check.go", "package svc\n\nfunc Value() int { return 1 }\n")
	root := filepath.Join(module, "svc")
	cacheBoom := &panickingCacheRule{&findingFileRule{rules.NewBaseRule("cache-boom", "patterns", "panics", core.SeverityLow)}}
	list := []rules.Rule{newProjectStubRule(), cacheBoom}

	for run := 1; run <= 2; run++ {
		cfg := core.DefaultConfig()
		prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, list, true)
		require.NoError(t, err)
		require.NotNil(t, prepared.project, "run %d loads the project: nothing was cached", run)
		_, panics, err := analyzeProjectContained(prepared.contexts, prepared.contexts, list, cfg, prepared.project, prepared.cache)
		require.NoError(t, err)
		assert.Equal(t, []string{"cache-boom"}, panics.rules(), "run %d", run)
		require.NoError(t, prepared.cache.save())
	}
}

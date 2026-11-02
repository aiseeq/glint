package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/doccheck"
)

func requiredFilesFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeModuleFile(t, root, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, root, "CLAUDE.md", strings.Repeat("a", 25000))
	writeModuleFile(t, root, ".claude/skills/x/SKILL.md", strings.Repeat("я", 12500))
	for i := range 20 {
		writeModuleFile(t, root, fmt.Sprintf("src/file-%02d.go", i), "package src\n")
		writeModuleFile(t, root, fmt.Sprintf("web/file-%02d.ts", i), "export const value = 1\n")
		writeModuleFile(t, root, fmt.Sprintf("docs/file-%02d.md", i), "documentation\n")
	}
	return root
}

func TestRequiredFileRulesLimitWalkToNeededPaths(t *testing.T) {
	root := requiredFilesFixture(t)
	list := []rules.Rule{doccheck.NewInstructionSizeRule()}
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, core.DefaultConfig(), list, false)
	require.NoError(t, err)
	assert.Len(t, prepared.contexts, 2)
	assert.Equal(t, 2, prepared.walker.Stats().TotalFiles)
	assert.ElementsMatch(t, []string{"CLAUDE.md", ".claude/skills/x/SKILL.md"}, []string{
		prepared.contexts[0].RelPath, prepared.contexts[1].RelPath,
	})
	violations, panics, err := analyzePrepared(prepared, list, core.DefaultConfig())
	require.NoError(t, err)
	require.Empty(t, panics)
	assert.Len(t, violations, 2)
}

func TestRequiredFileWalkFallsBackWhenARuleHasNoPredicate(t *testing.T) {
	root := requiredFilesFixture(t)
	list := []rules.Rule{
		doccheck.NewInstructionSizeRule(),
		&everyFileRule{BaseRule: rules.NewBaseRule("every-file", "patterns", "sees every file", core.SeverityLow)},
	}
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, core.DefaultConfig(), list, false)
	require.NoError(t, err)
	assert.Equal(t, 62, prepared.walker.Stats().TotalFiles)
	assert.Len(t, prepared.contexts, 62)
}

func TestRequiredFileWalkDoesNotCorruptFullResultCache(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	root := requiredFilesFixture(t)
	instructionRule := doccheck.NewInstructionSizeRule()
	filteredRules := []rules.Rule{instructionRule}
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, core.DefaultConfig(), filteredRules, true)
	require.NoError(t, err)
	_, panics, err := analyzePrepared(prepared, filteredRules, core.DefaultConfig())
	require.NoError(t, err)
	require.Empty(t, panics)
	require.NoError(t, prepared.cache.save())

	fullRules := []rules.Rule{
		doccheck.NewInstructionSizeRule(),
		&everyFileRule{BaseRule: rules.NewBaseRule("every-file", "patterns", "sees every file", core.SeverityLow)},
	}
	prepared, err = prepareAnalysis(core.NewGoProjectLoader(), root, core.DefaultConfig(), fullRules, true)
	require.NoError(t, err)
	got, panics, err := analyzePrepared(prepared, fullRules, core.DefaultConfig())
	require.NoError(t, err)
	require.Empty(t, panics)
	require.NoError(t, prepared.cache.save())

	baselineRoot := requiredFilesFixture(t)
	baseline, err := prepareAnalysis(core.NewGoProjectLoader(), baselineRoot, core.DefaultConfig(), fullRules, false)
	require.NoError(t, err)
	want, panics, err := analyzePrepared(baseline, fullRules, core.DefaultConfig())
	require.NoError(t, err)
	require.Empty(t, panics)
	assert.Equal(t, fingerprint(want), fingerprint(got))
}

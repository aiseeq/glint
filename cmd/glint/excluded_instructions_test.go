package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/doccheck"
)

type everyFileRule struct{ *rules.BaseRule }

func (r *everyFileRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return []*core.Violation{r.CreateViolation(ctx.RelPath, 1, "seen")}
}

// A project that excludes *.md keeps its Markdown out of the rules, but its
// Claude Code instruction files still reach instruction-size: an exclusion
// meant for documentation must not hide a CLAUDE.md over its limit. The other
// rules do not see them, and a directory excluded as a whole keeps its own.
func TestExcludedInstructionFilesReachOnlyInstructionSize(t *testing.T) {
	module := t.TempDir()
	writeModuleFile(t, module, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, module, "main.go", "package main\n\nfunc main() {}\n")
	writeModuleFile(t, module, "CLAUDE.md", strings.Repeat("a", 20000))
	writeModuleFile(t, module, ".claude/skills/deploy/SKILL.md", strings.Repeat("я", 13000))
	writeModuleFile(t, module, "docs/guide.md", strings.Repeat("a", 20000))
	writeModuleFile(t, module, "third_party/app/CLAUDE.md", strings.Repeat("a", 20000))
	cfg := core.DefaultConfig()
	// A directory excluded as a whole is not ours, its instructions neither.
	cfg.Settings.Exclude = []string{"*.md", "third_party/**"}
	every := &everyFileRule{rules.NewBaseRule("every-file", "patterns", "sees every file", core.SeverityLow)}
	list := []rules.Rule{doccheck.NewInstructionSizeRule(), every}

	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), module, cfg, list, false)
	require.NoError(t, err)
	violations, panics, err := analyzePrepared(prepared, list, cfg)
	require.NoError(t, err)
	require.Empty(t, panics)

	byRule := map[string][]string{}
	for _, v := range violations {
		byRule[v.Rule] = append(byRule[v.Rule], v.File)
	}
	assert.ElementsMatch(t, []string{"CLAUDE.md", ".claude/skills/deploy/SKILL.md"}, byRule["instruction-size"])
	for _, file := range byRule["every-file"] {
		assert.False(t, strings.HasSuffix(file, ".md"), "the exclusion still holds for %s", file)
	}

	// Without the rule the walk keeps the exclusion as it is.
	prepared, err = prepareAnalysis(core.NewGoProjectLoader(), module, cfg, []rules.Rule{every}, false)
	require.NoError(t, err)
	assert.Empty(t, prepared.excludedInstructions)
}

// The cache report counts the excluded instruction files among the analyzed
// ones: they are analyzed and cached too, and a report of more unchanged
// files than analyzed ones reads as a counting bug.
func TestCacheReportCountsExcludedInstructionFiles(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	module := t.TempDir()
	writeModuleFile(t, module, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, module, "main.go", "package main\n\nfunc main() {}\n")
	writeModuleFile(t, module, "CLAUDE.md", "# Rules\n")
	cfg := core.DefaultConfig()
	cfg.Settings.Exclude = []string{"*.md"}
	list := []rules.Rule{doccheck.NewInstructionSizeRule()}

	for run := 1; run <= 2; run++ {
		prepared, err := prepareAnalysis(core.NewGoProjectLoader(), module, cfg, list, true)
		require.NoError(t, err)
		require.NotEmpty(t, prepared.excludedInstructions)
		_, _, err = analyzePrepared(prepared, list, cfg)
		require.NoError(t, err)
		require.NoError(t, prepared.cache.save())
		if run == 2 {
			assert.Equal(t, prepared.cache.reused, prepared.analyzedFiles(), "every file is unchanged on the second run")
		}
	}
}

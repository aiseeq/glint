package patterns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const approvedModelList = `# approved models: <name> <id>
opus claude-opus-5-5

sol gpt-6.1-sol
`

func modelRule(t *testing.T, list string) *ModelNotApprovedRule {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approved")
	require.NoError(t, os.WriteFile(path, []byte(list), 0o644))
	rule := NewModelNotApprovedRule()
	require.NoError(t, rule.Configure(map[string]any{"approved_file": path}))
	return rule
}

// A model named in code by a key, --model or -m has to be on the approved
// list, by name or by id: a default left at an older or unreviewed model
// keeps running it.
func TestModelNotApprovedGo(t *testing.T) {
	ctx := rulestest.GoFile(t, "internal/config/config.go", `package config

import "os/exec"

func defaults() *Config {
	return &Config{
		Jobs: JobConfig{
			Model:       "opus",
			TriageModel: "sonnet",
			Device:      Device{Model: "ThinkPad"},
			Fallback:    cfg.Model,
		},
	}
}

func run(model string) {
	exec.Command("claude", "-p", "--model", "haiku")
	exec.Command("claude", "-p", "--model", model)
	exec.Command("claude", "-p", "--model=claude-sonnet-4-5")
	exec.Command("codex", "exec", "-m", "gpt-5-codex")
	exec.Command("git", "commit", "-m", "fix: model")
	exec.Command("claude", "--model", "claude-opus-5-5")
	// The triage used to run on --model sonnet.
	if model == "sonnet" {
		return
	}
}
`)
	assert.Equal(t, []int{9, 17, 19, 20}, violationLines(modelRule(t, approvedModelList).AnalyzeFile(ctx)))
}

func TestModelNotApprovedTypeScript(t *testing.T) {
	ctx := rulestest.TextFile(t, "src/review.ts", `const config = {
  model: 'claude-haiku-4-5',
  reviewModel: "sol",
  carModel: 'Corolla',
};
// model: 'gpt-4o' was the old default
const args = ['--model', 'gpt-4o', '--model', model];
const cmd = `+"`claude --model ${model}`"+`;
const other = `+"`claude --model sonnet -p`"+`;
`)
	assert.Equal(t, []int{2, 7, 9}, violationLines(modelRule(t, approvedModelList).AnalyzeFile(ctx)))
}

func TestModelNotApprovedShell(t *testing.T) {
	ctx := rulestest.TextFile(t, "scripts/triage.sh", `#!/bin/bash
MODEL=sonnet
REVIEW_MODEL="opus"
claude -p --model haiku "$prompt"
claude -p --model "$MODEL" "$prompt"
codex exec -m gpt-5 "$prompt"
git commit -m "bump model"
# claude --model sonnet was too slow
claude --model opus[1m] -p "$prompt"
`)
	assert.Equal(t, []int{2, 4, 6}, violationLines(modelRule(t, approvedModelList).AnalyzeFile(ctx)))
}

func TestModelNotApprovedMessageNamesTheList(t *testing.T) {
	ctx := rulestest.TextFile(t, "run.sh", "claude --model sonnet\n")
	rule := modelRule(t, approvedModelList)
	got := rule.AnalyzeFile(ctx)
	require.Len(t, got, 1)
	assert.Contains(t, got[0].Message, `"sonnet"`)
	assert.Contains(t, got[0].Message, "opus, claude-opus-5-5, sol, gpt-6.1-sol")
	assert.Equal(t, core.SeverityHigh, got[0].Severity)
}

// The list is the source of truth: a missing or malformed list fails the
// run instead of passing every model.
func TestModelNotApprovedBadList(t *testing.T) {
	files := []*core.FileContext{rulestest.TextFile(t, "run.sh", "claude --model sonnet\n")}

	missing := NewModelNotApprovedRule()
	require.NoError(t, missing.Configure(map[string]any{"approved_file": filepath.Join(t.TempDir(), "absent")}))
	require.ErrorContains(t, missing.CheckTools(files), "absent")

	for _, list := range []string{"", "# only a comment\n", "opus\n", "opus claude-opus-5-5 extra\n"} {
		require.Error(t, modelRule(t, list).CheckTools(files), "%q", list)
	}
	require.NoError(t, modelRule(t, approvedModelList).CheckTools(files))
	require.NoError(t, missing.CheckTools([]*core.FileContext{rulestest.TextFile(t, "README.md", "--model sonnet\n")}))
}

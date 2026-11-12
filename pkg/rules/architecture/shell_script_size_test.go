package architecture

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func shellOfSize(size int) string {
	head := "#!/bin/bash\n"
	return head + strings.Repeat("x", size-len(head))
}

// A shell script over the limit is reported once, at its first line, with its
// size and the limit; a script at the limit is not, nor is a large file that is
// not a shell script.
func TestShellScriptSizeRule(t *testing.T) {
	rule := NewShellScriptSizeRule()
	limit := defaultShellScriptMaxBytes

	for _, path := range []string{"tools/run.sh", "tools/run.bash", "tools/run"} {
		found := rule.AnalyzeFile(rulestest.TextFile(t, path, shellOfSize(limit+1)))
		require.Len(t, found, 1, path)
		assert.Equal(t, 1, found[0].Line, path)
		assert.Equal(t, path, found[0].File, path)
		assert.Contains(t, found[0].Message, "Shell script of 20.1 KB", path)
		assert.Contains(t, found[0].Message, "over the 20 KB limit", path)
	}

	assert.Empty(t, rule.AnalyzeFile(rulestest.TextFile(t, "tools/run.sh", shellOfSize(limit))))

	// Just over the limit reads as over it, not as equal.
	found := rule.AnalyzeFile(rulestest.TextFile(t, "tools/run.sh", shellOfSize(limit+400)))
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "Shell script of 20.4 KB, over the 20 KB limit")
	require.NoError(t, rule.Configure(map[string]any{"max_bytes": 500}))
	found = rule.AnalyzeFile(rulestest.TextFile(t, "tools/run.sh", shellOfSize(501)))
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "Shell script of 501 bytes, over the 500 bytes limit")
	rule = NewShellScriptSizeRule()
	assert.Empty(t, rule.AnalyzeFile(rulestest.TextFile(t, "tools/data.txt", strings.Repeat("x", limit+1))))
	assert.Empty(t, rule.AnalyzeFile(rulestest.TextFile(t, "tools/run", strings.Repeat("x", limit+1))))
}

// committedRepo is a git repository whose HEAD holds the given files.
func committedRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = repositoryNeutralEnv(os.Environ())
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	git("init", "-q")
	for path, content := range files {
		full := filepath.Join(root, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	git("add", "-A")
	git("commit", "-q", "-m", "scripts")
	return root
}

func analyzeIn(t *testing.T, rule *ShellScriptSizeRule, root, path, content string) []*core.Violation {
	t.Helper()
	full := filepath.Join(root, path)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	ctx, err := core.NewFileContextChecked(full, root, []byte(content), core.DefaultConfig())
	require.NoError(t, err)
	return rule.AnalyzeFile(ctx)
}

// The limit is a ratchet against HEAD: a large script kept at or below its
// committed size is not reported, so a fix inside it is not blocked; one that
// grew, crossed the limit, or is not in HEAD is, with what HEAD had.
func TestShellScriptSizeRuleRatchet(t *testing.T) {
	limit := defaultShellScriptMaxBytes
	root := committedRepo(t, map[string]string{
		"ops/big.sh":   shellOfSize(limit + 2048),
		"ops/small.sh": shellOfSize(limit - 1024),
	})
	rule := NewShellScriptSizeRule()

	assert.Empty(t, analyzeIn(t, rule, root, "ops/big.sh", shellOfSize(limit+2048)), "unchanged")
	assert.Empty(t, analyzeIn(t, rule, root, "ops/big.sh", shellOfSize(limit+1024)), "shrunk")

	found := analyzeIn(t, rule, root, "ops/big.sh", shellOfSize(limit+2049))
	require.Len(t, found, 1, "grown by a byte")
	assert.Contains(t, found[0].Message, "Shell script of 22.1 KB, over the 20 KB limit for shell: grown from 22 KB in HEAD")

	found = analyzeIn(t, rule, root, "ops/small.sh", shellOfSize(limit+1))
	require.Len(t, found, 1, "crossed the limit")
	assert.Contains(t, found[0].Message, "grown from 19 KB in HEAD")

	found = analyzeIn(t, rule, root, "ops/new.sh", shellOfSize(limit+1))
	require.Len(t, found, 1, "not in HEAD")
	assert.Contains(t, found[0].Message, "Shell script of 20.1 KB, over the 20 KB limit for shell: a new shell script")

	// A script in a nested repository is compared with that repository's HEAD.
	nested := committedRepo(t, map[string]string{"run.sh": shellOfSize(limit + 2048)})
	require.NoError(t, os.Rename(nested, filepath.Join(root, "vendored")))
	assert.Empty(t, analyzeIn(t, rule, root, "vendored/run.sh", shellOfSize(limit+2048)))

	// A hook's GIT_DIR names another repository; the script's own one is read.
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "elsewhere.git"))
	assert.Empty(t, analyzeIn(t, rule, root, "ops/big.sh", shellOfSize(limit+2048)), "under a hook")
}

// max_bytes moves the limit; zero, a negative number or a non-number is an
// error, not a silent default.
func TestShellScriptSizeRuleConfigure(t *testing.T) {
	rule := NewShellScriptSizeRule()
	require.NoError(t, rule.Configure(map[string]any{"max_bytes": 100}))
	assert.Len(t, rule.AnalyzeFile(rulestest.TextFile(t, "a.sh", shellOfSize(101))), 1)
	assert.Empty(t, rule.AnalyzeFile(rulestest.TextFile(t, "a.sh", shellOfSize(100))))

	for _, bad := range []any{0, -5, "big"} {
		assert.Error(t, NewShellScriptSizeRule().Configure(map[string]any{"max_bytes": bad}), bad)
	}
}

// The rule is on by default at medium severity.
func TestShellScriptSizeRuleIsOnAndMedium(t *testing.T) {
	assert.True(t, core.DefaultConfig().IsRuleEnabled("architecture", "shell-script-size"))
	assert.Equal(t, core.SeverityMedium, NewShellScriptSizeRule().DefaultSeverity())
}

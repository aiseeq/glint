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
	// Outside a repository every script is new.
	found = rule.AnalyzeFile(rulestest.TextFile(t, "tools/run.sh", shellOfSize(limit+1)))
	require.Len(t, found, 1)
	assert.Equal(t, "Shell script of 20.1 KB, over the 20 KB limit for shell: a new shell script", found[0].Message)
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

	// A hook's variables name another repository; the script's own one is read.
	other := committedRepo(t, map[string]string{"ops/big.sh": "#!/bin/sh\n"})
	for _, name := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY"} {
		t.Run(name, func(t *testing.T) {
			value := filepath.Join(other, ".git")
			switch name {
			case "GIT_WORK_TREE":
				value = other
			case "GIT_OBJECT_DIRECTORY":
				value = filepath.Join(other, ".git", "objects")
			}
			t.Setenv(name, value)
			assert.Empty(t, analyzeIn(t, rule, root, "ops/big.sh", shellOfSize(limit+2048)), "unchanged under %s", name)
			assert.Len(t, analyzeIn(t, rule, root, "ops/big.sh", shellOfSize(limit+2049)), 1, "grown under %s", name)
		})
	}
}

// HEAD is read as committed: a replace ref in the repository does not stand
// in for the script, and a script committed empty that grew is not new.
func TestShellScriptSizeRuleReadsTheCommittedBlob(t *testing.T) {
	limit := defaultShellScriptMaxBytes
	root := committedRepo(t, map[string]string{"ops/big.sh": shellOfSize(limit + 2048), "ops/empty.sh": ""})
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		cmd.Env = repositoryNeutralEnv(os.Environ())
		out, err := cmd.Output()
		require.NoError(t, err)
		return strings.TrimSpace(string(out))
	}
	small := filepath.Join(t.TempDir(), "small")
	require.NoError(t, os.WriteFile(small, []byte("#!/bin/sh\n"), 0o644))
	git("replace", git("rev-parse", "HEAD:ops/big.sh"), git("hash-object", "-w", small))

	rule := NewShellScriptSizeRule()
	assert.Empty(t, analyzeIn(t, rule, root, "ops/big.sh", shellOfSize(limit+2048)))
	found := analyzeIn(t, rule, root, "ops/empty.sh", shellOfSize(limit+1))
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "grown from 0 bytes in HEAD")
}

// A HEAD that git could not read is told in the finding, not passed off as a
// new script: without git every large script would look new.
func TestShellScriptSizeRuleTellsAnUnreadHead(t *testing.T) {
	limit := defaultShellScriptMaxBytes
	root := committedRepo(t, map[string]string{"ops/big.sh": shellOfSize(limit + 2048)})
	t.Setenv("PATH", t.TempDir())
	found := analyzeIn(t, NewShellScriptSizeRule(), root, "ops/big.sh", shellOfSize(limit+2048))
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "Shell script of 22 KB, over the 20 KB limit for shell: its size in HEAD not read: ")
	assert.Contains(t, found[0].Message, "executable file not found")

	// git that fails otherwise than on a path absent from HEAD (exit 128).
	fake := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(fake, "git"), []byte("#!/bin/sh\nexit 3\n"), 0o755))
	t.Setenv("PATH", fake)
	found = analyzeIn(t, NewShellScriptSizeRule(), root, "ops/big.sh", shellOfSize(limit+2048))
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "its size in HEAD not read: git cat-file: exit status 3")

}

// git's exit 128 counts as a new script only when its words say HEAD has no
// such path; a store without the script's blob is a failure, told with them.
func TestShellScriptSizeRuleTellsAFailedHead(t *testing.T) {
	limit := defaultShellScriptMaxBytes
	root := committedRepo(t, map[string]string{"ops/big.sh": shellOfSize(limit + 2048)})
	cmd := exec.Command("git", "-C", root, "rev-parse", "HEAD:ops/big.sh")
	cmd.Env = repositoryNeutralEnv(os.Environ())
	out, err := cmd.Output()
	require.NoError(t, err)
	blob := strings.TrimSpace(string(out))
	require.NoError(t, os.Remove(filepath.Join(root, ".git", "objects", blob[:2], blob[2:])))

	found := analyzeIn(t, NewShellScriptSizeRule(), root, "ops/big.sh", shellOfSize(limit+2048))
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "its size in HEAD not read: git cat-file: exit status 128: fatal: ")
}

// git's words are read in English whatever the caller's locale, and a
// repository without commits has every script new.
func TestShellScriptSizeRuleReadsGitInAnyLocale(t *testing.T) {
	limit := defaultShellScriptMaxBytes
	root := committedRepo(t, map[string]string{"ops/big.sh": shellOfSize(limit + 2048)})
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	t.Setenv("LANGUAGE", "de")
	found := analyzeIn(t, NewShellScriptSizeRule(), root, "ops/new.sh", shellOfSize(limit+1))
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "a new shell script")

	empty := t.TempDir()
	cmd := exec.Command("git", "-C", empty, "init", "-q")
	cmd.Env = repositoryNeutralEnv(os.Environ())
	require.NoError(t, cmd.Run())
	found = analyzeIn(t, NewShellScriptSizeRule(), empty, "ops/big.sh", shellOfSize(limit+1))
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "a new shell script")
}

// A script moved without growing is not new: git mv, edited or not, is
// matched to its HEAD path by git's rename detection, and a plain move or copy
// by its content being a blob of HEAD.
func TestShellScriptSizeRuleFollowsMoves(t *testing.T) {
	limit := defaultShellScriptMaxBytes
	big, other := shellOfSize(limit+2048), shellOfSize(limit+4096)
	git := func(root string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		cmd.Env = repositoryNeutralEnv(os.Environ())
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	rule := NewShellScriptSizeRule()
	moved := func(t *testing.T, content string, move func(root string)) []*core.Violation {
		t.Helper()
		root := committedRepo(t, map[string]string{"ops/big.sh": big, "AAA.sh": other, "README": "scripts\n"})
		move(root)
		return analyzeIn(t, rule, root, "deploy/big.sh", content)
	}
	gitMove := func(root string) {
		// A change listed before the rename, under a name that starts as a
		// rename status does, and a rename of another script listed first.
		require.NoError(t, os.WriteFile(filepath.Join(root, "README"), []byte("scripts moved\n"), 0o644))
		require.NoError(t, os.MkdirAll(filepath.Join(root, "CCC"), 0o755))
		git(root, "mv", "AAA.sh", "CCC/AAA.sh")
		require.NoError(t, os.MkdirAll(filepath.Join(root, "deploy"), 0o755))
		git(root, "mv", "ops/big.sh", "deploy/big.sh")
	}
	plainMove := func(root string) {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "deploy"), 0o755))
		require.NoError(t, os.Rename(filepath.Join(root, "ops/big.sh"), filepath.Join(root, "deploy/big.sh")))
	}
	copied := func(root string) {}

	assert.Empty(t, moved(t, big, gitMove), "git mv")
	assert.Empty(t, moved(t, big[:len(big)-100], gitMove), "git mv, shrunk")
	assert.Empty(t, moved(t, big, plainMove), "mv")
	found := moved(t, big, copied)
	require.Len(t, found, 1, "cp: the original stays, the copy is new shell code")
	assert.Contains(t, found[0].Message, "a new shell script")

	found = moved(t, big+"echo more\n", gitMove)
	require.Len(t, found, 1, "git mv, grown")
	assert.Contains(t, found[0].Message, "grown from 22 KB in HEAD as ops/big.sh")

	found = moved(t, big+"echo more\n", plainMove)
	require.Len(t, found, 1, "mv, grown, not in the index")
	assert.Contains(t, found[0].Message, "a new shell script")

	// A move and a copy of one script in one change: the HEAD path is moved
	// once, so one of the two is new shell code once staged, as the gate sees it.
	root := committedRepo(t, map[string]string{"ops/big.sh": big})
	require.NoError(t, os.MkdirAll(filepath.Join(root, "deploy"), 0o755))
	require.NoError(t, os.Rename(filepath.Join(root, "ops/big.sh"), filepath.Join(root, "deploy/prod.sh")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "deploy/stage.sh"), []byte(big), 0o644))
	git(root, "add", "-A")
	found = append(analyzeIn(t, rule, root, "deploy/prod.sh", big), analyzeIn(t, rule, root, "deploy/stage.sh", big)...)
	require.Len(t, found, 1, "a move and a copy")
	assert.Contains(t, found[0].Message, "a new shell script")

	// A folder whose name starts with a space.
	root = committedRepo(t, map[string]string{"ops/big.sh": big})
	require.NoError(t, os.MkdirAll(filepath.Join(root, " lead"), 0o755))
	git(root, "mv", "ops/big.sh", " lead/big.sh")
	found = analyzeIn(t, rule, root, " lead/big.sh", big+"echo more\n")
	require.Len(t, found, 1, "git mv into a folder with a leading space, grown")
	assert.Contains(t, found[0].Message, "grown from 22 KB in HEAD as ops/big.sh")

	// Under a hook's index of another repository.
	elsewhere := committedRepo(t, map[string]string{"tools/other.sh": "#!/bin/sh\n"})
	root = committedRepo(t, map[string]string{"ops/big.sh": big, "AAA.sh": other, "README": "scripts\n"})
	gitMove(root)
	t.Setenv("GIT_INDEX_FILE", filepath.Join(elsewhere, ".git", "index"))
	found = analyzeIn(t, rule, root, "deploy/big.sh", big+"echo more\n")
	require.Len(t, found, 1, "git mv, grown, under another index")
	assert.Contains(t, found[0].Message, "grown from 22 KB in HEAD as ops/big.sh")
}

// A committed link to a large script is not reported: git keeps the link's
// target path, not the script, and the script is checked under its own name.
func TestShellScriptSizeRuleSkipsLinks(t *testing.T) {
	limit := defaultShellScriptMaxBytes
	root := committedRepo(t, map[string]string{"scripts/check.sh": shellOfSize(limit + 2048)})
	require.NoError(t, os.MkdirAll(filepath.Join(root, "githooks"), 0o755))
	require.NoError(t, os.Symlink("../scripts/check.sh", filepath.Join(root, "githooks", "pre-commit")))
	require.NoError(t, os.Symlink("check.sh", filepath.Join(root, "scripts", "link.sh")))
	cmd := exec.Command("git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "links")
	cmd.Env = repositoryNeutralEnv(os.Environ())
	require.NoError(t, exec.Command("git", "-C", root, "add", "-A").Run())
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	rule := NewShellScriptSizeRule()
	content, err := os.ReadFile(filepath.Join(root, "scripts", "check.sh"))
	require.NoError(t, err)
	for _, link := range []string{"githooks/pre-commit", "scripts/link.sh"} {
		ctx, err := core.NewFileContextChecked(filepath.Join(root, link), root, content, core.DefaultConfig())
		require.NoError(t, err)
		assert.Empty(t, rule.AnalyzeFile(ctx), link)
	}
}

// The size and the limit, and the HEAD size and the size, never read the same:
// rounding to a tenth of a kilobyte that would make them equal gives bytes.
func TestShellScriptSizeRuleMessageTellsSizesApart(t *testing.T) {
	cases := []struct {
		limit, head, size int
		want              string
	}{
		{20000, -1, 20001, "Shell script of 20001 bytes, over the 20000 bytes limit for shell: a new shell script"},
		{1100, -1, 1101, "Shell script of 1101 bytes, over the 1100 bytes limit for shell: a new shell script"},
		{defaultShellScriptMaxBytes, 22600, 22601, "Shell script of 22601 bytes, over the 20 KB limit for shell: grown from 22600 bytes in HEAD"},
		{defaultShellScriptMaxBytes, 20000, 23000, "Shell script of 22.5 KB, over the 20 KB limit for shell: grown from 19.6 KB in HEAD"},
		{1000, -1, 1024, "Shell script of 1 KB, over the 1000 bytes limit for shell: a new shell script"},
		{1000, -1, 1023, "Shell script of 1023 bytes, over the 1000 bytes limit for shell: a new shell script"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, sizeMessage(c.size, c.limit, headVersion{size: c.head}, nil), "%+v", c)
	}
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

package shellrules

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTree writes the files under root, each with the mode given for it on
// disk.
func writeTree(t *testing.T, root string, files map[string]string, modes map[string]os.FileMode) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		mode, ok := modes[name]
		if !ok {
			mode = 0o644
		}
		require.NoError(t, os.WriteFile(path, []byte(content), mode))
		require.NoError(t, os.Chmod(path, mode))
	}
}

// gitIn runs git in root and fails the test on an error.
func gitIn(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

// binExecBitFindings walks root as the check flow does with the rule enabled
// and returns the places of its findings with their messages.
func binExecBitFindings(t *testing.T, root string) ([]string, []*core.Violation) {
	t.Helper()
	rule := NewBinScriptExecBitRule()
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).
		WithAdditionalFilePredicate(rule.RequiresAdditionalFile).WalkSync()
	require.Empty(t, errs)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	return rulestest.ViolationPlaces(violations), violations
}

// A script in bin/ that git records without the executable bit is checked
// out non-executable on every other clone: ./bin/run fails with permission
// denied. The mode comes from the index, not from the disk of this clone.
func TestBinScriptExecBit(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"bin/run":            "#!/bin/sh\nexec go run ./cmd/app \"$@\"\n",
		"bin/tool":           "#!/usr/bin/env python3\nprint('ok')\n",
		"bin/deploy.sh":      "#!/usr/bin/env bash\necho deploy\n",
		"bin/ok":             "#!/bin/bash\necho ok\n",
		"bin/data":           "plain text kept beside the scripts\n",
		"bin/README.md":      "# tools\n",
		"bin/helper.py":      "def helper():\n    return 1\n",
		"bin/lib/common.sh":  "#!/bin/bash\nlog() { echo \"$@\"; }\n",
		"scripts/release":    "#!/bin/sh\necho release\n",
		"services/bin/start": "#!/bin/sh\necho start\n",
		"go.mod":             "module example.com/app\n\ngo 1.24\n",
	}, map[string]os.FileMode{
		// The disk of this clone says executable, the index does not.
		"bin/run": 0o755,
	})
	// A link git records as 120000: the bit belongs to the file it names.
	require.NoError(t, os.Symlink("../scripts/release", filepath.Join(root, "bin", "release")))
	gitIn(t, root, "init", "-q")
	gitIn(t, root, "config", "core.fileMode", "false")
	gitIn(t, root, "add", "-A")
	gitIn(t, root, "update-index", "--chmod=-x", "bin/run")
	// The disk says plain, the index says executable.
	gitIn(t, root, "update-index", "--chmod=+x", "bin/ok")
	// Not yet added: git knows no mode of it.
	writeTree(t, root, map[string]string{"bin/new": "#!/bin/sh\necho new\n"}, nil)

	places, violations := binExecBitFindings(t, root)
	assert.Equal(t, []string{"bin/deploy.sh:1", "bin/run:1", "bin/tool:1", "services/bin/start:1"}, places)
	for _, v := range violations {
		if v.File == "bin/run" {
			assert.Contains(t, v.Message, "100644")
			assert.Contains(t, v.Suggestion, "git update-index --chmod=+x bin/run")
			assert.Equal(t, "#!/bin/sh", v.Code)
		}
	}

	// The fix in the index clears the finding in the same process.
	gitIn(t, root, "update-index", "--chmod=+x", "bin/run")
	places, _ = binExecBitFindings(t, root)
	assert.Equal(t, []string{"bin/deploy.sh:1", "bin/tool:1", "services/bin/start:1"}, places)
}

// glint run on a subdirectory of the repository names the path from it and
// finds the mode by the path from the top of the repository.
func TestBinScriptExecBitInSubdirectory(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"backend/bin/run": "#!/bin/sh\necho run\n",
		"backend/go.mod":  "module example.com/app\n\ngo 1.24\n",
	}, nil)
	gitIn(t, root, "init", "-q")
	gitIn(t, root, "config", "core.fileMode", "false")
	gitIn(t, root, "add", "-A")

	places, violations := binExecBitFindings(t, filepath.Join(root, "backend"))
	assert.Equal(t, []string{"bin/run:1"}, places)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Suggestion, "git update-index --chmod=+x bin/run")
}

// suggestedCommand is the shell command a finding's suggestion names.
func suggestedCommand(t *testing.T, v *core.Violation) string {
	t.Helper()
	_, command, ok := strings.Cut(v.Suggestion, "Record the executable bit in git: ")
	require.True(t, ok, v.Suggestion)
	return command
}

// indexMode is the mode git's index records for path.
func indexMode(t *testing.T, root, path string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "ls-files", "-s", "--", ":(literal)"+path).Output()
	require.NoError(t, err)
	mode, _, _ := strings.Cut(string(out), " ")
	return mode
}

// The command of the suggestion runs as written from where glint ran, also
// for a name a shell splits or reads as a quote.
func TestBinScriptExecBitSuggestionRunsInShell(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"bin/a b":   "#!/bin/sh\necho a\n",
		"bin/q\"x":  "#!/bin/sh\necho q\n",
		"bin/it's":  "#!/bin/sh\necho it\n",
		"bin/t\tab": "#!/bin/sh\necho tab\n",
		"go.mod":    "module example.com/app\n\ngo 1.24\n",
	}, nil)
	gitIn(t, root, "init", "-q")
	gitIn(t, root, "config", "core.fileMode", "false")
	gitIn(t, root, "add", "-A")

	places, violations := binExecBitFindings(t, root)
	assert.Equal(t, []string{"bin/a b:1", "bin/it's:1", "bin/q\"x:1", "bin/t\tab:1"}, places)
	for _, v := range violations {
		cmd := exec.Command("bash", "-c", suggestedCommand(t, v))
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s: %s", v.Suggestion, out)
		assert.Equal(t, "100755", indexMode(t, root, v.File), v.Suggestion)
	}
}

// glint run on the bin directory itself (glint check bin, glint check
// bin/run, cd bin && glint check .) names the script from there and finds it
// as from the top of the repository.
func TestBinScriptExecBitRunOnBinDirectory(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"bin/run":         "#!/bin/sh\necho run\n",
		"bin/ok":          "#!/bin/sh\necho ok\n",
		"svc/bin/start":   "#!/bin/sh\necho start\n",
		"svc/.glint.yaml": "settings: {}\n",
		"go.mod":          "module example.com/app\n\ngo 1.24\n",
	}, nil)
	gitIn(t, root, "init", "-q")
	gitIn(t, root, "config", "core.fileMode", "false")
	gitIn(t, root, "add", "-A")
	gitIn(t, root, "update-index", "--chmod=+x", "bin/ok")

	bin := filepath.Join(root, "bin")
	places, violations := binExecBitFindings(t, bin)
	assert.Equal(t, []string{"run:1"}, places)
	require.Len(t, violations, 1)
	cmd := exec.Command("bash", "-c", suggestedCommand(t, violations[0]))
	cmd.Dir = bin
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s: %s", violations[0].Suggestion, out)
	assert.Equal(t, "100755", indexMode(t, root, "bin/run"))

	places, _ = binExecBitFindings(t, filepath.Join(root, "svc", "bin"))
	assert.Equal(t, []string{"start:1"}, places)
	places, _ = binExecBitFindings(t, filepath.Join(root, "svc"))
	assert.Equal(t, []string{"bin/start:1"}, places)
}

// Outside git there is no index: nothing is reported, and nothing fails.
func TestBinScriptExecBitOutsideGit(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"bin/run": "#!/bin/sh\necho run\n",
		"go.mod":  "module example.com/app\n\ngo 1.24\n",
	}, nil)
	places, _ := binExecBitFindings(t, root)
	assert.Empty(t, places)
	inputs, err := NewBinScriptExecBitRule().CacheInputs(root)
	require.NoError(t, err)
	assert.Empty(t, inputs)
}

// The modes join the result-cache key: a change of the index alone reruns
// the rule.
func TestBinScriptExecBitCacheInputs(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"bin/run":   "#!/bin/sh\necho run\n",
		"bin/z":     "#!/bin/sh\n",
		"bin/lib/x": "#!/bin/sh\n",
		"a/bin/x":   "#!/bin/sh\n",
		"README.md": "# app\n",
	}, nil)
	gitIn(t, root, "init", "-q")
	gitIn(t, root, "config", "core.fileMode", "false")
	gitIn(t, root, "add", "-A")
	rule := NewBinScriptExecBitRule()
	before, err := rule.CacheInputs(root)
	require.NoError(t, err)
	assert.Equal(t, "100644 a/bin/x\n100644 bin/run\n100644 bin/z\n", before)
	gitIn(t, root, "update-index", "--chmod=+x", "bin/run")
	after, err := rule.CacheInputs(root)
	require.NoError(t, err)
	assert.Equal(t, "100644 a/bin/x\n100755 bin/run\n100644 bin/z\n", after)
	assert.True(t, rule.ReadsOtherFiles())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

// The walk reads a file for the rule only when it is a script right in a
// bin directory: a compiled program there, a script elsewhere and a FIFO
// are left alone.
func TestBinScriptExecBitSelectsFiles(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"bin/tool":          "#!/usr/bin/env python3\n",
		"bin/data":          "\x7fELF\x02\x01\x01",
		"bin/lib/common.sh": "#!/bin/bash\n",
		"scripts/tool":      "#!/usr/bin/env python3\n",
		"bin/empty":         "",
		"bin/notes":         "# notes\n",
	}, nil)
	require.NoError(t, syscall.Mkfifo(filepath.Join(root, "bin", "pipe"), 0o644))
	rule := NewBinScriptExecBitRule()
	assert.True(t, rule.RequiresFile(filepath.Join(root, "bin", "run")))
	assert.False(t, rule.RequiresFile(filepath.Join(root, "bin", "lib", "common.sh")))
	assert.False(t, rule.RequiresFile(filepath.Join(root, "scripts", "run")))
	assert.True(t, rule.RequiresAdditionalFile(filepath.Join(root, "bin", "tool")))
	assert.False(t, rule.RequiresAdditionalFile(filepath.Join(root, "bin", "data")))
	assert.False(t, rule.RequiresAdditionalFile(filepath.Join(root, "bin", "empty")))
	assert.False(t, rule.RequiresAdditionalFile(filepath.Join(root, "bin", "notes")), "a comment is no #!")
	assert.False(t, rule.RequiresAdditionalFile(filepath.Join(root, "bin", "lib", "common.sh")))
	assert.False(t, rule.RequiresAdditionalFile(filepath.Join(root, "scripts", "tool")))
	assert.False(t, rule.RequiresAdditionalFile(filepath.Join(root, "bin", "missing")))
	done := make(chan bool, 1)
	go func() { done <- rule.RequiresAdditionalFile(filepath.Join(root, "bin", "pipe")) }()
	select {
	case selected := <-done:
		assert.False(t, selected)
	case <-time.After(5 * time.Second):
		t.Fatal("a FIFO in bin/ was opened: the walk blocks on it")
	}
}

// A repository git cannot read is told in a finding on the script in bin/,
// not passed off as a script without a mode; a file outside bin/ does not
// ask git at all.
func TestBinScriptExecBitGitFailure(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: "+filepath.Join(root, "missing")+"\n"), 0o644))
	rule := NewBinScriptExecBitRule()
	script := []byte("#!/bin/sh\necho run\n")
	found := rule.AnalyzeFile(core.NewFileContext(filepath.Join(root, "bin", "run"), root, script, core.DefaultConfig()))
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "could not read the mode of script bin/run from the git index")
	assert.Empty(t, rule.AnalyzeFile(core.NewFileContext(filepath.Join(root, "scripts", "run"), root, script, core.DefaultConfig())))
	_, err := rule.CacheInputs(root)
	require.Error(t, err)
}

// A script whose path cannot be made absolute (the working directory is
// gone) is told in a finding, not passed off as one without a mode.
func TestBinScriptExecBitPathNotResolved(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "gone")
	require.NoError(t, os.Mkdir(gone, 0o755))
	t.Chdir(gone)
	require.NoError(t, os.Remove(gone))
	found := NewBinScriptExecBitRule().AnalyzeFile(core.NewFileContext(filepath.Join("bin", "run"), ".", []byte("#!/bin/sh\n"), core.DefaultConfig()))
	require.Len(t, found, 1)
	assert.Contains(t, found[0].Message, "could not read the mode of script bin/run")
}

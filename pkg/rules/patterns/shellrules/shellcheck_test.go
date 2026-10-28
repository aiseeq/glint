package shellrules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shellcheckProject writes files under a fresh root, points the tool cache
// at a fresh directory, and returns the root.
func shellcheckProject(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck is not installed: the rule runs it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	for name, content := range files {
		patterntest.WriteProjectFile(t, root, name, content)
	}
	return root
}

func shellcheckFindings(t *testing.T, root, name string) []string {
	t.Helper()
	path := filepath.Join(root, name)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	ctx, err := core.NewFileContextChecked(path, root, content, core.DefaultConfig())
	require.NoError(t, err)
	var found []string
	for _, v := range NewShellcheckRule().AnalyzeFile(ctx) {
		code, _, _ := strings.Cut(v.Message, ":")
		found = append(found, fmt.Sprintf("%s %s:%d %s", v.Severity, v.File, v.Line, code))
	}
	return found
}

// shellcheck's errors are high and its warnings medium; its info notes (an
// unquoted $1, SC2086) are not reported, and a file that is not a shell
// script is not checked.
func TestShellcheckReportsErrorsAndWarnings(t *testing.T) {
	root := shellcheckProject(t, map[string]string{
		"deploy":        "#!/bin/bash\nrm -rf $1/*\nfor f in $(ls); do echo \"$f\"; done\n",
		"lib/common.sh": "greet() { echo hi; }\n",
		"notes.txt":     "#!/bin/bash\necho $1\n",
	})
	assert.Equal(t, []string{
		"medium deploy:2 SC2115",
		"high deploy:3 SC2045",
	}, shellcheckFindings(t, root, "deploy"))
	// A file without a shebang: shellcheck cannot tell its shell.
	assert.Equal(t, []string{"high lib/common.sh:1 SC2148"}, shellcheckFindings(t, root, "lib/common.sh"))
	assert.Empty(t, shellcheckFindings(t, root, "notes.txt"))
}

// The answer is cached, but a change to the project's .shellcheckrc or to
// a sourced file is a change of the input: shellcheck runs again.
func TestShellcheckCacheFollowsWhatShellcheckReads(t *testing.T) {
	root := shellcheckProject(t, map[string]string{
		".shellcheckrc": "external-sources=true\nsource-path=SCRIPTDIR\n",
		"run.sh":        "#!/bin/bash\n. ./env.sh\necho \"$target\"\n",
		"env.sh":        "#!/bin/bash\n# shellcheck disable=SC2034\ntarget=prod\n",
	})
	assert.Empty(t, shellcheckFindings(t, root, "run.sh"))

	patterntest.WriteProjectFile(t, root, "env.sh", "#!/bin/bash\n# shellcheck disable=SC2034\nother=prod\n")
	assert.Equal(t, []string{"medium run.sh:3 SC2154"}, shellcheckFindings(t, root, "run.sh"))

	patterntest.WriteProjectFile(t, root, ".shellcheckrc", "external-sources=true\nsource-path=SCRIPTDIR\ndisable=SC2154\n")
	assert.Empty(t, shellcheckFindings(t, root, "run.sh"))
}

// A root with shell scripts needs shellcheck; a root without them does not.
func TestShellcheckCheckToolsNeedsShellcheckForScripts(t *testing.T) {
	rule := NewShellcheckRule()
	rule.program = "shellcheck-that-is-not-installed"
	script, err := core.NewFileContextChecked("/p/run.sh", "/p", []byte("#!/bin/sh\n"), core.DefaultConfig())
	require.NoError(t, err)
	code, err := core.NewFileContextChecked("/p/main.go", "/p", []byte("package main\n"), core.DefaultConfig())
	require.NoError(t, err)

	assert.NoError(t, rule.CheckTools([]*core.FileContext{code}))
	err = rule.CheckTools([]*core.FileContext{code, script})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 shell scripts need shellcheck")
}

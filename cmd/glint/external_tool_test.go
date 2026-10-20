package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// A root with a shell script fails the run when shellcheck is missing,
// instead of passing the script unchecked; a root without one does not
// need it.
func TestMissingShellcheckFailsTheRun(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	analyze := func(files map[string]string) error {
		root := t.TempDir()
		for name, content := range files {
			path := filepath.Join(root, name)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
			require.NoError(t, os.WriteFile(path, []byte(content), 0o755))
		}
		cfg, enabled, err := loadConfig(root)
		require.NoError(t, err)
		prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, enabled, false)
		require.NoError(t, err)
		rules.ResetState(enabled)
		_, err = analyzeProject(prepared.contexts, enabled, cfg, prepared.project, nil)
		return err
	}

	err := analyze(map[string]string{"notes.md": "# Notes\n", "tools/deploy": "#!/bin/bash\necho deploy\n"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule shellcheck: 1 shell scripts need shellcheck")

	assert.NoError(t, analyze(map[string]string{"notes.md": "# Notes\n"}))
}

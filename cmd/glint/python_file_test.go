package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// pythonScript is written to trip text rules if they read Python: a secret,
// a hard-coded URL, SQL in a string, a TODO, a block repeated across files.
const pythonScript = `#!/usr/bin/env python3
# TODO: rewrite
import os, sqlite3

PASSWORD = "hunter2-very-secret-password"
API = "http://api.example.com/v1/tokens"

def load(path):
    db = sqlite3.connect(path)
    for row in db.execute("SELECT * FROM users WHERE id = " + os.environ["ID"]):
        print(row)
        print(row)
        print(row)
        print(row)
        print(row)
        print(row)
    return db
`

// The walker hands Python sources to the rules so python-file can see them.
// Besides it only the secret scan, which reads any text, reports in them;
// every other rule guards its own languages. An exception by glob, with its
// reason, silences python-file for its files.
func TestPythonSourcesReachOnlyThePythonFileRule(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":            "module example.com/check\n\ngo 1.24\n",
		"main.go":           "package main\n\nfunc main() {}\n",
		"tools/token.py":    pythonScript,
		"tools/rotate.py":   pythonScript,
		"ml/voice/model.py": pythonScript,
		".glint.yaml": `version: 1
categories:
  architecture:
    rules:
      python-file:
        exceptions:
          - files: "ml/**"
            reason: speech recognition model
`,
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}

	cfg, enabled, err := loadConfig(root)
	require.NoError(t, err)
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, enabled, false)
	require.NoError(t, err)
	rules.ResetState(enabled)
	violations, err := analyzeProject(prepared.contexts, enabled, cfg, prepared.project, nil)
	require.NoError(t, err)
	findings, _ := core.SplitSuppressions(violations)

	var python []string
	for _, v := range findings {
		if !strings.HasSuffix(v.File, ".py") {
			continue
		}
		python = append(python, v.Rule+" "+v.Location())
	}
	assert.ElementsMatch(t, []string{
		"python-file tools/rotate.py:1",
		"python-file tools/token.py:1",
		"hardcoded-secret ml/voice/model.py:5",
		"hardcoded-secret tools/rotate.py:5",
		"hardcoded-secret tools/token.py:5",
	}, python)
}

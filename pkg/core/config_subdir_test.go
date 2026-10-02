package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A check of a subdirectory takes the configuration of the project above it:
// its excludes and exceptions name paths from the project root, so they must
// match the same files as in a check of the whole project.
func TestConfigPathsFromSubdirectoryRun(t *testing.T) {
	root := t.TempDir()
	config := `version: 1
settings:
  exclude:
    - frontend/generated/**
categories:
  patterns:
    enabled: true
    rules:
      frontend-money-arithmetic:
        enabled: true
        exceptions:
          - files: "frontend/e2e/utils/**"
            reason: "helpers compute the expected amount themselves"
          - file: "frontend/app/total.ts"
            line: 3
            reason: "display only"
`
	require.NoError(t, os.WriteFile(filepath.Join(root, ".glint.yaml"), []byte(config), 0o644))
	sub := filepath.Join(root, "frontend")
	require.NoError(t, os.MkdirAll(sub, 0o755))

	for _, run := range []struct{ dir, prefix string }{{root, "frontend/"}, {sub, ""}} {
		cfg, err := LoadConfigWithDefaults(run.dir)
		require.NoError(t, err)
		assert.True(t, cfg.ShouldExclude(run.prefix+"generated/api.ts"), run.dir)
		assert.True(t, cfg.IsFileExcepted("patterns", "frontend-money-arithmetic", run.prefix+"e2e/utils/users.ts"), run.dir)
		assert.False(t, cfg.IsFileExcepted("patterns", "frontend-money-arithmetic", run.prefix+"app/users.ts"), run.dir)
		assert.True(t, cfg.IsViolationExcepted("patterns", "frontend-money-arithmetic", run.prefix+"app/total.ts", &Violation{Line: 3}), run.dir)
	}
}

// An exception written relative to a checked subdirectory instead of the
// configuration's directory suppresses nothing; it is dead whichever
// directory the run checks.
func TestDeadExceptions(t *testing.T) {
	root := t.TempDir()
	config := `version: 1
categories:
  patterns:
    enabled: true
    rules:
      frontend-money-arithmetic:
        exceptions:
          - files: "frontend/e2e/utils/**"
          - files: "services/billing/**"
          - file: "total.ts"
            line: 3
          - pattern: "legacy"
          - file: "backend/services/billing/invoice.go"
            function: renamedAway
          - file: "backend/services/billing/invoice.go"
            function: Issue
          - files: "frontend/**"
            function: anyTS
`
	require.NoError(t, os.WriteFile(filepath.Join(root, ".glint.yaml"), []byte(config), 0o644))
	for _, dir := range []string{"frontend/e2e/utils", "backend/services/billing", "frontend/app", "node_modules/x/services/billing"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
	}
	for _, file := range []string{"frontend/e2e/utils/users.ts", "backend/services/billing/invoice.go", "frontend/app/total.ts", "node_modules/x/services/billing/a.js"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, file), nil, 0o644))
	}
	cfg, err := LoadConfigWithDefaults(filepath.Join(root, "backend"))
	require.NoError(t, err)
	files, err := cfg.ConfigFiles()
	require.NoError(t, err)
	assert.NotContains(t, files, "node_modules/x/services/billing/a.js")
	functions := func(path string) ([]string, bool, error) {
		if path == "backend/services/billing/invoice.go" {
			return []string{"Issue"}, true, nil
		}
		return nil, false, nil
	}
	dead, err := cfg.DeadExceptions(files, functions)
	require.NoError(t, err)
	require.Len(t, dead, 2)
	assert.Equal(t, "services/billing/**", dead[0].Exception.Files)
	assert.Equal(t, 9, dead[0].Line)
	assert.Equal(t, filepath.Join(root, ".glint.yaml"), dead[0].Source)
	assert.False(t, dead[0].NoFunction)
	assert.Equal(t, "renamedAway", dead[1].Exception.Function)
	assert.True(t, dead[1].NoFunction)
}

// A file git ignores is not analyzed, so an exception naming it suppresses
// nothing in any checkout: the files of the configuration leave it out.
func TestConfigFilesLeaveOutGitignoredFiles(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".glint.yaml"), []byte("version: 1\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".gitignore"), []byte("keys/\n*.local.go\n"), 0o644))
	for _, dir := range []string{"keys", "app"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "app/.gitignore"), []byte("scratch.go\n"), 0o644))
	for _, file := range []string{"keys/README.md", "app/main.go", "app/dev.local.go", "app/scratch.go"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, file), nil, 0o644))
	}
	cfg, err := LoadConfigWithDefaults(root)
	require.NoError(t, err)
	files, err := cfg.ConfigFiles()
	require.NoError(t, err)
	assert.Contains(t, files, "app/main.go")
	assert.NotContains(t, files, "keys/README.md")
	assert.NotContains(t, files, "app/dev.local.go")
	assert.NotContains(t, files, "app/scratch.go")
}

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
	dead := cfg.DeadExceptions(files)
	require.Len(t, dead, 1)
	assert.Equal(t, "services/billing/**", dead[0].Exception.Files)
	assert.Equal(t, 9, dead[0].Line)
	assert.Equal(t, filepath.Join(root, ".glint.yaml"), dead[0].Source)
}

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

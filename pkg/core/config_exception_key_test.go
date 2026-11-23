package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExceptionKeyFlowList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".glint.yaml")
	flow := `version: 1
categories:
  patterns:
    rules:
      error-string:
        exceptions: [{file: a.go, function: F, reason: used}, {file: b.go, function: G, reason: stale}]
`
	require.NoError(t, os.WriteFile(path, []byte(flow), 0o644))
	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	exceptions := cfg.GetRuleExceptions("patterns", "error-string")
	require.Len(t, exceptions, 2)
	require.NotEqual(t, cfg.ExceptionKey(exceptions[0]), cfg.ExceptionKey(exceptions[1]))
	require.Equal(t, 6, exceptions[0].DeclaredAt())
	require.Equal(t, 6, exceptions[1].DeclaredAt())

	block := `version: 1
categories:
  patterns:
    rules:
      error-string:
        exceptions:
          - file: a.go
            function: F
            reason: used
          - file: b.go
            function: G
            reason: stale
`
	require.NoError(t, os.WriteFile(path, []byte(block), 0o644))
	cfg, err = LoadConfig(path)
	require.NoError(t, err)
	exceptions = cfg.GetRuleExceptions("patterns", "error-string")
	require.Len(t, exceptions, 2)
	require.Equal(t, 7, exceptions[0].DeclaredAt())
	require.Equal(t, 10, exceptions[1].DeclaredAt())
	require.NotEqual(t, cfg.ExceptionKey(exceptions[0]), cfg.ExceptionKey(exceptions[1]))
}

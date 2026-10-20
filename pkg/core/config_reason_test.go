package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An exception says why the finding does not apply there: without a reason
// nobody can tell later whether it still holds.
func TestExceptionWithoutReasonIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".glint.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`version: 1
categories:
  architecture:
    rules:
      python-file:
        enabled: true
        exceptions:
          - files: "ml/**"
            reason: speech recognition model
          - files: "vendor-ref/**"
`), 0o644))

	_, err := LoadConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceptions[1]")
	assert.Contains(t, err.Error(), "reason")
}

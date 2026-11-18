package deadcode

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestReachedFileMatchesFileAndFilesLikeTheRun(t *testing.T) {
	exc := core.Exception{File: "svc/stop.go", Files: "other/*.go"}
	reached, err := reachedFile([]string{"svc/stop.go", "other/stop.go"}, exc, func(string) (bool, error) { return false, nil })
	assert.NoError(t, err)
	assert.True(t, reached)

	reached, err = reachedFile([]string{"svc/other.go", "unrelated/other.go"}, exc, func(string) (bool, error) { return false, nil })
	assert.NoError(t, err)
	assert.False(t, reached)
}

func TestTicketExceptionScopeMatchesFileAndFilesLikeTheRun(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".glint.yaml"), []byte("version: 1\n"), 0o644))
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	ctx := core.NewFileContext(filepath.Join(root, "svc", "stop.go"), root, nil, core.DefaultConfig())
	run := StaleSuppressionRun{Contexts: []*core.FileContext{ctx}, Config: cfg}
	assert.True(t, ticketExceptionInScope(core.Exception{File: "svc/stop.go", Files: "other/*.go"}, run))
}

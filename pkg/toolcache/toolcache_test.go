package toolcache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func useDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := baseDir
	baseDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { baseDir = old })
	return dir
}

func TestStoreThenLoad(t *testing.T) {
	useDir(t)
	cache := New("shellcheck")
	key := Key([]byte("v1"), []byte("echo $x"))
	var got []string
	found, err := cache.Load(key, &got)
	require.NoError(t, err)
	assert.False(t, found)

	require.NoError(t, cache.Store(key, []string{"SC2086"}))
	found, err = cache.Load(key, &got)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, []string{"SC2086"}, got)

	Disabled = true
	t.Cleanup(func() { Disabled = false })
	found, err = cache.Load(key, &got)
	require.NoError(t, err)
	assert.False(t, found, "--no-cache asks the program again")
}

func TestKeySeparatesParts(t *testing.T) {
	assert.NotEqual(t, Key([]byte("ab"), []byte("c")), Key([]byte("a"), []byte("bc")))
}

// An entry unused for a month goes on the next store; a fresh one stays.
func TestStorePrunesOldEntries(t *testing.T) {
	dir := useDir(t)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "tsc"), 0o755))
	old := filepath.Join(dir, "tsc", "old.json")
	require.NoError(t, os.WriteFile(old, []byte("[]"), 0o644))
	month := time.Now().Add(-31 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(old, month, month))

	require.NoError(t, New("tsc").Store(Key([]byte("x")), []int{1}))
	assert.NoFileExists(t, old)
	assert.FileExists(t, filepath.Join(dir, "tsc", Key([]byte("x"))+".json"))
}

func TestDirPrunesOldFiles(t *testing.T) {
	dir := useDir(t)
	cache := New("tsc")
	toolDir := filepath.Join(dir, "tsc")
	require.NoError(t, os.MkdirAll(toolDir, 0o755))
	old := filepath.Join(toolDir, "old.tsbuildinfo")
	require.NoError(t, os.WriteFile(old, []byte("stale"), 0o600))
	month := time.Now().Add(-31 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(old, month, month))

	got, err := cache.Dir()
	require.NoError(t, err)
	assert.Equal(t, toolDir, got)
	assert.NoFileExists(t, old)
}

package sqlschema

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A root read with and without settings.respect_gitignore has two schemas:
// the one cached first does not stand for the other.
func TestLoadCachedKeepsSchemaPerRespectGitignore(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		".gitignore":                "/gen/\n",
		"migrations/001.up.sql":     "CREATE TABLE a (id int);",
		"gen/migrations/002.up.sql": "CREATE TABLE b (id int);",
	} {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	respecting, err := LoadCached(root, nil, true)
	require.NoError(t, err)
	require.Nil(t, respecting.Table("b"))
	all, err := LoadCached(root, nil, false)
	require.NoError(t, err)
	require.NotNil(t, all.Table("b"))
	respectingKey, err := InputsHash(root, nil, true)
	require.NoError(t, err)
	allKey, err := InputsHash(root, nil, false)
	require.NoError(t, err)
	require.NotEqual(t, respectingKey, allKey)
}

func TestInputsHashUsesTheLoadedSchemaBytes(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "migrations")
	require.NoError(t, os.Mkdir(dir, 0o700))
	path := filepath.Join(dir, "001.up.sql")
	require.NoError(t, os.WriteFile(path, []byte("CREATE TABLE a (id int);"), 0o600))
	schema, err := LoadCached(root, nil, true)
	require.NoError(t, err)
	require.NotNil(t, schema.Table("a"))
	_, original, err := load(root, nil, true)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, []byte("CREATE TABLE b (id int);"), 0o600))
	_, changed, err := load(root, nil, true)
	require.NoError(t, err)
	require.NotEqual(t, original, changed)
	key, err := InputsHash(root, nil, true)
	require.NoError(t, err)
	require.Equal(t, original, key, "the key describes the cached schema, not the changed file")
	again, err := LoadCached(root, nil, true)
	require.NoError(t, err)
	require.Same(t, schema, again)
	require.Nil(t, again.Table("b"))
}

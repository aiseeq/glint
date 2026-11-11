package sqlschema

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInputsHashUsesTheLoadedSchemaBytes(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "migrations")
	require.NoError(t, os.Mkdir(dir, 0o700))
	path := filepath.Join(dir, "001.up.sql")
	require.NoError(t, os.WriteFile(path, []byte("CREATE TABLE a (id int);"), 0o600))
	schema, err := LoadCached(root, nil)
	require.NoError(t, err)
	require.NotNil(t, schema.Table("a"))
	_, original, err := load(root, nil)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, []byte("CREATE TABLE b (id int);"), 0o600))
	_, changed, err := load(root, nil)
	require.NoError(t, err)
	require.NotEqual(t, original, changed)
	key, err := InputsHash(root, nil)
	require.NoError(t, err)
	require.Equal(t, original, key, "the key describes the cached schema, not the changed file")
	again, err := LoadCached(root, nil)
	require.NoError(t, err)
	require.Same(t, schema, again)
	require.Nil(t, again.Table("b"))
}

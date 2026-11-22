package cachekey

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goBinary copies the running test binary, a Go executable with a build
// ID, to a temporary file.
func goBinary(t *testing.T) (string, []byte) {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	data, err := os.ReadFile(self)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "glint")
	require.NoError(t, os.WriteFile(path, data, 0o755))
	return path, data
}

func TestAppendedManifestReadsBack(t *testing.T) {
	path, binary := goBinary(t)
	var index Index
	manifest := &Manifest{Driver: "driver", All: "all", DriverFuncs: []int{index.Add("m/cmd/glint/main.go:10")}}
	manifest.Sites = []Site{{File: "m/pkg/rules/check/a.go", From: 12, To: 14, Hash: "a", Funcs: []int{index.Add("m/pkg/rules/check/a.go:20")}}}
	manifest.Funcs = index.Keys()

	require.NoError(t, Append(path, manifest))

	got, err := Read(path)
	require.NoError(t, err)
	assert.Equal(t, manifest.Sites, got.Sites)
	assert.Equal(t, manifest.Driver, got.Driver)
	assert.NotEmpty(t, got.Binary, "the manifest names the build it was appended to")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, binary, data[:len(binary)], "the binary itself is untouched")
	site := got.SiteAt("m/pkg/rules/check/a.go", 13)
	require.NotNil(t, site, "a line inside a multi-line call finds its site")
	assert.Equal(t, []string{"m/pkg/rules/check/a.go:20"}, got.Names(site.Funcs))
	assert.Nil(t, got.SiteAt("m/pkg/rules/check/a.go", 15))
}

func TestBinaryWithoutManifestReportsNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "glint")
	require.NoError(t, os.WriteFile(path, []byte("a plain go build"), 0o755))
	_, err := Read(path)
	assert.ErrorIs(t, err, ErrNone)
}

// A manifest carried over to another build - its trailer copied, or the
// binary rebuilt in place with the old trailer kept - keys nothing: the
// build ID of the binary it was appended to does not match.
func TestManifestOfAnotherBuildIsNotTrusted(t *testing.T) {
	path, binary := goBinary(t)
	id, err := BuildID(path)
	require.NoError(t, err)
	require.NotEmpty(t, id)
	require.NoError(t, Append(path, &Manifest{Driver: "driver", All: "all"}))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	at := bytes.Index(data, []byte(id))
	require.GreaterOrEqual(t, at, 0)
	other := bytes.Clone(data)
	other[at] ^= 1 // another build: its ID differs, the trailer is the same
	require.NoError(t, os.WriteFile(path, other, 0o755))
	_, err = Read(path)
	assert.ErrorIs(t, err, ErrNone)
	assert.Less(t, at, len(binary), "the ID is in the binary, not in the trailer")
}

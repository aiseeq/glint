package shellrules

import (
	"go/build"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A glint built with -trimpath has no GOROOT of its own: the standard
// library must still import, or testing.T is untyped and every subtest body
// of a test-only package goes unchecked.
func TestSignalStdImporterWithoutBuildGOROOT(t *testing.T) {
	saved := build.Default.GOROOT
	build.Default.GOROOT = ""
	t.Cleanup(func() { build.Default.GOROOT = saved })
	pkg, err := newSignalStdImporter().Import("testing")
	require.NoError(t, err)
	require.NotNil(t, pkg.Scope().Lookup("T"))
}

// glint runs in the project it checks: a go.mod there that the go command
// rejects must not cost the standard library its types.
func TestSignalStdImporterInBrokenModule(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/broken\n\nrequire (\n"), 0o600))
	t.Chdir(dir)
	saved := build.Default.GOROOT
	build.Default.GOROOT = ""
	t.Cleanup(func() { build.Default.GOROOT = saved })
	pkg, err := newSignalStdImporter().Import("testing")
	require.NoError(t, err)
	require.NotNil(t, pkg.Scope().Lookup("T"))
}

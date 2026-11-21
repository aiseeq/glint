package shellrules

import (
	"bytes"
	"go/build"
	"os"
	"path/filepath"
	"strings"
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

// When neither the build nor the go command names GOROOT, the standard
// library cannot import and kill and signal calls lose their types: the run
// must say so once instead of degrading signal-implicit-target silently.
func TestSignalStdImporterWarnsOnceWhenGOROOTIsUnknown(t *testing.T) {
	saved := build.Default.GOROOT
	build.Default.GOROOT = ""
	t.Cleanup(func() { build.Default.GOROOT = saved })
	t.Setenv("PATH", t.TempDir())
	var out bytes.Buffer
	savedOutput := signalWarningOutput
	signalWarningOutput = &out
	t.Cleanup(func() { signalWarningOutput = savedOutput })

	// signalImporter turns the failure into an empty package, so the warning
	// is all the run shows; the shared cache holds only imports that worked.
	std := newSignalStdImporter()
	for _, path := range []string{"os", "syscall"} {
		_, err := std.Import(path)
		require.Error(t, err)
	}
	require.Equal(t, 1, strings.Count(out.String(), "warning: signal-implicit-target"), out.String())
	require.Contains(t, out.String(), "go env GOROOT")
}

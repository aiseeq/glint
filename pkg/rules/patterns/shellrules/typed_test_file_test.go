package shellrules

import (
	"go/build"
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

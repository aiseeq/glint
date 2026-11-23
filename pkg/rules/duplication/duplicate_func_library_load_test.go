package duplication

import (
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A library is listed with -trimpath, as the project is: a second copy of the
// sources reuses the Go build cache entries of the first.
func TestLibraryLoadConfigTrimsPaths(t *testing.T) {
	fset := token.NewFileSet()
	cfg := libraryLoadConfig("/src/lib", fset)
	assert.Equal(t, []string{"-trimpath"}, cfg.BuildFlags)
	assert.Equal(t, "/src/lib", cfg.Dir)
	assert.Same(t, fset, cfg.Fset)
}

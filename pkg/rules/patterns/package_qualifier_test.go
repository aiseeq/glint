package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// parseBothWays returns the file parsed as the walker parses it and as the
// project load does: the load leaves identifiers unresolved, and a rule must
// tell a package from a local name the same way in both.
func parseBothWays(t *testing.T, path, code string) map[string]*core.FileContext {
	t.Helper()
	walker := core.NewFileContext(path, "/src", []byte(code), core.DefaultConfig())
	fset, file, err := core.NewParser().ParseGoFile(path, []byte(code))
	require.NoError(t, err)
	walker.SetGoAST(fset, file)

	loader := core.NewFileContext(path, "/src", []byte(code), core.DefaultConfig())
	require.NoError(t, core.ParseGoFiles("/src", []*core.FileContext{loader}, false))
	return map[string]*core.FileContext{"walker": walker, "loader": loader}
}

// A parameter named after an imported logging package is not that package.
func TestNonCanonicalLoggerTellsShadowingParameterFromPackage(t *testing.T) {
	code := `package app

import "log"

type Logger interface{ Printf(format string, args ...any) }

func Boot() { log.Printf("boot") }

func Serve(log Logger) { log.Printf("started") }
`
	for mode, ctx := range parseBothWays(t, "/src/app/app.go", code) {
		violations := NewNonCanonicalLoggerRule().AnalyzeFile(ctx)
		require.Len(t, violations, 1, "%s-parsed file", mode)
		assert.Equal(t, 7, violations[0].Line, "%s-parsed file: only the package call", mode)
	}
}

// Without type information only a call qualified by an imported package counts
// as foreign; a parameter named like the package is the project's own code.
func TestErrorWrapUntypedTellsShadowingParameterFromPackage(t *testing.T) {
	code := `package svc

import "os"

type opener interface{ Open(name string) (*os.File, error) }

func Read() error {
	_, err := os.Open("a")
	if err != nil {
		return err
	}
	return nil
}

func ReadWith(os opener) error {
	_, err := os.Open("b")
	if err != nil {
		return err
	}
	return nil
}
`
	for mode, ctx := range parseBothWays(t, "/src/svc.go", code) {
		violations := NewErrorWrapRule().AnalyzeFile(ctx)
		require.Len(t, violations, 1, "%s-parsed file", mode)
		assert.Equal(t, 10, violations[0].Line, "%s-parsed file: only the os package call", mode)
	}
}

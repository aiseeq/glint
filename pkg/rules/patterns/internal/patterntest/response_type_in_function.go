package patterntest

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/require"
)

// CreatePatternContext собирает FileContext с разобранным Go-AST.
func CreatePatternContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   strings.Split(code, "\n"),
		Content: []byte(code),
	}

	if strings.HasSuffix(path, ".go") {
		parser := core.NewParser()
		fset, file, err := parser.ParseGoFile(path, []byte(code))
		require.NoError(t, err, "разбор Go-кода")
		ctx.SetGoAST(fset, file)
	}

	return ctx
}

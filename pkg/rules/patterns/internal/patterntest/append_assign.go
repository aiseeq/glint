package patterntest

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

// Helper function
func CreateAppendContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitAppendLines(code),
		Content: []byte(code),
	}

	if len(path) > 3 && path[len(path)-3:] == ".go" {
		parser := core.NewParser()
		fset, ast, err := parser.ParseGoFile(path, []byte(code))
		if err != nil {
			t.Fatalf("Failed to parse Go code: %v", err)
		}
		ctx.SetGoAST(fset, ast)
	}

	return ctx
}

func splitAppendLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

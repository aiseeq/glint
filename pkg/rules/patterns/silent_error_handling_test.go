package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/require"
)

func TestSilentErrorHandlingRule_UserVisibleErrorStruct(t *testing.T) {
	code := `package main

type Result struct {
	Error string
}

func parse() (*Result, error) { return nil, nil }

func example() (*Result, *Result) {
	_, err := parse()
	if err != nil {
		return nil, &Result{Error: "failed to parse"}
	}
	return nil, nil
}
`

	ctx := createSilentErrorContext(t, "service.go", code)
	violations := NewSilentErrorHandlingRule().AnalyzeFile(ctx)
	require.Empty(t, violations)
}

func createSilentErrorContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitTimeEqualLines(code),
		Content: []byte(code),
	}
	parser := core.NewParser()
	fset, file, err := parser.ParseGoFile(path, []byte(code))
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)
	return ctx
}

package patterns

import (
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// sharedFileSetContext parses a file into a file set that already holds
// another file, exactly like the Go project loader does. Positions are then
// offset by the earlier file's size — hand-rolled newline counting over
// ctx.Content silently collapses to line 1.
func sharedFileSetContext(t *testing.T, name, code string) *core.FileContext {
	t.Helper()
	fset := token.NewFileSet()
	filler := "package filler\n\n" + "// padding\n"
	if _, err := parser.ParseFile(fset, "filler.go", filler, parser.ParseComments); err != nil {
		t.Fatalf("parse filler: %v", err)
	}

	astFile, err := parser.ParseFile(fset, name, code, parser.ParseComments)
	require.NoError(t, err)

	ctx := core.NewFileContext(name, ".", []byte(code), nil)
	ctx.SetGoAST(fset, astFile)
	return ctx
}

const queryInLoopSource = `package svc

import "context"

type Service struct {
	repo Repo
}

func (s *Service) Sync(ctx context.Context, ids []string) error {
	for _, id := range ids {
		item, err := s.repo.FindByID(ctx, id)
		if err != nil {
			return err
		}
		if err := s.repo.UpdateStatus(ctx, item); err != nil {
			return err
		}
	}
	return nil
}
`

func TestQueryInLoopReportsRealLinesWithSharedFileSet(t *testing.T) {
	ctx := sharedFileSetContext(t, "service.go", queryInLoopSource)

	violations := NewQueryInLoopRule().AnalyzeFile(ctx)
	require.Len(t, violations, 2, "both data-access calls in the loop must be reported")

	lines := []int{violations[0].Line, violations[1].Line}
	assert.Equal(t, []int{11, 15}, lines, "findings must point at the calls, not at line 1")
	for _, v := range violations {
		assert.NotEqual(t, 1, v.Line, "line 1 means the position was lost")
		assert.NotEmpty(t, v.Code, "the offending source line must be attached")
	}
}

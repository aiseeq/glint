package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// queryInLoopProject loads the source behind a filler file of the same
// package, so the service file does not start at the beginning of the shared
// file set - hand-rolled newline counting over ctx.Content would collapse to
// line 1.
func queryInLoopProject(t *testing.T) *core.GoProjectContext {
	t.Helper()
	return rulestest.Project(t, map[string]string{
		"svc/a_filler.go": `package svc

import "context"

// Repo is the storage the service reads through.
type Repo interface {
	FindByID(ctx context.Context, id string) (string, error)
	UpdateStatus(ctx context.Context, item string) error
}
`,
		"svc/service.go": queryInLoopSource,
	})
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
	violations, err := NewQueryInLoopRule().AnalyzeGoProject(queryInLoopProject(t))
	require.NoError(t, err)
	require.Len(t, violations, 2, "both data-access calls in the loop must be reported")

	lines := []int{violations[0].Line, violations[1].Line}
	assert.Equal(t, []int{11, 15}, lines, "findings must point at the calls, not at line 1")
	for _, v := range violations {
		assert.NotEqual(t, 1, v.Line, "line 1 means the position was lost")
		assert.NotEmpty(t, v.Code, "the offending source line must be attached")
	}
}

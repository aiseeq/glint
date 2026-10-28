package httprules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
)

// A page that says more exists but carries no cursor ends the walk as if
// the history were complete.
func TestPaginationBoundaryTruncationRule_MissingCursorEndsWalk(t *testing.T) {
	code := `package sync

func backfill(ctx context.Context, c *Client) error {
	var cursor *string
	for {
		result, err := c.Page(ctx, cursor)
		if err != nil {
			return err
		}
		if !result.HasNextPage || result.NextCursor == "" {
			markComplete()
			break
		}
		next := result.NextCursor
		cursor = &next
	}
	return nil
}

func walkStrict(ctx context.Context, c *Client) error {
	var cursor *string
	for {
		result, err := c.Page(ctx, cursor)
		if err != nil {
			return err
		}
		if !result.HasNextPage {
			break
		}
		if result.NextCursor == "" {
			return errors.New("page without a cursor")
		}
		next := result.NextCursor
		cursor = &next
	}
	return nil
}
`
	ctx := patterntest.CreateQueryContext(t, "sync.go", code)
	assert.Equal(t, []int{10}, patterntest.ViolationLines(NewPaginationBoundaryTruncationRule().AnalyzeFile(ctx)))
}

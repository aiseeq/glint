package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A nil check guards only the code it dominates: a dereference after an if
// whose branch merely tests the field, and falls through either way, runs on
// the path where the field is nil.
func TestFieldNilCheckInconsistentCheckOnOtherPath(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"router.go": `package example

import ("context"; "log/slog")

type PortfolioHandler struct{}
type Position struct{}
type Report struct{}
func (*PortfolioHandler) Positions(context.Context) ([]Position, error) { return nil, nil }
func (*PortfolioHandler) Valuation(context.Context) (*Report, error) { return nil, nil }

type Router struct { portfolio *PortfolioHandler }
func (r *Router) positions(ctx context.Context) ([]Position, error) {
	if r.portfolio == nil { slog.Warn("portfolio unavailable"); return nil, nil }
	return r.portfolio.Positions(ctx)
}
func (r *Router) report(ctx context.Context) *Report {
	if r.portfolio != nil { slog.Info("portfolio set") }
	v, _ := r.portfolio.Valuation(ctx)
	return v
}
func (r *Router) inside(ctx context.Context) *Report {
	if r.portfolio != nil {
		v, _ := r.portfolio.Valuation(ctx)
		return v
	}
	return nil
}
func (r *Router) after(ctx context.Context) *Report {
	if r.portfolio == nil { return nil }
	v, _ := r.portfolio.Valuation(ctx)
	return v
}
func (r *Router) afterElse(ctx context.Context) *Report {
	if r.portfolio == nil {
		return nil
	} else {
		slog.Info("portfolio set")
	}
	v, _ := r.portfolio.Valuation(ctx)
	return v
}
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"router.go:18"}, patterntest.FoundLines(violations))
}

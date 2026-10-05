package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A helper without a context parameter that opens context.Background, called
// only from handlers that hold the request: a client gone or a deadline hit
// never reaches the storage read. A helper also called from a function
// without a context keeps its own context.
func TestContextBackgroundHelperCalledOnlyWithLiveContext(t *testing.T) {
	project := decisionProject(t, map[string]string{"rates/rates.go": `package rates

import (
	"context"
	"net/http"
)

type Store interface {
	Rate(ctx context.Context, pair string) (float64, error)
}

type Admin struct{ store Store }

func (a *Admin) marketRate(pair string) (float64, error) {
	return a.store.Rate(context.Background(), pair)
}

func (a *Admin) cachedRate(pair string) (float64, error) {
	return a.store.Rate(context.Background(), pair)
}

func (a *Admin) handleQuote(w http.ResponseWriter, r *http.Request) {
	_, _ = a.marketRate("A/B")
	_, _ = a.cachedRate("A/B")
}

func (a *Admin) quote(ctx context.Context) {
	_, _ = a.marketRate("A/B")
}

func (a *Admin) warm() {
	_, _ = a.cachedRate("A/B")
}

func (a *Admin) history(_ context.Context, pair string) (float64, error) {
	return a.store.Rate(context.Background(), pair)
}

func (a *Admin) refill() {
	_, _ = a.store.Rate(context.Background(), "A/B")
}

func (a *Admin) handleHistory(w http.ResponseWriter, r *http.Request) {
	_, _ = a.history(r.Context(), "A/B")
	go a.refill()
}
`})
	violations, err := NewContextBackgroundRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	var lines []int
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{15}, lines)
}

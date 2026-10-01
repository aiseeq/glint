package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A nil check that comes after the value was already read through the
// pointer guards nothing: a nil order panics on the log line above it.
func TestNilCheckAfterDereference(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"orders/handler.go": `package orders

import "fmt"

type Order struct {
	ID     string
	Amount string
}

type Logger interface{ Info(string) }

type Handler struct{ log Logger }

func (h *Handler) Process(order *Order) {
	if h.log != nil {
		h.log.Info(fmt.Sprintf("processing %s for %s", order.ID, order.Amount))
	}
	if order == nil {
		return
	}
	h.log.Info(order.ID)
}

func (h *Handler) Guarded(order *Order) {
	if order != nil {
		h.log.Info(order.ID)
	}
	if order == nil {
		return
	}
}

func (h *Handler) ShortCircuit(order *Order) {
	ok := order != nil && order.ID != ""
	if order == nil || !ok {
		return
	}
}

func (h *Handler) Reassigned(order *Order, next func() *Order) {
	h.log.Info(order.ID)
	order = next()
	if order == nil {
		return
	}
}

func (h *Handler) Deferred(order *Order) {
	report := func() { h.log.Info(order.ID) }
	if order == nil {
		return
	}
	report()
}

func (h *Handler) Value(order Order, list *[]Order) {
	h.log.Info(order.ID)
	if list == nil {
		return
	}
}

func (h *Handler) FetchedInBranch(name string, fetch func() *Order) string {
	var order *Order
	if name == "" {
		order = fetch()
		name = order.ID
	}
	if order == nil {
		order = fetch()
	}
	return name + order.Amount
}

func (h *Handler) Latest(all []Order) *Order {
	var latest *Order
	for i := range all {
		if latest == nil || all[i].ID > latest.ID {
			latest = &all[i]
		}
	}
	if latest == nil {
		return nil
	}
	return latest
}

func (h *Handler) Star(count *int) int {
	total := *count + 1
	if count == nil {
		return 0
	}
	return total
}
`,
	}
	violations, err := NewNilCheckAfterDereferenceRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"orders/handler.go:18", "orders/handler.go:90"}, foundLines(violations))
}

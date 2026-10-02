package patterns

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func typedRuleFindings(t *testing.T, rule interface {
	AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
}, files map[string]string) []string {
	t.Helper()
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

const accessScopeService = `package board

import (
	"context"
	"time"
)

type StaffAccess struct{ Types map[string]bool }

type Event struct{ Type string }

type Service struct{ events []Event }

// The list and its refresh are filtered by what the viewer may see.
func (s *Service) ListFor(ctx context.Context, access StaffAccess) []Event       { return s.visible(access) }
func (s *Service) RefreshFor(ctx context.Context, access StaffAccess) []Event    { return s.visible(access) }
func (s *Service) Acknowledge(ctx context.Context, key string, access StaffAccess) error { return nil }

// List has a filtered twin, ListFor: the poller uses the unfiltered one.
func (s *Service) List(ctx context.Context) []Event { return s.events }

// GetHistory is the only reader of the section with no filter.
func (s *Service) GetHistory(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	return s.events, nil
}

// Count answers a number, not records.
func (s *Service) GetOpenCount(ctx context.Context) int { return len(s.events) }

func (s *Service) visible(access StaffAccess) []Event {
	var out []Event
	for _, e := range s.events {
		if access.Types[e.Type] {
			out = append(out, e)
		}
	}
	return out
}
`

// A reader the handler serves with no access argument, while its siblings
// filter by the viewer's access, shows what the rest of the section hides.
func TestReadMethodSkipsAccessFilter(t *testing.T) {
	assert.Equal(t, []string{"board/board.go:23"}, typedRuleFindings(t, NewReadMethodSkipsAccessFilterRule(), map[string]string{
		"board/board.go": accessScopeService,
		"api/api.go": `package api

import (
	"net/http"
	"time"

	"example.com/rulestest/board"
)

type Router struct{ board *board.Service }

func (r *Router) list(w http.ResponseWriter, req *http.Request) {
	_ = r.board.ListFor(req.Context(), board.StaffAccess{})
}

func (r *Router) history(w http.ResponseWriter, req *http.Request) {
	_, _ = r.board.GetHistory(req.Context(), time.Time{}, 50)
	_ = r.board.GetOpenCount(req.Context())
}
`,
		"poll/poll.go": `package poll

import (
	"context"

	"example.com/rulestest/board"
)

func Tick(ctx context.Context, s *board.Service) { _ = s.List(ctx) }
`,
	}))
}

// A report scoped to one portfolio carries a list read from a process-wide
// source that is not handed the portfolio: every portfolio shows the alerts
// of all of them.
func TestScopedResultIncludesGlobalList(t *testing.T) {
	assert.Equal(t, []string{"risk/risk.go:33"}, typedRuleFindings(t, NewScopedResultIncludesGlobalListRule(), map[string]string{
		"risk/risk.go": `package risk

import "context"

type Alert struct {
	PositionID string
	Level      string
}

type Chain struct{ Name string }

type Monitor struct{ last []Alert }

func (m *Monitor) LastAlerts() ([]Alert, bool) { return m.last, true }
func (m *Monitor) AlertsOf(portfolioID string) []Alert { return nil }
func (m *Monitor) Chains() []Chain                  { return nil }

type Report struct {
	PortfolioID string
	Alerts      []Alert
	Mine        []Alert
	Chains      []Chain
	Exposure    []Alert
}

type Service struct{ monitor *Monitor }

func (s *Service) exposure(ctx context.Context, portfolioID string) []Alert { return nil }

func (s *Service) Report(ctx context.Context, portfolioID string) *Report {
	var alerts []Alert
	if s.monitor != nil {
		last, _ := s.monitor.LastAlerts()
		alerts = last
	}
	return &Report{
		PortfolioID: portfolioID,
		Alerts:      alerts,
		Mine:        s.monitor.AlertsOf(portfolioID),
		Chains:      s.monitor.Chains(),
		Exposure:    s.exposure(ctx, portfolioID),
	}
}
`,
	}))
}

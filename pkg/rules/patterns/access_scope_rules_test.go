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

// The viewer's scope (the tenant ids of the signed-in user) is handed to some
// readers of the handlers' package; a handler that calls another reader with
// neither the scope nor a check of what it returns serves every tenant's
// records to every viewer.
func TestReadMethodSkipsAccessFilterHandlerScope(t *testing.T) {
	assert.Equal(t, []string{"web/batches.go:13", "web/batches.go:28", "web/hooks.go:11", "web/hooks.go:12"}, typedRuleFindings(t, NewReadMethodSkipsAccessFilterRule(), map[string]string{
		"store/store.go": `package store

import "context"

type Order struct {
	ID       int
	TenantID int
}

type Batch struct {
	ID, Input string
	TenantID  int
}

type Hook struct{ ID, OrderID int }

type Tenant struct{ ID int }

type User struct{ Name string }

type Orders struct{}

func (Orders) ListRecent(ctx context.Context, limit int, tenantIDs []int) ([]Order, error) { return nil, nil }
func (Orders) GetByID(ctx context.Context, id int) (*Order, error)                         { return nil, nil }

type Batches struct{}

func (Batches) Get(ctx context.Context, id string) (*Batch, error) { return nil, nil }

type Hooks struct{}

func (Hooks) ListHooks(ctx context.Context, limit int) ([]Hook, error) { return nil, nil }

type Tenants struct{}

func (Tenants) GetAll(ctx context.Context) ([]Tenant, error) { return nil, nil }

type Currency struct{ Code string }

func (Tenants) ListCurrencies(ctx context.Context) ([]Currency, error) { return nil, nil }

type Users struct{}

func (Users) TenantIDsFor(ctx context.Context, name string) ([]int, error) { return nil, nil }
`,
		"web/web.go": `package web

import (
	"context"
	"net/http"

	"example.com/rulestest/store"
)

type Viewer struct {
	Name      string
	TenantIDs []int // nil = every tenant
}

type Admin struct {
	orders  store.Orders
	batches store.Batches
	hooks   store.Hooks
	tenants store.Tenants
	users   store.Users
}

func viewerOf(r *http.Request) *Viewer { return &Viewer{} }

func allowed(v *Viewer, tenantID int) bool {
	if v.TenantIDs == nil {
		return true
	}
	for _, id := range v.TenantIDs {
		if id == tenantID {
			return true
		}
	}
	return false
}

func (a *Admin) checkOrder(v *Viewer, o *store.Order) bool { return allowed(v, o.TenantID) }

func (a *Admin) load(ctx context.Context, v *Viewer) {
	ids, _ := a.users.TenantIDsFor(ctx, v.Name)
	v.TenantIDs = ids
}

func (a *Admin) dashboard(w http.ResponseWriter, r *http.Request) {
	v := viewerOf(r)
	ids := v.TenantIDs
	_, _ = a.orders.ListRecent(r.Context(), 20, ids)
}

func (a *Admin) order(w http.ResponseWriter, r *http.Request) {
	v := viewerOf(r)
	o, err := a.orders.GetByID(r.Context(), 1)
	if err != nil || !a.checkOrder(v, o) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

func (a *Admin) tenantList(w http.ResponseWriter, r *http.Request) {
	v := viewerOf(r)
	all, _ := a.tenants.GetAll(r.Context())
	for _, t := range all {
		if allowed(v, t.ID) {
			_ = t
		}
	}
}
`,
		"web/batches.go": `package web

import (
	"net/http"

	"example.com/rulestest/store"
)

var _ store.Batch

func (a *Admin) batch(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	b, err := a.batches.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "missing", http.StatusNotFound)
		return
	}
	_, _ = w.Write([]byte(b.Input))
}

func (a *Admin) confirm(w http.ResponseWriter, r *http.Request) {
	v := viewerOf(r)
	_, _ = a.orders.ListRecent(r.Context(), 5, v.TenantIDs)
	_ = a.process(w, r)
}

func (a *Admin) process(w http.ResponseWriter, r *http.Request) error {
	o, err := a.orders.GetByID(r.Context(), 7)
	if err != nil {
		return err
	}
	_ = o.ID
	return nil
}
`,
		"web/hooks.go": `package web

import "net/http"

type hookPage struct{ Rows, Tenants, Currencies int }

// A hook belongs to a tenant through its order, and the tenant list itself is
// read unfiltered. Currencies belong to no tenant: a reference list.
func (a *Admin) hooksPage(w http.ResponseWriter, r *http.Request) {
	page := hookPage{}
	rows, _ := a.hooks.ListHooks(r.Context(), 50)
	tenants, _ := a.tenants.GetAll(r.Context())
	currencies, _ := a.tenants.ListCurrencies(r.Context())
	page.Rows, page.Tenants, page.Currencies = len(rows), len(tenants), len(currencies)
}
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

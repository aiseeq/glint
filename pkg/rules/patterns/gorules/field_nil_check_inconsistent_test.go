package gorules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldNilCheckInconsistent(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"router.go": `package example

import ("context"; "log/slog")

type Service struct{}
type PortfolioHandler struct{}
type Position struct{}
type Report struct{}
func (*PortfolioHandler) Positions(context.Context) ([]Position, error) { return nil, nil }
func (*PortfolioHandler) Valuation(context.Context) (*Report, error) { return nil, nil }

type Router struct { service *Service; portfolio *PortfolioHandler }
func (r *Router) positions(ctx context.Context) ([]Position, error) {
	if r.portfolio == nil { slog.Warn("portfolio unavailable"); return nil, nil }
	return r.portfolio.Positions(ctx)
}
func (r *Router) report(ctx context.Context) (*Report, error) {
	return r.portfolio.Valuation(ctx)
}
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "router.go:18", patterntest.FoundLines(violations)[0])
	assert.Contains(t, violations[0].Message, "positions")
	assert.Contains(t, violations[0].Message, "router.go:13")
}

func TestFieldNilCheckInconsistentNegatives(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"router.go": `package example

type Service struct{}
func (*Service) Run() {}
type Optional struct{}
func (*Optional) Run() {}
type NoopGuard struct { dep *Optional }
func (n *NoopGuard) available() { if n.dep == nil { return } }
func (n *NoopGuard) use() { n.dep.Run() }
type NilErrorGuard struct { dep *Optional }
func (n *NilErrorGuard) available() error { if n.dep == nil { return nil }; return nil }
func (n *NilErrorGuard) use() { n.dep.Run() }
type Lazy struct { dep *Optional }
func (l *Lazy) ensure() { if l.dep != nil { return }; l.dep = &Optional{} }
func (l *Lazy) use() { l.dep.Run() }
type Etalon struct{ value int }
type Progress struct { etalon *Etalon }
func (p *Progress) Set(e *Etalon) { if p.etalon == nil { p.etalon = e } }
func (p *Progress) Value() int { return p.etalon.value }
type Router struct { service *Service; items map[string]*Service; callback func() }
func (r *Router) checked() { if r.service == nil { return }; r.service.Run() }
func (r *Router) guarded() { if r.service != nil { r.service.Run() } }
func (r *Router) mapRead(key string) { _ = r.items[key] }
func (r *Router) callbackCall() { r.callback() }
func (r *Router) Close() { if r.items == nil { return }; _ = r.items }
func (r *Router) cleanup() { defer func() { if r.service == nil { return }; r.service.Run() }() }
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestFieldNilCheckInconsistentGuardWithError(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"repo.go": `package example

import ("context"; "errors")
type DB struct{}
func (*DB) QueryRowContext(context.Context, string) int { return 0 }
type Repo struct { db *DB }
func (r *Repo) List(context.Context) ([]int, error) {
	if r.db == nil { return nil, errors.New("repository DB is not initialized") }
	return nil, nil
}
func (r *Repo) Ready(ctx context.Context) (int, error) {
	if r.db != nil { return r.db.QueryRowContext(ctx, "query"), nil }
	return 0, errors.New("repository DB is not initialized")
}
func (r *Repo) Latest(ctx context.Context) (int, error) { return r.db.QueryRowContext(ctx, "query"), nil }
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestFieldNilCheckInconsistentGuardMethod(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"service.go": `package example

import "errors"
type Config struct{}
type Sessions struct{}
func (*Sessions) Refresh(*Config) error { return nil }
type Svc struct { sessions *Sessions; cfg *Config }
func (s *Svc) optionalCheck() { if s.sessions == nil { return } }
func (s *Svc) tokenConfig() (*Config, error) {
	if s.sessions == nil { return nil, errors.New("sessions not initialized") }
	return s.cfg, nil
}
func (s *Svc) Refresh() error {
	cfg, err := s.tokenConfig()
	if err != nil { return err }
	return s.sessions.Refresh(cfg)
}
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestFieldNilCheckInconsistentRefusalWithoutError(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"handlers.go": `package example

import "net/http"

type Logger struct{}
func (*Logger) Error(string) {}
type Order struct{}
func (*Order) ID() string { return "" }
type Handler struct { logger *Logger }
func sendError(http.ResponseWriter, *http.Request, int, string) {}
func (h *Handler) userID(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.logger == nil {
		sendError(w, r, http.StatusInternalServerError, "handler is not initialized")
		return "", false
	}
	return "user", true
}
func (h *Handler) errorLog(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil { h.logger.Error("handler is not initialized"); return }
}
func (h *Handler) useLogger() { h.logger.Error("request") }

type Admin struct { orders *Order }
func (a *Admin) fail(http.ResponseWriter, *http.Request, string, error) {}
func (a *Admin) orderDetail(w http.ResponseWriter, r *http.Request) (*Order, bool) {
	if a.orders == nil {
		a.fail(w, r, "orders: repository not configured", errNotConfigured)
		return nil, false
	}
	return a.orders, true
}
func (a *Admin) useOrder() string { return a.orders.ID() }

var errNotConfigured = errorString("not configured")
type errorString string
func (e errorString) Error() string { return string(e) }
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestFieldNilCheckInconsistentSoftGuardIsNotGuard(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"router.go": `package example

import "context"
type Vault struct{}
type Position struct{}
type Report struct{}
func (*Vault) Positions(context.Context) ([]Position, []string, error) { return nil, nil, nil }
func (*Vault) Valuation(context.Context) (*Report, error) { return nil, nil }
type Router struct { vault *Vault }
func (r *Router) positions(ctx context.Context) ([]Position, []string, error) {
	if r.vault == nil { return nil, []string{"no vault"}, nil }
	rows, _, err := r.vault.Positions(ctx)
	return rows, nil, err
}
func (r *Router) build(ctx context.Context) (*Report, error) {
	_, _, err := r.positions(ctx)
	if err != nil { return nil, err }
	return r.vault.Valuation(ctx)
}
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "router.go:18", patterntest.FoundLines(violations)[0])
	assert.Contains(t, violations[0].Message, "positions")
}

func TestFieldNilCheckInconsistentMostlyRequired(t *testing.T) {
	tests := []struct {
		name  string
		users int
		want  int
	}{
		{name: "five unguarded methods", users: 5, want: 0},
		{name: "two unguarded methods", users: 2, want: 2},
		{name: "three unguarded methods", users: 3, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString(`package example

import "log/slog"
type Dependency struct{}
func (*Dependency) Value() int { return 1 }
type Service struct { dep *Dependency }
func (s *Service) optional() {
	if s.dep == nil { slog.Warn("dependency unavailable"); return }
}
`)
			for i := 0; i < tt.users; i++ {
				fmt.Fprintf(&source, "func (s *Service) use%d() int { return s.dep.Value() }\n", i)
			}
			files := map[string]string{
				"go.mod":     "module example.com/rulestest\n\ngo 1.24\n",
				"service.go": source.String(),
			}
			violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
			require.NoError(t, err)
			assert.Len(t, violations, tt.want)
		})
	}
}

func TestFieldNilCheckInconsistentSetupManagedState(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"analyzer.go": `package example

type Plan struct{}
func (*Plan) Run() {}
type Analyzer struct { plan *Plan }
func (a *Analyzer) CheckTools() error { a.plan = &Plan{}; return nil }
func (a *Analyzer) AnalyzeFile() { if a.plan == nil { return } }
func (a *Analyzer) check() { a.plan.Run() }
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestFieldNilCheckInconsistentMapWriteAcrossFiles(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"router.go": `package example

import "log/slog"
type Service struct{}
type Router struct { items map[string]*Service }
func (r *Router) configured() { if r.items == nil { slog.Warn("items unavailable"); return } }
`,
		"writer.go": `package example

func (r *Router) put(key string, value *Service) { r.items[key] = value }
`,
	}
	violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "writer.go:3", patterntest.FoundLines(violations)[0])
	assert.Contains(t, violations[0].Message, "configured")
}

func TestFieldNilCheckInconsistentCallerProtection(t *testing.T) {
	t.Run("protected chain", func(t *testing.T) {
		files := map[string]string{
			"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
			"service.go": `package example

import "log/slog"
type Dependency struct{}
func (*Dependency) Run() {}
type Service struct { dep *Dependency }
func (s *Service) request() {
	if s.dep == nil { slog.Warn("dependency unavailable"); return }
	s.first()
}
func (s *Service) first() { s.second() }
func (s *Service) second() { s.dep.Run() }
`,
		}
		violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
		require.NoError(t, err)
		assert.Empty(t, violations)
	})

	t.Run("unprotected caller", func(t *testing.T) {
		files := map[string]string{
			"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
			"service.go": `package example

import "log/slog"
type Dependency struct{}
func (*Dependency) Run() {}
type Service struct { dep *Dependency }
func (s *Service) request() {
	if s.dep == nil { slog.Warn("dependency unavailable"); return }
	s.first()
}
func (s *Service) first() { s.second() }
func (s *Service) second() { s.dep.Run() }
func (s *Service) unsafe() { s.first() }
`,
		}
		violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
		require.NoError(t, err)
		require.Len(t, violations, 1)
		assert.Equal(t, "service.go:12", patterntest.FoundLines(violations)[0])
	})

	t.Run("exported helper", func(t *testing.T) {
		files := map[string]string{
			"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
			"service.go": `package example

import "log/slog"
type Dependency struct{}
func (*Dependency) Run() {}
type Service struct { dep *Dependency }
func (s *Service) request() {
	if s.dep == nil { slog.Warn("dependency unavailable"); return }
	s.Use()
}
func (s *Service) Use() { s.dep.Run() }
`,
		}
		violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
		require.NoError(t, err)
		require.Len(t, violations, 1)
		assert.Equal(t, "service.go:11", patterntest.FoundLines(violations)[0])
	})
}

func TestFieldNilCheckInconsistentNegatedGuardMethod(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		want int
	}{
		{
			name: "early exit protects the field",
			body: "if !p.IsSet() { return 0 }; return p.etalon.Steps",
			want: 0,
		},
		{
			name: "guard without early exit does not protect",
			body: "if !p.IsSet() { }; return p.etalon.Steps",
			want: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
				"progress.go": `package example

import "log/slog"
type Etalon struct { Steps int }
type Progress struct { etalon *Etalon }
func (p *Progress) Optional() { if p.etalon == nil { slog.Warn("etalon unavailable"); return } }
func (p *Progress) IsSet() bool { return p != nil && p.etalon != nil }
func (p *Progress) LastN(name string) int { BODY }
`,
			}
			files["progress.go"] = strings.Replace(files["progress.go"], "BODY", tt.body, 1)
			violations, err := NewFieldNilCheckInconsistentRule().AnalyzeGoProject(rulestest.Project(t, files))
			require.NoError(t, err)
			assert.Len(t, violations, tt.want)
			if tt.want > 0 {
				assert.Contains(t, violations[0].Message, "Progress.etalon")
			}
		})
	}
}

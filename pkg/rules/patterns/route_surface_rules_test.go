package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// routerSource is a chi-like router: groups and routes take func literals.
const routerSource = `package router

import "net/http"

type Router interface {
	Use(mw ...func(http.Handler) http.Handler)
	Group(fn func(r Router))
	Route(pattern string, fn func(r Router))
	Get(pattern string, h http.HandlerFunc)
	Post(pattern string, h http.HandlerFunc)
}
`

// Routes registered outside the limited groups of a router that limits
// some: a readiness probe pinging the database and a webhook checked by a
// shared secret take any number of requests.
func TestUnauthenticatedRouteOutsideRateLimit(t *testing.T) {
	assert.Equal(t, []string{"api/server.go:26", "api/server.go:27"}, typedFuncFindings(t, NewUnauthenticatedRouteOutsideRateLimitRule(), map[string]string{
		"router/router.go": routerSource,
		"api/server.go": `package api

import (
	"crypto/subtle"
	"database/sql"
	"net/http"

	"example.com/rulestest/router"
)

type limiter struct{}

func (l *limiter) middleware() func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler { return h }
}

func auth(next http.Handler) http.Handler { return next }

type Server struct {
	db     *sql.DB
	secret string
}

func (s *Server) routes(r router.Router, rateLimiter *limiter) {
	r.Get("/health", s.health)
	r.Get("/ready", s.ready)
	r.Post("/hooks/provider", s.hook)
	r.Route("/api", func(r router.Router) {
		r.Use(rateLimiter.middleware())
		r.Use(auth)
		r.Get("/items", s.items)
	})
	r.Group(func(r router.Router) {
		r.Use(auth)
		r.Get("/account", s.items)
	})
}

// internal registers on a router that limits nothing: no limited group to
// compare with.
func (s *Server) internal(r router.Router) {
	r.Get("/ready", s.ready)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.db.PingContext(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

func (s *Server) hook(w http.ResponseWriter, r *http.Request) {
	if !equal(r.Header.Get("X-Secret"), s.secret) {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (s *Server) items(w http.ResponseWriter, r *http.Request) {
	_, _ = s.db.QueryContext(r.Context(), "SELECT 1")
}
`,
	}))
}

// Pages behind a login with no Cache-Control: a shared browser or a proxy
// keeps an operator's page and shows it to the next one.
func TestAuthenticatedPagesWithoutNoStore(t *testing.T) {
	assert.Equal(t, []string{"admin/routes.go:24", "admin/routes.go:52"}, typedFuncFindings(t, NewAuthenticatedPagesWithoutNoStoreRule(), map[string]string{
		"router/router.go": routerSource,
		"admin/routes.go": `package admin

import (
	"html/template"
	"net/http"

	"example.com/rulestest/router"
)

type Admin struct{ tmpl *template.Template }

func (a *Admin) basicAuth(next http.Handler) http.Handler { return next }

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		next.ServeHTTP(w, r)
	})
}

func (a *Admin) Routes(r router.Router) {
	r.Get("/login", a.page)
	r.Group(func(r router.Router) {
		r.Use(a.basicAuth)
		r.Get("/", a.page)
	})
}

func (a *Admin) SafeRoutes(r router.Router) {
	r.Use(noStore)
	r.Group(func(r router.Router) {
		r.Use(a.basicAuth)
		r.Get("/", a.page)
	})
}

func (a *Admin) page(w http.ResponseWriter, r *http.Request) { _ = a.tmpl.Execute(w, nil) }

func (a *Admin) useCommon(r router.Router) {
	r.Use(a.basicAuth)
	r.Use(noStore)
}

func (a *Admin) useAuthOnly(r router.Router) { r.Use(a.basicAuth) }

func (a *Admin) HelperRoutes(r router.Router) {
	r.Group(func(r router.Router) {
		a.useCommon(r)
		r.Get("/", a.page)
	})
	r.Group(func(r router.Router) {
		a.useAuthOnly(r)
		r.Get("/reports", a.page)
	})
}
`,
		// An API package renders no pages: its JSON is not what this is about.
		"api/routes.go": `package api

import (
	"net/http"

	"example.com/rulestest/router"
)

func requireAuth(next http.Handler) http.Handler { return next }

func Routes(r router.Router, h http.HandlerFunc) {
	r.Group(func(r router.Router) {
		r.Use(requireAuth)
		r.Get("/items", h)
	})
}
`,
	}))
}

// A third-party script or stylesheet with no integrity hash runs whatever
// the CDN serves today inside the admin's origin.
func TestCDNAssetWithoutIntegrity(t *testing.T) {
	ctx := rulestest.TextFile(t, "web/templates/layout.html", `<!doctype html>
<html>
<head>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/pico@2/css/pico.min.css">
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  <script src="https://unpkg.com/alpinejs@3.14.1" integrity="sha384-abc" crossorigin="anonymous"></script>
  <link rel="stylesheet" href="/static/app.css">
  <script src="/static/app.js"></script>
  <link rel="preconnect" href="https://fonts.gstatic.com">
</head>
</html>
`)
	assert.Equal(t, []string{"web/templates/layout.html:4", "web/templates/layout.html:5"}, foundLines(NewCDNAssetWithoutIntegrityRule().AnalyzeFile(ctx)))
	// A mockup kept with the documentation is not served by the application.
	mockup := rulestest.TextFile(t, "docs/prototype/index.html", `<script src="https://unpkg.com/htmx.org@2.0.4"></script>`)
	assert.Empty(t, NewCDNAssetWithoutIntegrityRule().AnalyzeFile(mockup))
}

// An admin panel or a mock provider switched on unless an environment
// variable says otherwise: a deploy that forgets the variable exposes it.
func TestPrivilegedSurfaceEnabledByDefault(t *testing.T) {
	assert.Equal(t, []string{"config/config.go:11", "config/config.go:23"}, typedFuncFindings(t, NewPrivilegedSurfaceEnabledByDefaultRule(), map[string]string{
		"config/config.go": `package config

import "os"

type Config struct {
	AdminEnabled, Debug, Metrics, Mock bool
}

func Load() *Config {
	cfg := &Config{}
	adminEnabled := true
	if v := os.Getenv("ADMIN_ENABLED"); v != "" {
		adminEnabled = v == "true"
	}
	debug := false
	if v := os.Getenv("DEBUG"); v != "" {
		debug = v == "true"
	}
	metricsEnabled := true
	if v := os.Getenv("METRICS_ENABLED"); v != "" {
		metricsEnabled = v == "true"
	}
	cfg.Mock = envBool("MOCK_PROVIDER", true)
	cfg.AdminEnabled, cfg.Debug, cfg.Metrics = adminEnabled, debug, metricsEnabled
	cfg.Debug = cfg.Debug || envBool("DEBUG_SQL", false)
	return cfg
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "true"
	}
	return def
}
`,
	}))
}

// A handler that fills an entity from hardcoded test data and stores it,
// with no switch that keeps it off in production, creates real records from
// fake people.
func TestTestDataPathUngatedInProduction(t *testing.T) {
	assert.Equal(t, []string{"admin/ops.go:30", "admin/ops.go:36"}, typedFuncFindings(t, NewTestDataPathUngatedInProductionRule(), map[string]string{
		"admin/ops.go": `package admin

import "net/http"

type Tx struct{ Sender string }

type Repo struct{}

func (r *Repo) CreateTx(tx *Tx) error { return nil }

type Config struct{ TestTools bool }

type Admin struct {
	repo *Repo
	cfg  Config
}

type quoteInput struct{ amount int }

func (in quoteInput) newTestTransaction() *Tx { return &Tx{Sender: "TEST SENDER"} }

func applyTestSenderData(tx *Tx) { tx.Sender = "TEST SENDER" }

func (a *Admin) createQuote(tx *Tx) error { return a.repo.CreateTx(tx) }

func parse(r *http.Request) quoteInput { return quoteInput{} }

func (a *Admin) quick(w http.ResponseWriter, r *http.Request) {
	input := parse(r)
	tx := input.newTestTransaction()
	_ = a.createQuote(tx)
}

func (a *Admin) fill(w http.ResponseWriter, r *http.Request) {
	tx := &Tx{}
	applyTestSenderData(tx)
	_ = a.repo.CreateTx(tx)
}

func (a *Admin) gated(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.TestTools {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	tx := parse(r).newTestTransaction()
	_ = a.createQuote(tx)
}

// preview shows the sample without storing it.
func (a *Admin) preview(w http.ResponseWriter, r *http.Request) {
	tx := parse(r).newTestTransaction()
	_, _ = w.Write([]byte(tx.Sender))
}
`,
	}))
}

// A scope read as "nil means everything" filled from a loader that returns
// nil for a user with no rows: the user with nothing assigned sees all.
func TestNilSliceAsUnrestrictedScope(t *testing.T) {
	assert.Equal(t, []string{"admin/auth.go:17"}, typedFuncFindings(t, NewNilSliceAsUnrestrictedScopeRule(), map[string]string{
		"store/repo.go": `package store

type Repo struct{ rows map[int][]int }

func (r *Repo) ProjectIDs(user int) ([]int, error) {
	var ids []int
	for _, id := range r.rows[user] {
		ids = append(ids, id)
	}
	return ids, nil
}

func (r *Repo) RoleIDs(user int) ([]int, error) {
	ids := []int{}
	for _, id := range r.rows[user] {
		ids = append(ids, id)
	}
	return ids, nil
}

func (r *Repo) TagIDs(user int) ([]int, error) {
	var ids []int
	for _, id := range r.rows[user] {
		ids = append(ids, id)
	}
	return ids, nil
}
`,
		"admin/auth.go": `package admin

import "example.com/rulestest/store"

type User struct {
	ProjectIDs []int
	RoleIDs    []int
	TagIDs     []int
}

func load(repo *store.Repo, id int) (*User, error) {
	u := &User{}
	pids, err := repo.ProjectIDs(id)
	if err != nil {
		return nil, err
	}
	u.ProjectIDs = pids
	rids, err := repo.RoleIDs(id)
	if err != nil {
		return nil, err
	}
	u.RoleIDs = rids
	tids, err := repo.TagIDs(id)
	if err != nil {
		return nil, err
	}
	u.TagIDs = tids
	return u, nil
}

func allowed(u *User, project int) bool {
	if u.ProjectIDs == nil {
		return true
	}
	for _, p := range u.ProjectIDs {
		if p == project {
			return true
		}
	}
	return false
}

func hasRole(u *User) bool {
	if u.RoleIDs == nil {
		return true
	}
	return len(u.RoleIDs) > 0
}

func tagged(u *User) bool { return len(u.TagIDs) > 0 }
`,
	}))
}

package frontendrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTSPathNotRouted(t *testing.T) {
	assert.Len(t, apiPaths("await request.get(apiEndpoint('/api/admin/analytics'))"), 1)
	files := map[string]string{
		"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
		"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
		"third_party/mux/mux.go": patterntest.MuxStub,
		"backend/admin.go": `package backend
import "github.com/gorilla/mux"
import "net/http"
func Register(router *mux.Router) {
 router.HandleFunc("/api/admin/stats", nil).Methods("GET")
 reports := router.PathPrefix("/api/admin/reports").Subrouter()
 reports.HandleFunc("/{id}", nil).Methods("GET")
}
func Alerts(router *mux.Router) {
 router.Handle("/alerts/{id}", nil).Methods("PATCH")
}
func handler(http.ResponseWriter, *http.Request) {}
`,
		"frontend/config/endpoints.ts": `export const ENDPOINTS = { ANALYTICS: ` + "`" + `${API_BASE}/admin/analytics` + "`" + `, STATS: '/api/admin/stats' }
`,
		"e2e/admin.spec.ts": `await request.get(
  apiEndpoint('/api/admin/analytics'),
)
await request.get(` + "`" + `/api/admin/reports/${id}` + "`" + `)
`,
	}
	places := typedProjectFilesRulePlaces(t, NewTSPathNotRoutedRule(), files)
	assert.Equal(t, []string{"e2e/admin.spec.ts:2", "frontend/config/endpoints.ts:1"}, places)
}

func TestTSPathNotRoutedAPIBasePathDoesNotUseSuffixMatch(t *testing.T) {
	files := map[string]string{
		"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
		"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
		"third_party/mux/mux.go": patterntest.MuxStub,
		"backend/routes.go": `package backend
import "github.com/gorilla/mux"
func Register(router *mux.Router) {
 router.HandleFunc("/api/admin/analytics/metrics", nil)
}
`,
		"frontend/api-endpoints.ts": "const API_BASE_PATH = '/api' as const\nfetch(" + "`" + `${API_BASE_PATH}/admin/analytics` + "`" + ")\n",
	}
	assert.Equal(t, []string{"frontend/api-endpoints.ts:2"}, typedProjectFilesRulePlaces(t, NewTSPathNotRoutedRule(), files))
}

func TestTSPathNotRoutedSubrouter(t *testing.T) {
	files := map[string]string{
		"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
		"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
		"third_party/mux/mux.go": patterntest.MuxStub,
		"backend/routes.go": `package backend
import "github.com/gorilla/mux"
import "net/http"
func Register(router *mux.Router) {
 reports := router.PathPrefix("/api/admin/reports").Subrouter()
 reports.HandleFunc("/{id}", nil)
}
func Alerts(router *mux.Router) {
 router.HandleFunc("/alerts/{id}", nil)
 router.HandleFunc("/admin/alerts/{id}", nil)
}
func handler(http.ResponseWriter, *http.Request) {}
`,
		"frontend/api.ts": "fetch(" + "`" + "/api/admin/reports/${id}" + "`" + ")\nfetch(" + "`" + "/alerts/${id}" + "`" + ")\nfetch(" + "`" + "/api/admin/alerts/${id}" + "`" + ")\n",
	}
	assert.Empty(t, typedProjectFilesRulePlaces(t, NewTSPathNotRoutedRule(), files))
}

func TestTSPathNotRoutedNegatives(t *testing.T) {
	assert.Empty(t, apiPaths("await page.goto(`${APP_URL}/analytics`)"))
	assert.Len(t, apiPaths("await request.get(`${API_BASE}/admin/analytics`);"), 1)
	assert.True(t, routeCovers([]muxEndpoint{{Path: "/api/user/goals/{id}"}}, "/user/goals/*", true))

	t.Run("no mux routes", func(t *testing.T) {
		files := map[string]string{"frontend/api.ts": `fetch('/api/missing')`}
		assert.Empty(t, typedProjectFilesRulePlaces(t, NewTSPathNotRoutedRule(), files))
	})

	t.Run("external URLs queries and ordinary paths", func(t *testing.T) {
		files := map[string]string{
			"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
			"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
			"third_party/mux/mux.go": patterntest.MuxStub,
			"backend/routes.go": `package backend
import "github.com/gorilla/mux"
func Register(router *mux.Router) { router.PathPrefix("/api/assets").Handler(nil) }
`,
			"frontend/api.ts": `fetch('https://service.example/api/missing')
fetch('/api/assets/logo.png?size=small')
fetch('/ordinary/path')
// fetch('/api/comment-only')
`,
		}
		assert.Empty(t, typedProjectFilesRulePlaces(t, NewTSPathNotRoutedRule(), files))
	})

	t.Run("API base path matches full route", func(t *testing.T) {
		files := map[string]string{
			"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
			"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
			"third_party/mux/mux.go": patterntest.MuxStub,
			"backend/routes.go": `package backend
import "github.com/gorilla/mux"
func Register(router *mux.Router) { router.HandleFunc("/api/user/balance", nil) }
func handler() {}
`,
			"frontend/api.ts": "fetch(" + "`" + `${API_BASE}/user/balance` + "`" + ")\n",
		}
		assert.Empty(t, typedProjectFilesRulePlaces(t, NewTSPathNotRoutedRule(), files))
	})

	t.Run("suffix under API base path matches full route", func(t *testing.T) {
		assert.True(t, routeCovers([]muxEndpoint{{Path: "/api/admin/finance-reports/{section}.csv", Unknown: true}}, "/admin/finance-reports/report.csv", true))
	})
}

func TestTSPathNotRoutedFieldReceiverAndConst(t *testing.T) {
	files := map[string]string{
		"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
		"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
		"third_party/mux/mux.go": patterntest.MuxStub,
		"backend/routes.go": `package backend
import "github.com/gorilla/mux"
type Server struct{ router *mux.Router }
const CardStatusPath = "/api/user/cards/status"
func (s *Server) health(h *Health) {
	s.router.HandleFunc("/api/health/ready", nil).Methods("GET")
	s.router.Handle(CardStatusPath, nil)
}
type Health struct{}
func (*Health) Ready() {}
func (*Health) Status() interface{} { return nil }
type AdminWithdrawals struct{}
func (r *AdminWithdrawals) MountRoutes(router *mux.Router) {
	w := router.PathPrefix("/withdrawals").Subrouter()
	w.HandleFunc("", nil).Methods("GET")
	w.HandleFunc("/{id}/approve", nil).Methods("POST")
}
func (*AdminWithdrawals) list() {}
func (*AdminWithdrawals) approve() {}
`,
		"frontend/api.ts": "fetch('/api/health/ready')\nfetch('/api/user/cards/status')\n",
	}
	assert.Empty(t, typedProjectFilesRulePlaces(t, NewTSPathNotRoutedRule(), files))
}

func TestTSPathNotRoutedUnknownPrefixSubrouter(t *testing.T) {
	files := map[string]string{
		"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
		"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
		"third_party/mux/mux.go": patterntest.MuxStub,
		"backend/routes.go": `package backend
import "github.com/gorilla/mux"
type AdminWithdrawals struct{}
func (r *AdminWithdrawals) MountRoutes(router *mux.Router) {
	w := router.PathPrefix("/withdrawals").Subrouter()
	w.HandleFunc("", nil)
	w.HandleFunc("/{id}/approve", nil)
}
func (*AdminWithdrawals) list() {}
func (*AdminWithdrawals) approve() {}
`,
		"frontend/api.ts": "fetch('/api/admin/withdrawals/x/approve')\nfetch('/api/admin/withdrawals/x/explode')\n",
	}
	assert.Equal(t, []string{"frontend/api.ts:2"}, typedProjectFilesRulePlaces(t, NewTSPathNotRoutedRule(), files))
}

func TestTSPathNotRoutedNotAPath(t *testing.T) {
	assert.Empty(t, apiPaths("const r2 = { method: 'POST', path: `${TEST_CONFIG.api.endpoints.adminWithdrawals}/test-id/approve` }"))
	assert.Empty(t, apiPaths("if (url.pathname.startsWith('/api/')) {}"))
	assert.Empty(t, apiPaths("fetch('/api/')"))
	assert.Empty(t, apiPaths(`  user: "/api/user",`))
	files := map[string]string{
		"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
		"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
		"third_party/mux/mux.go": patterntest.MuxStub,
		"backend/routes.go": `package backend
import "github.com/gorilla/mux"
func Register(router *mux.Router) { router.HandleFunc("/api/user/cards/status", nil) }
func handler() {}
`,
		"frontend/__tests__/card.test.tsx": "mockApi.get.mock.calls('/api/user/cards/status')\n",
		"frontend/api.ts":                  "if (url.pathname.startsWith('/api/')) {}\nfetch('/api/')\n",
	}
	assert.Empty(t, typedProjectFilesRulePlaces(t, NewTSPathNotRoutedRule(), files))
}

func typedProjectFilesRulePlaces(t *testing.T, rule *TSPathNotRoutedRule, files map[string]string) []string {
	t.Helper()
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	var hasGo bool
	for _, file := range contexts {
		hasGo = hasGo || file.GoAST != nil
	}
	if hasGo {
		project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
		require.NoError(t, err)
		_ = project
	}
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, file := range contexts {
		violations = append(violations, rule.AnalyzeFile(file)...)
	}
	return rulestest.ViolationPlaces(violations)
}

func TestTSPathNotRoutedCatchAll(t *testing.T) {
	files := map[string]string{
		"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
		"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
		"third_party/mux/mux.go": patterntest.MuxStub,
		"backend/routes.go": `package backend
import "github.com/gorilla/mux"
func Register(router *mux.Router) {
 router.HandleFunc("/api/admin/stats", nil)
 adminRouter := router.PathPrefix("/api/admin").Subrouter()
 adminRouter.PathPrefix("/").HandlerFunc(nil)
 router.PathPrefix("/").Handler(nil)
}
func RegisterAdmin(adminRouter *mux.Router) {
 adminRouter.PathPrefix("/").HandlerFunc(nil)
}
func handler() {}
func spa() {}
func notFound() {}
`,
		"frontend/api.ts": "fetch('/api/admin/analytics')\nfetch('/api/admin/stats')\n",
	}
	assert.Equal(t, []string{"frontend/api.ts:1"}, typedProjectFilesRulePlaces(t, NewTSPathNotRoutedRule(), files))
}

package httprules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A literal path registered after a template that already matches it never
// reaches its handler: gorilla/mux takes the first route that matches, and
// "performance" is a fine {id}.
func TestMuxRouteShadowed(t *testing.T) {
	files := map[string]string{
		"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
		"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
		"third_party/mux/mux.go": patterntest.MuxStub,
		"api/routes.go": `package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

type API struct{ router *mux.Router }

func h(w http.ResponseWriter, r *http.Request) {}

func (a *API) Register(router *mux.Router) {
	router.HandleFunc("/api/orders", h).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/orders/{id}", h).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/orders/{id}", h).Methods("DELETE")
	router.HandleFunc("/api/orders/{id}/cancel", h).Methods("POST")
	router.HandleFunc("/api/orders/summary", h).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/orders/export", h).Methods("POST")
	router.HandleFunc("/api/items/{id:[0-9]+}", h).Methods("GET")
	router.HandleFunc("/api/items/latest", h).Methods("GET")
	router.HandleFunc("/api/items/7", h).Methods("GET")
}

func (a *API) Static() {
	a.router.PathPrefix("/").Handler(http.FileServer(http.Dir("web")))
	a.router.HandleFunc("/healthz", h)
}

func (a *API) Guarded(router *mux.Router) {
	router.PathPrefix("/").Handler(http.NotFoundHandler()).Headers("X-Static", "1")
	router.HandleFunc("/healthz", h)
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/ping", h)
	router.HandleFunc("/api/ping", h)
}

func (a *API) SpecificFirst(router *mux.Router) {
	router.HandleFunc("/api/users/me", h).Methods("GET")
	router.HandleFunc("/api/users/{id}", h).Methods("GET")
	router.Path("/api/files/{name}").HandlerFunc(h)
	router.Path("/api/files/{name}/meta").HandlerFunc(h)
	reports := router.PathPrefix("/reports").Subrouter()
	reports.HandleFunc("", h).Methods("GET")
	reports.HandleFunc("/", h).Methods("GET")
	reports.HandleFunc("/daily", h).Methods("GET")
}
`,
	}
	violations, err := NewMuxRouteShadowedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"api/routes.go:18", "api/routes.go:22", "api/routes.go:27"}, patterntest.FoundLines(violations))
}

package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A package that fails to type-check (an old tree, a broken build) still
// reaches the route, map-lookup and context-key rules by its syntax.
func TestRulesOnPackageWithoutTypes(t *testing.T) {
	files := map[string]string{
		"go.mod":                 "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/gorilla/mux v1.8.0\n\nreplace github.com/gorilla/mux => ./third_party/mux\n",
		"third_party/mux/go.mod": "module github.com/gorilla/mux\n\ngo 1.24\n",
		"third_party/mux/mux.go": muxStub,
		"web/routes.go": `package web

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
)

var broken int = "not an int"

type adminKey string

const (
	AdminIDKey    adminKey = "adminID"
	AdminRolesKey adminKey = "adminRoles"
	ClaimsKey     adminKey = "claims"
)

func h(w http.ResponseWriter, r *http.Request) {}

func Register(router *mux.Router, cfg map[string]struct{ Hosts []string }) string {
	router.HandleFunc("/api/items/{id}", h).Methods("GET")
	router.HandleFunc("/api/items/latest", h).Methods("GET")
	return cfg["primary"].Hosts[0]
}

func enrich(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, AdminIDKey, "a")
	return context.WithValue(ctx, AdminRolesKey, []string{"admin"})
}

func Cookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ClaimsKey, "c")
		ctx = context.WithValue(ctx, AdminIDKey, "a")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func Roles(r *http.Request) any { return r.Context().Value(AdminRolesKey) }
`,
	}
	assert.Equal(t, []string{"web/routes.go:24"}, foundLines(runRuleOnBrokenFiles(t, NewMuxRouteShadowedRule(), files)))
	assert.Equal(t, []string{"web/routes.go:25"}, foundLines(runRuleOnBrokenFiles(t, NewIndexIntoMapLookupRule(), files)))
	assert.Equal(t, []string{"web/routes.go:36"}, foundLines(runRuleOnBrokenFiles(t, NewContextKeyUnpairedRule(), files)))
}

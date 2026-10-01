package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// The cookie middleware authenticates the same request as the token one but
// stores only the user id: handlers reading the role get nil and refuse an
// authenticated admin. A key read and never stored, or stored and never
// read, is the same mismatch seen from one side.
func TestContextKeyUnpaired(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"auth/keys.go": `package auth

type ctxKey string

const (
	UserIDKey   ctxKey = "userID"
	UserRoleKey ctxKey = "role"
	TraceKey    ctxKey = "trace"
	OrphanKey   ctxKey = "orphan"
	UnsetKey    ctxKey = "unset"
	SessionKey  ctxKey = "session"
)

const AliasUserKey = UserIDKey

type otherKey int

const BatchKey otherKey = 1
`,
		"auth/middleware.go": `package auth

import (
	"context"
	"net/http"
)

func Token(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(enrich(r.Context())))
	})
}

func enrich(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, UserIDKey, "u")
	return context.WithValue(ctx, UserRoleKey, "admin")
}

func WithUser(ctx context.Context) context.Context {
	return context.WithValue(ctx, UserIDKey, "u")
}

func Cookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), SessionKey, "s")
		ctx = context.WithValue(ctx, UserIDKey, "u")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func Visitor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), TraceKey, "t")
		ctx = context.WithValue(ctx, SessionKey, "s")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func Trace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), TraceKey, "t")))
	})
}

func Tag(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, OrphanKey, 1)
	return context.WithValue(ctx, BatchKey, 2)
}

func lookup(ctx context.Context, key otherKey) any { return ctx.Value(key) }
`,
		"api/handlers.go": `package api

import (
	"context"

	"example.com/rulestest/auth"
)

func Whoami(ctx context.Context) (any, any, any, any, any) {
	return ctx.Value(auth.AliasUserKey), ctx.Value(auth.UserRoleKey), ctx.Value(auth.TraceKey), ctx.Value(auth.UnsetKey), ctx.Value(auth.SessionKey)
}
`,
	}
	violations, err := NewContextKeyUnpairedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"api/handlers.go:10", "auth/middleware.go:26", "auth/middleware.go:46"}, foundLines(violations))
}

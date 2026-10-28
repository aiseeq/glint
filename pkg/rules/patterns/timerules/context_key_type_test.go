package timerules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A context value read or stored under a key of a built-in type: a reader
// with "userID" never sees what a middleware stored under ctxKey("userID"),
// and two packages using the same string collide.
func TestContextKeyBuiltinType(t *testing.T) {
	files := map[string]string{
		"auth/keys.go": `package auth

import (
	"context"
	"net/http"
)

type ctxKey string

const UserIDKey ctxKey = "userID"

const plainKey = "session"

type Store struct{ values map[string]any }

// Value of a type of its own: string keys are its design.
func (s *Store) Value(key string) any { return s.values[key] }

func Middleware(next http.Handler, id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), UserIDKey, id)
		ctx = context.WithValue(ctx, "role", "admin") // want context-key-builtin-type
		ctx = context.WithValue(ctx, plainKey, 1)     // want context-key-builtin-type
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserID(r *http.Request) (string, bool) {
	id, ok := r.Context().Value("userID").(string) // want context-key-builtin-type
	return id, ok
}

func Typed(ctx context.Context, s *Store) (any, any) {
	var key = "dynamic"
	return ctx.Value(UserIDKey), s.Value("userID") == ctx.Value(key) // want context-key-builtin-type
}
`,
	}
	violations, err := NewContextKeyBuiltinTypeRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "context-key-builtin-type"), patterntest.FoundLines(violations))
}

package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A middleware for a restricted role that forbids a list of path prefixes and
// passes everything else lets that role reach every route nobody listed.
func TestRoleRouteDenylist(t *testing.T) {
	assert.Equal(t, []string{"api/guard.go:24"}, typedRuleFindings(t, NewRoleRouteDenylistRule(), map[string]string{
		"api/guard.go": `package api

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey struct{}

func IsPartnerUser(ctx context.Context) bool { return ctx.Value(ctxKey{}) != nil }

func partnerGuard(next http.Handler) http.Handler {
	ownerOnly := []string{"/console/firms", "/console/accounts", "/console/sync"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if !IsPartnerUser(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}
		for _, prefix := range ownerOnly {
			if strings.HasPrefix(r.URL.Path, prefix) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// An allowlist: the partner reaches only the listed paths.
func partnerAllowlist(next http.Handler) http.Handler {
	partnerPaths := []string{"/console/reports", "/console/me"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsPartnerUser(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}
		for _, prefix := range partnerPaths {
			if strings.HasPrefix(r.URL.Path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

// A list of public paths skipped by authentication for everyone is no role
// restriction.
func publicPaths(next http.Handler) http.Handler {
	blocked := []string{"/debug", "/internal"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, prefix := range blocked {
			if strings.HasPrefix(r.URL.Path, prefix) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
`,
	}))
}

// A download name built into the header with %s breaks the header on a quote
// or a semicolon of a name the server does not choose.
func TestContentDispositionUnescaped(t *testing.T) {
	assert.Equal(t, []string{"api/export.go:18", "api/export.go:22"}, typedRuleFindings(t, NewContentDispositionUnescapedRule(), map[string]string{
		"api/export.go": `package api

import (
	"fmt"
	"mime"
	"net/http"
	"time"
)

type Report struct {
	HolderName string
	Period     time.Time
	Number     int
}

func export(w http.ResponseWriter, report Report) {
	filename := fmt.Sprintf("report-%s-%s.csv", report.HolderName, report.Period.Format("2006-01-02"))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
}

func exportConcat(w http.ResponseWriter, report Report) {
	w.Header().Set("Content-Disposition", "attachment; filename="+report.HolderName+".csv")
}

func exportSafe(w http.ResponseWriter, report Report) {
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": report.HolderName + ".csv"}))
}

// A name the server builds from a date and a number carries no quote.
func exportDated(w http.ResponseWriter, report Report) {
	filename := fmt.Sprintf("report-%s-%d.csv", report.Period.Format("2006-01-02"), report.Number)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
}

// %q escapes the quote.
func exportQuoted(w http.ResponseWriter, report Report) {
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", report.HolderName))
}
`,
	}))
}

// A session token written into web storage outlives the session and is open
// to any script on the page.
func TestWebStorageHoldsToken(t *testing.T) {
	code := `export class Api {
  setAuthToken(token: string | null) {
    this.authToken = token
    if (token) {
      localStorage.setItem('console_jwt', token)
    }
    window.sessionStorage.setItem(ACCESS_TOKEN_KEY, value)
    localStorage.setItem('refresh', refreshToken)
    localStorage.setItem(SIGNED_IN_KEY, '1')
    sessionStorage.setItem(SESSION_ID_KEY, id)
    localStorage.setItem('csrf_token', csrf)
    localStorage.setItem('theme', theme)
  }
}`
	ctx := core.NewFileContext("frontend/services/api.ts", ".", []byte(code), nil)
	var lines []int
	for _, v := range NewWebStorageHoldsTokenRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{5, 7, 8}, lines)
}

const roleClaimAuth = `package api

import (
	"os"
	"strings"
)

type ctxKey string

const roleKey ctxKey = "role"

type Claims struct {
	Subject string
	Email   string
	Role    string
}

type identity struct {
	sub  string
	role string
}

func isOwnerEmail(email string) bool {
	for _, e := range strings.Split(os.Getenv("OWNER_EMAILS"), ",") {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	return false
}

func parseSession(token string) (*Claims, error) { return &Claims{}, nil }

func resolveLogin(email, sub string) (identity, bool) {
	if isOwnerEmail(email) {
		return identity{sub: sub, role: "owner"}, true
	}
	return identity{}, false
}
`

// A role the login hands out only to an allowlisted email is trusted from
// the token on every request: removing the email from the list revokes
// nothing until the token expires.
func TestRoleClaimTrustedWithoutRecheck(t *testing.T) {
	assert.Equal(t, []string{"api/session.go:20"}, typedRuleFindings(t, NewRoleClaimTrustedWithoutRecheckRule(), map[string]string{
		"api/auth.go": roleClaimAuth,
		"api/session.go": `package api

import (
	"context"
	"net/http"
)

func sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := parseSession(cookie.Value)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), roleKey, claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
`,
	}))
}

// The middleware that rechecks the allowlist on each request revokes the
// role at once.
func TestRoleClaimRecheckedOnEachRequest(t *testing.T) {
	assert.Empty(t, typedRuleFindings(t, NewRoleClaimTrustedWithoutRecheckRule(), map[string]string{
		"api/auth.go": roleClaimAuth,
		"api/session.go": `package api

import (
	"context"
	"net/http"
)

func sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := parseSession(cookie.Value)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if claims.Role == "owner" && !isOwnerEmail(claims.Email) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), roleKey, claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
`,
	}))
}

// A write permission equal to the read permission of the same route lets a
// read-only role change the data.
func TestWritePermissionIsRead(t *testing.T) {
	ctx := rulestest.GoFile(t, "api/perms.go", `package api

type routePermission struct {
	prefix     string
	read       string
	write      string
	selfScoped bool
}

var routePermissions = []routePermission{
	{prefix: "/ledger", read: "ledger:read", write: "ledger:write"},
	{prefix: "/reports", read: "reports:read"},
	{prefix: "/units", read: "reports:read", write: "settings:write"},
	{prefix: "/rates", read: "reports:read", write: "reports:read"},
	{prefix: "/cards", read: "cards:read", write: "dashboard:read"},
	{prefix: "/notify/settings", read: "issues:read", write: "issues:read", selfScoped: true},
}
`)
	var lines []int
	for _, v := range NewWritePermissionIsReadRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{14, 15}, lines)
}

// The allowlisted seed gets its role back on every access, and the allowlist
// alone authorizes: a role removed in the admin screen does not hold.
func TestAllowlistRegrantsRevokedRole(t *testing.T) {
	assert.Equal(t, []string{"api/access.go:32", "api/access.go:44"}, typedRuleFindings(t, NewAllowlistRegrantsRevokedRoleRule(), map[string]string{
		"api/access.go": `package api

import (
	"context"
	"os"
	"strings"
)

func isSeedEmail(email string) bool {
	return strings.Contains(os.Getenv("SEED_EMAILS"), email)
}

type Access struct{ Roles []string }

type Staff struct{ ID string }

type Store interface {
	EnsureByEmail(ctx context.Context, email string) (*Staff, error)
	EnsureDefaultRole(ctx context.Context, staffID, role string) (bool, error)
	GetAccess(ctx context.Context, staffID string) (Access, error)
	CreateSeeded(ctx context.Context, email, role string) (*Staff, bool, error)
}

type Resolver struct{ store Store }

func (c *Resolver) AccessByEmail(ctx context.Context, email string) (Access, error) {
	staff, err := c.store.EnsureByEmail(ctx, email)
	if err != nil {
		return Access{}, err
	}
	if isSeedEmail(email) {
		if _, err := c.store.EnsureDefaultRole(ctx, staff.ID, "super_admin"); err != nil {
			return Access{}, err
		}
	}
	return c.store.GetAccess(ctx, staff.ID)
}

func (c *Resolver) Authorized(ctx context.Context, email string) (bool, error) {
	access, err := c.AccessByEmail(ctx, email)
	if err != nil {
		return false, err
	}
	return isSeedEmail(email) || len(access.Roles) > 0, nil
}

// The seed is created with its role once; afterwards roles live in the store.
func (c *Resolver) resolveSeed(ctx context.Context, email string) (*Staff, error) {
	if isSeedEmail(email) {
		staff, _, err := c.store.CreateSeeded(ctx, email, "super_admin")
		return staff, err
	}
	return c.store.EnsureByEmail(ctx, email)
}
`,
	}))
}

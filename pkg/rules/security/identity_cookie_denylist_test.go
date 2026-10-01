package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// An identity read from a request header the project never sets comes from
// the client: whoever sends X-Admin-ID is that admin. A header the project's
// own middleware sets after verifying a token, a header of another meaning
// (a request id) and a header of a response are left alone.
func TestIdentityHeaderFromClient(t *testing.T) {
	files := map[string]string{
		"httpx/ids.go": `package httpx

import "net/http"

const HeaderUserID = "X-User-ID"

func AdminID(r *http.Request) (string, bool) {
	id := r.Header.Get("X-Admin-ID")
	return id, id != ""
}

func UserID(r *http.Request) string { return r.Header.Get(HeaderUserID) }

func RequestID(r *http.Request) string { return r.Header.Get("X-Request-ID") }

func Tenant(resp *http.Response) string { return resp.Header.Get("X-Tenant-ID") }

func Role(r *http.Request) string { return r.Header.Get("X-User-Role") }
`,
		"middleware/auth.go": `package middleware

import "net/http"

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-User-ID", "verified")
		next.ServeHTTP(w, r)
	})
}
`,
	}
	assert.Equal(t, []string{"httpx/ids.go:18", "httpx/ids.go:8"},
		typedRuleLines(t, NewIdentityHeaderFromClientRule().AnalyzeGoProject, files))
}

// A cookie set with a Domain is deleted only by a cookie with the same
// Domain and Path: a deletion without it leaves the domain-wide cookie in
// the browser, and logout does not log out. A deletion of a cookie of
// another name, and one with the same attributes, are fine.
func TestCookieDeletedWithOtherAttributes(t *testing.T) {
	files := map[string]string{
		"auth/cookie.go": `package auth

import (
	"net/http"
	"time"
)

func SetSessionCookie(w http.ResponseWriter, name, value, baseDomain string, secure bool) {
	cookie := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: secure}
	if secure {
		cookie.Domain = "." + baseDomain
	}
	http.SetCookie(w, cookie)
}

func ClearSessionCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
}

func ClearThemeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "theme", Path: "/", MaxAge: -1})
}

func SetTheme(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: v, Path: "/"})
}

func SetLang(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{Name: "lang", Value: v, Path: "/app", Domain: ".example.com"})
}

func ClearLang(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "lang", Path: "/app", Domain: ".example.com", Expires: time.Unix(0, 0)})
}

func ClearLangRoot(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "lang", Path: "/", Domain: ".example.com", MaxAge: -1})
}
`,
		"helpers/cookie.go": `package helpers

import "net/http"

func AuthCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true}
}

func LogoutCookie(name string) *http.Cookie {
	return &http.Cookie{Name: name, Path: "/", MaxAge: -1}
}
`,
	}
	assert.Equal(t, []string{"auth/cookie.go:17", "auth/cookie.go:37"},
		typedRuleLines(t, NewCookieDeletedWithOtherAttributesRule().AnalyzeGoProject, files))
}

// SQL text checked against a list of dangerous keywords is a denylist: a tab
// instead of a space, a comment inside a keyword or OR 1=1 pass it, and the
// SQL is still built from strings. A check that classifies a statement
// (is it a write?) is not a denylist.
func TestSQLKeywordDenylist(t *testing.T) {
	code := `package sqlx

import (
	"errors"
	"strings"
)

var dangerous = []string{"DROP ", "DELETE ", "UNION ", "--", ";"}

func ValidateWhere(where string) error {
	upper := strings.ToUpper(where)
	for _, kw := range dangerous {
		if strings.Contains(upper, kw) {
			return errors.New("forbidden")
		}
	}
	return nil
}

func ValidateColumns(cols string) error {
	upper := strings.ToUpper(cols)
	if strings.Contains(upper, "DROP ") || strings.Contains(upper, "--") || strings.Contains(upper, ";") {
		return errors.New("forbidden")
	}
	return nil
}

func IsWrite(query string) bool {
	upper := strings.ToUpper(strings.TrimSpace(query))
	return strings.HasPrefix(upper, "INSERT") || strings.HasPrefix(upper, "UPDATE") || strings.Contains(upper, "DELETE ")
}

func blockComment(line string, open bool) bool {
	if open {
		return !strings.Contains(line, "*/")
	}
	return strings.Contains(line, "/*") && !strings.Contains(line, ";")
}
`
	assert.Equal(t, []int{13, 22}, ruleLines(t, NewSQLKeywordDenylistRule(), code))
}

package security

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A validator that looks only at the length and the first characters
// accepts any string of that shape: a typo, another chain's address, "TRtest".
// One that decodes, checks a checksum or calls a library is fine.
func TestAddressValidatedByShape(t *testing.T) {
	code := `package wallet

import (
	"errors"
	"strings"
)

func isChainAAddress(address string) bool {
	if len(address) < 34 || len(address) > 42 {
		return false
	}
	return strings.HasPrefix(address, "TR") || strings.HasPrefix(address, "TRtest")
}

func validateChainBAddress(address string) error {
	if !strings.HasPrefix(address, "0x") || len(address) != 42 {
		return errors.New("invalid address")
	}
	return nil
}

func isPrivateAddress(addr string) bool {
	return strings.HasPrefix(addr, "10.") || strings.HasPrefix(addr, "192.168.")
}

func isChainCAddress(address string) bool {
	if !strings.HasPrefix(address, "0x") || len(address) != 42 {
		return false
	}
	return checksumOK(address)
}

func checksumOK(string) bool { return true }

func isChainDAddress(address string) bool {
	return len(address) == 56 && strings.HasPrefix(address, "G")
}

func withdraw(to string) error {
	if !isChainAAddress(to) {
		return errors.New("bad address")
	}
	switch {
	case isChainDAddress(to):
		return nil
	}
	return nil
}
`
	assert.Equal(t, []int{8, 15}, ruleLines(t, NewAddressValidatedByShapeRule(), code))
}

func projectFileLines(t *testing.T, rule interface {
	rules.Rule
	UseProjectFiles(files []*core.FileContext)
}, files map[string]string) []string {
	t.Helper()
	var contexts []*core.FileContext
	for path, source := range files {
		contexts = append(contexts, rulestest.GoFile(t, path, source))
	}
	rule.UseProjectFiles(contexts)
	var found []string
	for _, ctx := range contexts {
		for _, v := range rule.AnalyzeFile(ctx) {
			found = append(found, fmt.Sprintf("%s:%d", v.File, v.Line))
		}
	}
	slices.Sort(found)
	return found
}

// The same security header set by two middlewares: the one that runs last
// wins, and the policy in force is not the one the reader of either file sees.
func TestSecurityHeaderMultipleWriters(t *testing.T) {
	found := projectFileLines(t, NewSecurityHeaderMultipleWritersRule(), map[string]string{
		"middleware/https.go": `package middleware

import "net/http"

func setHTTPSHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "upgrade-insecure-requests")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
}
`,
		"middleware/security.go": `package middleware

import "net/http"

func securityHeaders(w http.ResponseWriter, csp string, prod bool) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Frame-Options", "DENY")
	if prod {
		h.Set("X-Content-Type-Options", "nosniff")
	} else {
		h.Set("X-Content-Type-Options", "nosniff")
	}
}
`,
		"middleware/html.go": `package middleware

import "net/http"

func pageHeaders(w http.ResponseWriter) { w.Header().Set("Referrer-Policy", "no-referrer") }

func htmlHeaders(w http.ResponseWriter, csp string) { w.Header().Set("Referrer-Policy", "same-origin") }
`,
		"middleware/security_test.go": `package middleware

import "net/http"

func fake(w http.ResponseWriter) { w.Header().Set("X-Frame-Options", "SAMEORIGIN") }
`,
	})
	assert.Equal(t, []string{"middleware/https.go:6", "middleware/security.go:7"}, found)
}

// A JSON API router left with mux's default NotFoundHandler answers an
// unknown /api/ path with text/plain "404 page not found".
func TestMuxAPIDefaultNotFound(t *testing.T) {
	found := projectFileLines(t, NewMuxAPIDefaultNotFoundRule(), map[string]string{
		"routing/router.go": `package routing

import (
	"net/http"

	"github.com/gorilla/mux"
)

func New(h http.HandlerFunc) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/api/users", h).Methods("GET")
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("static")))
	return router
}
`,
		"admin/router.go": `package admin

import "github.com/gorilla/mux"

func Routes() *mux.Router {
	r := mux.NewRouter()
	r.Path("/health")
	return r
}
`,
	})
	assert.Equal(t, []string{"routing/router.go:10"}, found)

	handled := projectFileLines(t, NewMuxAPIDefaultNotFoundRule(), map[string]string{
		"routing/router.go": `package routing

import (
	"net/http"

	"github.com/gorilla/mux"
)

func New(h, notFound http.HandlerFunc) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/api/users", h)
	router.NotFoundHandler = notFound
	return router
}
`,
	})
	assert.Empty(t, handled)

	catchAll := projectFileLines(t, NewMuxAPIDefaultNotFoundRule(), map[string]string{
		"routing/router.go": `package routing

import (
	"net/http"

	"github.com/gorilla/mux"
)

func New(h, apiNotFound http.HandlerFunc) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/api/users", h)
	router.PathPrefix("/api/").HandlerFunc(apiNotFound)
	return router
}
`,
	})
	assert.Empty(t, catchAll)
}

// An identifier built from data and later taken apart to get the data back:
// the id carries the email, and anything that changes its shape breaks the
// parse. Prefixes used only to build or only to parse are fine.
func TestIDEncodesData(t *testing.T) {
	found := projectFileLines(t, NewIDEncodesDataRule(), map[string]string{
		"auth/router.go": `package auth

import "fmt"

func login(email, role string) string {
	adminID := fmt.Sprintf("admin-%s", email)
	cacheKey := "admin-" + email
	_ = cacheKey
	return issue(adminID, role)
}
`,
		"auth/tokens.go": `package auth

import "strings"

func issue(userID, role string) string {
	adminEmail := userID
	if strings.HasPrefix(userID, "admin-") {
		adminEmail = strings.TrimPrefix(userID, "admin-")
	}
	return adminEmail + role
}

func orderRef(orderID string) string { return strings.TrimPrefix(orderID, "ord_") }
`,
	})
	assert.Equal(t, []string{"auth/router.go:6", "auth/tokens.go:8"}, found)
}

// A value written into an HTML attribute without escaping: a quote in it
// closes the attribute and adds another (onload=...). Escaped values and
// numbers are fine.
func TestHTMLAttributeUnescaped(t *testing.T) {
	code := `package og

import (
	"html"
	"strconv"
)

func meta(base, slug string) string {
	img := base + "/og/" + slug + ".png"
	return ` + "`<meta property=\"og:image\" content=\"`" + ` + img + ` + "`\">`" + `
}

func metaSafe(base string) string {
	img := html.EscapeString(base)
	return ` + "`<meta content=\"`" + ` + img + ` + "`\">`" + `
}

func size(n int) string {
	dim := strconv.Itoa(n)
	return ` + "`<meta content=\"`" + ` + dim + ` + "`\">`" + `
}

func link(href string) string {
	return "<a href='" + href + "'>open</a>"
}

func escapeHTML(s string) string { return html.EscapeString(s) }

func anchor(text string) string {
	return ` + "`<a href=\"`" + ` + escapeHTML(text) + ` + "`\">`" + `
}
`
	assert.Equal(t, []int{10, 24}, ruleLines(t, NewHTMLAttributeUnescapedRule(), code))
}

package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Credentials allowed for any origin: a wildcard, the request's own Origin
// sent back unchecked, a "*" entry that lets every origin through the
// allowlist, a CORS library configured with both.
func TestCORSCredentialsForAnyOrigin(t *testing.T) {
	code := `package middleware

import (
	"net/http"
	"slices"

	"github.com/rs/cors"
)

func events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func reflect(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Vary", "Origin")
}

func reflectNonEmpty(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func allowlisted(w http.ResponseWriter, r *http.Request, allowed []string) {
	origin := r.Header.Get("Origin")
	if origin != "" && slices.Contains(allowed, origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func publicAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

type CORS struct{ allowOrigins []string }

func (m *CORS) isOriginAllowed(origin string) bool {
	for _, allowed := range m.allowOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

func handler() http.Handler {
	return cors.New(cors.Options{AllowedOrigins: []string{"*"}, AllowCredentials: true}).Handler(nil)
}
`
	assert.Equal(t, []int{11, 16, 23, 46, 54}, ruleLines(t, NewCORSCredentialsRule(), code))
}

// An Allow-Origin that changes with the request must say so in Vary: without
// it a cache hands one origin's answer to another.
func TestCORSDynamicOriginWithoutVary(t *testing.T) {
	code := `package middleware

import "net/http"

type CORS struct{ allowed map[string]bool }

func (m *CORS) Handler(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if m.allowed[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}

func (m *CORS) HandlerVary(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if m.allowed[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
}

func fixed(w http.ResponseWriter, site string) {
	w.Header().Set("Access-Control-Allow-Origin", site)
}
`
	assert.Equal(t, []int{10}, ruleLines(t, NewCORSCredentialsRule(), code))
}

package security

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

type fileRule interface {
	AnalyzeFile(ctx *core.FileContext) []*core.Violation
}

func ruleLines(t *testing.T, rule fileRule, code string) []int {
	t.Helper()
	var lines []int
	for _, v := range rule.AnalyzeFile(rulestest.GoFile(t, "middleware.go", code)) {
		lines = append(lines, v.Line)
	}
	slices.Sort(lines)
	return lines
}

// A header a proxy sets is read from any client that sends it: without a
// check that the connection came from the proxy, the client picks its own
// address and scheme. Strict-Transport-Security sent on its word is harmless:
// a browser ignores it on a plain HTTP response.
func TestProxyHeaderTrustReportsUncheckedHeaders(t *testing.T) {
	code := `package middleware

import (
	"net"
	"net/http"
	"strings"
)

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	return r.Header.Get("CF-Visitor") == ` + "`" + `{"scheme":"https"}` + "`" + `
}

func trustedClientIP(r *http.Request, isTrustedProxy func(string) bool) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteIP == "127.0.0.1" || remoteIP == "::1" {
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return realIP
		}
	}
	if !isTrustedProxy(remoteIP) {
		return remoteIP
	}
	return r.Header.Get("X-Forwarded-For")
}

func secureScheme(r *http.Request, behindProxy bool) bool {
	if behindProxy && r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	return r.TLS != nil
}

func logRequest(r *http.Request, logger interface{ Info(string, ...any) }) {
	logger.Info("request", "xff", r.Header.Get("X-Forwarded-For"))
}

func securityHeaders(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
}
`
	assert.Equal(t, []int{10, 14, 25, 28}, ruleLines(t, NewProxyHeaderTrustRule(), code))
}

// Trust turned around: the headers are taken exactly when the connection did
// not come from the local proxy, that is from any client on the internet.
func TestProxyHeaderTrustReportsInvertedCheck(t *testing.T) {
	code := `package middleware

import (
	"net/http"
	"strings"
)

func clientKey(r *http.Request) string {
	remoteIP := r.RemoteAddr[:strings.LastIndex(r.RemoteAddr, ":")]
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if remoteIP != "127.0.0.1" && remoteIP != "::1" {
			parts := strings.Split(xff, ",")
			return "client:" + strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return "client:" + remoteIP
}

func forwardedFor(r *http.Request) string {
	if r.RemoteAddr != "" && !isLoopback(r.RemoteAddr) {
		return r.Header.Get("X-Forwarded-For")
	}
	return ""
}

func isLoopback(addr string) bool { return strings.HasPrefix(addr, "127.") }
`
	assert.Equal(t, []int{10, 21}, ruleLines(t, NewProxyHeaderTrustRule(), code))
}

// The leftmost element of X-Forwarded-For is whatever the client sent: a
// proxy appends the address it saw, so only the rightmost trusted hop is the
// client's own.
func TestProxyHeaderTrustReportsLeftmostForwardedFor(t *testing.T) {
	code := `package middleware

import (
	"net"
	"net/http"
	"strings"
)

func clientIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteIP != "127.0.0.1" {
		return remoteIP
	}
	xff := r.Header.Get("X-Forwarded-For")
	if parts := strings.Split(xff, ","); len(parts) > 0 {
		if first := strings.TrimSpace(parts[0]); first != "" {
			return first
		}
	}
	if first, _, found := strings.Cut(r.Header.Get("X-Forwarded-For"), ","); found {
		return first
	}
	return strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]
}

func lastHop(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteIP != "127.0.0.1" {
		return remoteIP
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	return strings.TrimSpace(parts[len(parts)-1])
}
`
	assert.Equal(t, []int{16, 20, 23}, ruleLines(t, NewProxyHeaderTrustRule(), code))
}

// RemoteAddr is host:port. Split by ":" it breaks on IPv6; kept whole as an
// IP it carries a port that changes with every connection, so a limit or a
// ban keyed on it never repeats.
func TestRemoteAddrMisuse(t *testing.T) {
	code := `package middleware

import (
	"net"
	"net/http"
	"strings"
)

type Session struct{ IP, Agent string }

type limiter interface{ Allow(key string) bool }

func getClientIP(r *http.Request) string {
	if ip := strings.Split(r.RemoteAddr, ":"); len(ip) > 0 {
		return ip[0]
	}
	return r.RemoteAddr
}

func handle(w http.ResponseWriter, r *http.Request, l limiter, visits map[string]int) {
	ip := r.RemoteAddr
	s := Session{IP: r.RemoteAddr, Agent: r.UserAgent()}
	_ = s
	if !l.Allow(ip) {
		return
	}
	visits[r.RemoteAddr]++
	addr := r.RemoteAddr
	_ = strings.SplitN(addr, ":", 2)
}

func hostOf(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	return ip
}

func logIt(r *http.Request, logger interface{ Warn(string, ...any) }) {
	logger.Warn("not found", "remote", r.RemoteAddr)
}
`
	assert.Equal(t, []int{14, 17, 21, 22, 27, 29}, ruleLines(t, NewRemoteAddrMisuseRule(), code))
}

// A redirect built from the Host header sends the client wherever the header
// points: an open redirect and a poisoned cache entry.
func TestHostHeaderRedirect(t *testing.T) {
	code := `package middleware

import (
	"fmt"
	"net/http"
	"strings"
)

func forceHTTPS(w http.ResponseWriter, r *http.Request) {
	httpsURL := "https://" + r.Host + r.RequestURI
	http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
}

func forceHTTPSFormatted(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", fmt.Sprintf("https://%s%s", r.Header.Get("X-Forwarded-Host"), r.URL.Path))
	w.WriteHeader(http.StatusFound)
}

func forceHTTPSChecked(w http.ResponseWriter, r *http.Request, baseDomain string) {
	host := r.Host
	if !strings.HasSuffix(host, baseDomain) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusMovedPermanently)
}

func toCanonical(w http.ResponseWriter, r *http.Request, base string) {
	http.Redirect(w, r, base+r.URL.Path, http.StatusFound)
}
`
	assert.Equal(t, []int{10, 15}, ruleLines(t, NewHostHeaderRedirectRule(), code))
}

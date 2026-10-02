package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The middleware restricts the request only when the restricting claim is
// present: a token without it - a wiring bug, a new kind of user - is let
// through with the widest access.
func TestFailOpen_MissingClaimPassesRequest(t *testing.T) {
	const source = `package svc

import "net/http"

type ctxKey string

const accountKey ctxKey = "account"

func isolation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Context().Value(accountKey)
		if raw == nil {
			next.ServeHTTP(w, r)
			return
		}
		account, ok := raw.(string)
		if !ok || account == "" {
			http.Error(w, "bad account", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func enrich(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(accountKey)
		if user == nil {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("X-User", user.(string))
		next.ServeHTTP(w, r)
	})
}
`
	assert.Equal(t, []int{13}, failOpenLines(t, source))
}

// The body check runs only when the body was read and parsed: a read or
// decode error skips it and the request goes on.
func TestFailOpen_CheckGuardedBySuccessFallsThrough(t *testing.T) {
	const source = `package svc

import (
	"encoding/json"
	"io"
	"net/http"
)

func enforce(next http.Handler, allowed func(string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			var body struct{ Account string }
			if json.Unmarshal(bodyBytes, &body) == nil && body.Account != "" {
				if !allowed(body.Account) {
					http.Error(w, "denied", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func strict(next http.Handler, allowed func(string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		var body struct{ Account string }
		if err := json.Unmarshal(bodyBytes, &body); err == nil {
			w.Header().Set("X-Account", body.Account)
		}
		next.ServeHTTP(w, r)
	})
}
`
	assert.Equal(t, []int{12}, failOpenLines(t, source))
}

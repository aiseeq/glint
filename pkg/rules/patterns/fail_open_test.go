package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func failOpenLines(t *testing.T, source string) []int {
	t.Helper()
	ctx := rulestest.GoFile(t, "svc/svc.go", source)
	return violationLines(NewFailOpenRule().AnalyzeFile(ctx))
}

// A check that cannot be made answers yes: the deployment is active, the user
// exists. The gate it guards opens exactly when the check is broken.
func TestFailOpen_PermissivePredicateAnswersYesOnFailure(t *testing.T) {
	const source = `package svc

import (
	"log/slog"
	"os"
)

type Svc struct {
	users  interface{ Exists(id string) bool }
	logger *slog.Logger
}

func (s *Svc) isActiveDeployment() bool {
	_, err := os.ReadFile("/state")
	if err != nil {
		s.logger.Warn("assuming active", "error", err)
		return true
	}
	return false
}

func (s *Svc) validateUserExists(id string) bool {
	if s.users == nil || id == "" {
		return true
	}
	return s.users.Exists(id)
}

func isOverwritable(rule *string) bool {
	if rule == nil {
		return true
	}
	return *rule == "auto"
}

func (s *Svc) isBlocked() bool {
	_, err := os.ReadFile("/blocklist")
	if err != nil {
		return true
	}
	return false
}

func (s *Svc) shouldRetry() bool {
	_, err := os.ReadFile("/state")
	if err != nil {
		return true
	}
	return false
}
`
	assert.Equal(t, []int{17, 24}, failOpenLines(t, source))
}

// A middleware whose check failed lets the request through; an error branch
// answers with success.
func TestFailOpen_ErrorBranchLetsThroughOrAnswersSuccess(t *testing.T) {
	const source = `package svc

import (
	"log/slog"
	"net/http"
)

type Svc struct {
	logger *slog.Logger
	check  func() (bool, error)
	status func() (string, error)
}

func SendSuccess(w http.ResponseWriter, v any, msg string) {}

func (s *Svc) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, err := s.check()
		if err != nil {
			s.logger.Error("limiter failed", "error", err)
			next.ServeHTTP(w, r)
			return
		}
		if !allowed {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Svc) Complete(w http.ResponseWriter, r *http.Request) {
	status, err := s.status()
	if err != nil {
		s.logger.Error("status check failed", "error", err)
		SendSuccess(w, map[string]string{"status": "processing"}, "status verification failed")
		return
	}
	SendSuccess(w, map[string]string{"status": status}, "done")
}

type AuthStatus struct{ Authenticated bool }

func (s *Svc) AuthStatus(w http.ResponseWriter, r *http.Request) {
	_, err := s.status()
	if err != nil {
		s.logger.Warn("invalid session", "error", err)
		SendSuccess(w, AuthStatus{Authenticated: false}, "not authenticated")
		return
	}
	SendSuccess(w, AuthStatus{Authenticated: true}, "authenticated")
}
`
	assert.Equal(t, []int{21, 36}, failOpenLines(t, source))
}

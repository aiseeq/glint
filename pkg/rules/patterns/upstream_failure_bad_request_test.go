package patterns

import "testing"

// A handler answers 400 for any error of a call that parses the request and
// then fetches from a service: an unavailable source reads to the client as
// its own mistake. Errors told apart with errors.Is, or a call that only
// parses, are fine. A 401 for every error of a call handed the request's
// context (a token check that fetches the signing keys) is the same trap: an
// outage logs the client out. So is a 404 for every error of a read: a
// failed database reads as "no such item".
func TestUpstreamFailureAnsweredAsBadRequest(t *testing.T) {
	assertWanted(t, NewUpstreamFailureAnsweredAsBadRequestRule(), `package routing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Report struct{ Total int }

type Source interface {
	Positions(ctx context.Context) ([]int, error)
}

type Router struct{ source Source }

var ErrInvalidInput = errors.New("invalid input")

func writeValidationProblem(w http.ResponseWriter, r *http.Request, message, detail string) {
	http.Error(w, message+": "+detail, http.StatusBadRequest)
}

func parseSpan(req *http.Request) (time.Time, error) {
	return time.Parse("2006-01-02", req.URL.Query().Get("start"))
}

func (r *Router) assembleSummary(req *http.Request) (*Report, error) {
	if _, err := parseSpan(req); err != nil {
		return nil, fmt.Errorf("parse period: %w", err)
	}
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	positions, err := r.source.Positions(ctx)
	if err != nil {
		return nil, fmt.Errorf("positions: %w", err)
	}
	return &Report{Total: len(positions)}, nil
}

func (r *Router) handleReport(w http.ResponseWriter, req *http.Request) {
	report, err := r.assembleSummary(req)
	if err != nil {
		writeValidationProblem(w, req, "report failed", err.Error()) // want
		return
	}
	_ = report
}

func (r *Router) handleReportSplit(w http.ResponseWriter, req *http.Request) {
	report, err := r.assembleSummary(req)
	if err != nil {
		if errors.Is(err, ErrInvalidInput) {
			writeValidationProblem(w, req, "bad input", err.Error())
			return
		}
		http.Error(w, "source unavailable", http.StatusBadGateway)
		return
	}
	_ = report
}

type Verifier interface {
	Verify(ctx context.Context, token string) (string, error)
}

type AdminRouter struct{ verifier Verifier }

var ErrKeysUnavailable = errors.New("signing keys unavailable")

func decodeToken(token string) (string, error) { return token, nil }

func (r *AdminRouter) verifyAdmin(w http.ResponseWriter, req *http.Request, token string) error {
	email, err := r.verifier.Verify(req.Context(), token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized) // want
		return err
	}
	_ = email
	return nil
}

func (r *AdminRouter) verifyAdminSplit(w http.ResponseWriter, req *http.Request, token string) error {
	email, err := r.verifier.Verify(req.Context(), token)
	if err != nil {
		if errors.Is(err, ErrKeysUnavailable) {
			http.Error(w, "sign-in unavailable", http.StatusServiceUnavailable)
			return err
		}
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return err
	}
	_ = email
	return nil
}

type Session interface {
	UserIDFromContext(ctx context.Context) (string, error)
}

type ClaimRouter struct{ session Session }

func (r *ClaimRouter) claim(w http.ResponseWriter, req *http.Request) {
	userID, err := r.session.UserIDFromContext(req.Context())
	if err != nil {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	_ = userID
}

type RoleRepo interface {
	GetRole(ctx context.Context, name string) (string, error)
}

type RoleRouter struct{ roles RoleRepo }

var ErrRoleNotFound = errors.New("role not found")

func sendNotFoundError(w http.ResponseWriter, r *http.Request, message string) {
	http.Error(w, message, http.StatusNotFound)
}

func (r *RoleRouter) updateRole(w http.ResponseWriter, req *http.Request) {
	role, err := r.roles.GetRole(req.Context(), "admin")
	if err != nil {
		sendNotFoundError(w, req, "role not found") // want
		return
	}
	_ = role
}

func (r *RoleRouter) showRole(w http.ResponseWriter, req *http.Request) {
	role, err := r.roles.GetRole(req.Context(), "admin")
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			http.Error(w, "role not found", http.StatusNotFound)
			return
		}
		http.Error(w, "role read failed", http.StatusInternalServerError)
		return
	}
	_ = role
}

func isCodedError(err error, code string) bool { return err != nil && code != "" }

func (r *RoleRouter) showRoleCoded(w http.ResponseWriter, req *http.Request) {
	role, err := r.roles.GetRole(req.Context(), "admin")
	if err != nil {
		if isCodedError(err, "not_found") {
			http.Error(w, "role not found", http.StatusNotFound)
			return
		}
		http.Error(w, "role read failed", http.StatusInternalServerError)
		return
	}
	_ = role
}

func (r *RoleRouter) showRoleCompared(w http.ResponseWriter, req *http.Request) {
	role, err := r.roles.GetRole(req.Context(), "admin")
	if err != nil {
		if err == ErrRoleNotFound {
			http.Error(w, "role not found", http.StatusNotFound)
			return
		}
		http.Error(w, "role read failed", http.StatusInternalServerError)
		return
	}
	_ = role
}

func (r *AdminRouter) checkToken(w http.ResponseWriter, req *http.Request, token string) {
	email, err := decodeToken(token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	_ = email
}

func (r *Router) handlePeriod(w http.ResponseWriter, req *http.Request) {
	start, err := parseSpan(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = start
}
`)
}

func TestUpstreamFailureAnsweredAsBadRequest_NestedHandlerReportedOnce(t *testing.T) {
	assertWanted(t, NewUpstreamFailureAnsweredAsBadRequestRule(), `package routing

import (
	"context"
	"net/http"
)

type Repo interface { Load(context.Context) (string, error) }
type Router struct { repo Repo }
func (r *Router) load(ctx context.Context) (string, error) { return r.repo.Load(ctx) }

func (r *Router) handle(w http.ResponseWriter, req *http.Request) {
	_ = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		value, err := r.load(req.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized) // want
			return
		}
		_ = value
	})
}
`)
}

func TestUpstreamFailureAnsweredAsBadRequest_MiddlewareClosure(t *testing.T) {
	assertWanted(t, NewUpstreamFailureAnsweredAsBadRequestRule(), `package routing

import (
	"context"
	"net/http"
)

type Repo interface { Load(context.Context) (string, error) }
type Router struct { repo Repo }
func (r *Router) load(ctx context.Context) (string, error) { return r.repo.Load(ctx) }

func (r *Router) middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			value, err := r.load(req.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized) // want
				return
			}
			_ = value
		})
	}
}

func (r *Router) fixed() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			value, err := r.load(req.Context())
			if err != nil {
				http.Error(w, "unavailable", http.StatusInternalServerError)
				return
			}
			_ = value
		})
	}
}

func (r *Router) badInput(w http.ResponseWriter, req *http.Request) {
	if _, err := http.NewRequestWithContext(req.Context(), "!", ""); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func ordinary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "" {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, req)
	})
}
`)
}

func TestUpstreamFailureAnsweredAsBadRequest_ClassifiedSubsetStillAnswersUnauthorized(t *testing.T) {
	assertWanted(t, NewUpstreamFailureAnsweredAsBadRequestRule(), `package routing

import (
	"context"
	"errors"
	"net/http"
)

type TokenValidator interface {
	Validate(context.Context, string) (string, error)
}
type RefreshService interface {
	Refresh(context.Context, string) error
}
type Router struct {
	validator TokenValidator
	refresh RefreshService
}
var ErrStepUp = errors.New("step-up required")
var ErrRevoked = errors.New("session revoked")
var ErrStorageDown = errors.New("storage unavailable")

func (r *Router) tokenCheck(w http.ResponseWriter, req *http.Request, token string) {
	_, err := r.validator.Validate(req.Context(), token)
	if err != nil {
		if errors.Is(err, ErrStepUp) {
			http.Error(w, "step-up required", 428)
			return
		}
		http.Error(w, "invalid token", http.StatusUnauthorized) // want
		return
	}
}

func (r *Router) refreshTokens(w http.ResponseWriter, req *http.Request, token string) {
	err := r.refresh.Refresh(req.Context(), token)
	if err != nil {
		if errors.Is(err, ErrRevoked) {
			http.Error(w, "invalid session", http.StatusUnauthorized) // want
			return
		}
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}
}

func writeStatusError(w http.ResponseWriter, status int, err error) {
	http.Error(w, err.Error(), status)
}

func (r *Router) helperAnswer(w http.ResponseWriter, req *http.Request, token string) {
	err := r.refresh.Refresh(req.Context(), token)
	if err != nil {
		writeStatusError(w, http.StatusBadRequest, err) // want
		return
	}
}

func (r *Router) fixed(w http.ResponseWriter, req *http.Request, token string) {
	_, err := r.validator.Validate(req.Context(), token)
	if err != nil {
		if errors.Is(err, ErrStorageDown) {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
}
`)
}

func TestUpstreamFailureAnsweredAsBadRequest_ClassifiedSwitchesAndServerAnswers(t *testing.T) {
	assertWanted(t, NewUpstreamFailureAnsweredAsBadRequestRule(), `package routing

import (
	"context"
	"errors"
	"net/http"
)

type Repo interface { Load(context.Context) error }
type Router struct { repo Repo }
var ErrDisabled = errors.New("disabled")
var ErrLimited = errors.New("limited")
var ErrMissing = errors.New("missing")
func writeValidationProblem(http.ResponseWriter, *http.Request, string) {}
func answerFault(http.ResponseWriter, int, string) {}
func writeInternalServerFault(http.ResponseWriter, *http.Request, error) {}
func respondJSONFault(http.ResponseWriter, int, string) {}
func writeAuthUnavailable(http.ResponseWriter) {}

func (r *Router) byConditions(w http.ResponseWriter, req *http.Request) {
	err := r.repo.Load(req.Context())
	if err != nil {
		switch {
		case errors.Is(err, ErrDisabled): writeValidationProblem(w, req, "disabled")
		case errors.Is(err, ErrLimited): answerFault(w, http.StatusTooManyRequests, "limited")
		default: writeInternalServerFault(w, req, err)
		}
		return
	}
}

func (r *Router) byErrorValue(w http.ResponseWriter, req *http.Request) {
	err := r.repo.Load(req.Context())
	if err != nil {
		switch err {
		case ErrMissing: writeValidationProblem(w, req, "missing")
		default: respondJSONFault(w, http.StatusBadGateway, "failed")
		}
		return
	}
}

func (r *Router) withUnavailableHelper(w http.ResponseWriter, req *http.Request) {
	err := r.repo.Load(req.Context())
	if err != nil {
		if errors.Is(err, ErrDisabled) { writeValidationProblem(w, req, "disabled"); return }
		if errors.Is(err, ErrMissing) { writeAuthUnavailable(w); return }
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
}

func (r *Router) fallbackServerHelper(w http.ResponseWriter, req *http.Request) {
	err := r.repo.Load(req.Context())
	if err != nil {
		if errors.Is(err, ErrDisabled) { http.Error(w, "disabled", http.StatusUnauthorized); return }
		writeInternalServerFault(w, req, err)
		return
	}
}

func routeError(w http.ResponseWriter, req *http.Request, logger any, err error, message string) {}

func (r *Router) delegatedError(w http.ResponseWriter, req *http.Request) {
	err := r.repo.Load(req.Context())
	if err != nil {
		if errors.Is(err, ErrDisabled) { writeValidationProblem(w, req, "disabled"); return }
		routeError(w, req, nil, err, "operation failed")
		return
	}
}

func (r *Router) byErrorType(w http.ResponseWriter, req *http.Request) {
	err := r.repo.Load(req.Context())
	if err != nil {
		switch err.(type) {
		case error: writeValidationProblem(w, req, "invalid")
		default: writeInternalServerFault(w, req, err)
		}
		return
	}
}
`)
}

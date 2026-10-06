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

func sendValidationError(w http.ResponseWriter, r *http.Request, message, detail string) {
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
		sendValidationError(w, req, "report failed", err.Error()) // want
		return
	}
	_ = report
}

func (r *Router) handleReportSplit(w http.ResponseWriter, req *http.Request) {
	report, err := r.assembleSummary(req)
	if err != nil {
		if errors.Is(err, ErrInvalidInput) {
			sendValidationError(w, req, "bad input", err.Error())
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

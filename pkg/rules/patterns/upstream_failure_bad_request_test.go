package patterns

import "testing"

// A handler answers 400 for any error of a call that parses the request and
// then fetches from a service: an unavailable source reads to the client as
// its own mistake. Errors told apart with errors.Is, or a call that only
// parses, are fine.
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

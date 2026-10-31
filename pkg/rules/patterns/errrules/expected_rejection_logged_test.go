package errrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A duplicate the operator is told about in words is an ordinary refusal,
// yet the ERROR line written before the branch picks it out raises the same
// alert as a broken database.
func TestExpectedRejectionLoggedAsError(t *testing.T) {
	files := map[string]string{
		"admin/tariffs.go": `package admin

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

var ErrConflict = errors.New("conflict")

type Code string

const CodeConflict Code = "conflict"

func IsBusinessError(err error, code Code) bool { return err != nil && code != "" }

type store interface {
	Create(ctx context.Context, name string) error
	Delete(ctx context.Context, id int) error
	Rename(ctx context.Context, id int, name string) error
}

type Admin struct {
	logger *slog.Logger
	store  store
}

func (a *Admin) redirect(w http.ResponseWriter, r *http.Request, msg string) {}

func (a *Admin) handleAdd(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Create(r.Context(), "x"); err != nil {
		a.logger.Error("failed to create tariff", "error", err) // want expected-rejection-logged-as-error
		if IsBusinessError(err, CodeConflict) {
			a.redirect(w, r, "a tariff for this corridor exists")
			return
		}
		a.redirect(w, r, "failed: "+err.Error())
		return
	}
}

func (a *Admin) handleDelete(w http.ResponseWriter, r *http.Request) {
	err := a.store.Delete(r.Context(), 1)
	if err != nil {
		a.logger.Error("failed to delete tariff", "error", err) // want expected-rejection-logged-as-error
		if errors.Is(err, ErrConflict) {
			a.redirect(w, r, "the tariff is in use")
			return
		}
		a.redirect(w, r, "failed")
		return
	}
}

func (a *Admin) handleCreateFixed(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Create(r.Context(), "x"); err != nil {
		if IsBusinessError(err, CodeConflict) {
			a.logger.Warn("tariff exists", "error", err)
			a.redirect(w, r, "a tariff for this corridor exists")
			return
		}
		a.logger.Error("failed to create tariff", "error", err)
		a.redirect(w, r, "failed")
		return
	}
}

// handleRename tells nothing apart after the log: every failure is one.
func (a *Admin) handleRename(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Rename(r.Context(), 1, "y"); err != nil {
		a.logger.Error("failed to rename", "error", err)
		if errors.Is(err, context.Canceled) {
			return
		}
		a.redirect(w, r, "failed")
	}
}
`,
	}
	violations, err := NewExpectedRejectionLoggedAsErrorRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "expected-rejection-logged-as-error"), patterntest.FoundLines(violations))
}

func TestExpectedRejectionLoggedAsErrorSwitchForms(t *testing.T) {
	files := map[string]string{
		"handler.go": `package handler

import (
	"errors"
	"log/slog"
	"net/http"
)

var errRateMissing = errors.New("missing")
var errOther = errors.New("other")

type Handler struct { logger *slog.Logger }

func answerWithStatus(http.ResponseWriter, int, string) {}
func newRequestRefusedError(int, string) error { return nil }

func (h *Handler) read(w http.ResponseWriter, err error) {
	if err != nil {
		h.logger.Error("read failed", "error", err) // want expected-rejection-logged-as-error
		switch {
		case errors.Is(err, errRateMissing):
			answerWithStatus(w, http.StatusNotFound, err.Error())
		default:
			answerWithStatus(w, http.StatusInternalServerError, "failed")
		}
	}
}

func (h *Handler) readWithoutClientAnswer(w http.ResponseWriter, err error) {
	if err != nil {
		h.logger.Error("read failed", "error", err)
		switch {
		case errors.Is(err, errRateMissing):
			answerWithStatus(w, http.StatusInternalServerError, "failed")
		default:
			answerWithStatus(w, http.StatusInternalServerError, "failed")
		}
	}
}

func (h *Handler) retry(state int) error {
	switch state {
	case 1:
		h.logger.Error("request cannot be retried")
		return newRequestRefusedError(http.StatusConflict, "retry manually")
	default:
		h.logger.Error("unexpected state")
		return errors.New("failed")
	}
}

func (h *Handler) retryWithServerError(state int) error {
	switch state {
	case 1:
		h.logger.Error("unexpected failure")
		return newRequestRefusedError(http.StatusInternalServerError, "failed")
	default:
		return nil
	}
}

func (h *Handler) retryWithUnderlyingError(state int, err error) error {
	switch state {
	case 1:
		h.logger.Error("unexpected failure", "error", err)
		return newRequestRefusedError(http.StatusConflict, err.Error())
	default:
		return nil
	}
}
`,
	}
	violations, err := NewExpectedRejectionLoggedAsErrorRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "expected-rejection-logged-as-error"), patterntest.FoundLines(violations))
}

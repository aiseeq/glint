package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
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

func IsDomainError(err error, code Code) bool { return err != nil && code != "" }

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

func (a *Admin) handleCreate(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Create(r.Context(), "x"); err != nil {
		a.logger.Error("failed to create tariff", "error", err) // want expected-rejection-logged-as-error
		if IsDomainError(err, CodeConflict) {
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
		if IsDomainError(err, CodeConflict) {
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
	assert.Equal(t, wantedLines(files, "expected-rejection-logged-as-error"), foundLines(violations))
}

package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A handler logs a failed load at ERROR and goes on to render with what the
// call returned: the operator gets a page with an empty list and no word of
// the failure, while the same handler answers 500 for its other loads.
func TestHandlerErrorOnlyLogged(t *testing.T) {
	files := map[string]string{
		"admin/pages.go": `package admin

import (
	"context"
	"log/slog"
	"net/http"
)

type Project struct{ ID int }

type repo interface {
	All(ctx context.Context) ([]Project, error)
	Spreads(ctx context.Context, id int) (map[string]string, error)
	Count(ctx context.Context) (int, error)
}

type Admin struct {
	logger   *slog.Logger
	projects repo
}

func (a *Admin) render(w http.ResponseWriter, name string, data any) {}

func (a *Admin) handleUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	projects, err := a.projects.All(ctx)
	if err != nil { // want handler-error-only-logged
		a.logger.Error("failed to get projects", "error", err)
	}
	spreads, err := a.projects.Spreads(ctx, 1)
	if err != nil {
		a.logger.Error("failed to load spreads", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	a.render(w, "upload.html", map[string]any{"projects": projects, "spreads": spreads})
}

// handleOptional degrades on purpose and says so at WARN.
func (a *Admin) handleOptional(w http.ResponseWriter, r *http.Request) {
	count, err := a.projects.Count(r.Context())
	if err != nil {
		a.logger.Warn("count unavailable", "error", err)
	}
	a.render(w, "count.html", count)
}

// handleUnused logs a failure of a value nothing reads afterwards.
func (a *Admin) handleUnused(w http.ResponseWriter, r *http.Request) {
	_, err := a.projects.Count(r.Context())
	if err != nil {
		a.logger.Error("count failed", "error", err)
	}
	a.render(w, "plain.html", nil)
}

// refresh is no handler: nobody is waiting for an answer.
func (a *Admin) refresh(ctx context.Context) []Project {
	projects, err := a.projects.All(ctx)
	if err != nil {
		a.logger.Error("refresh failed", "error", err)
	}
	return projects
}
`,
	}
	violations, err := NewHandlerErrorOnlyLoggedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "handler-error-only-logged"), foundLines(violations))
}

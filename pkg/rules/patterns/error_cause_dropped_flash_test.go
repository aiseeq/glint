package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A redirect with an error flash that names a cause nobody checked: a delete
// that failed on a lost connection tells the operator the project still has
// data. A flash carrying the error's own text, and a success flash, are
// left alone.
func TestErrorCauseDropped_GoFlashRedirectWithFixedCause(t *testing.T) {
	const source = `package admin

func (a *Admin) deleteProject(w http.ResponseWriter, r *http.Request, id int64) {
	if err := a.repo.Delete(r.Context(), id); err != nil {
		a.logger.Error("delete project", "error", err)
		a.redirectProjects(w, r, "error", "Cannot delete project with existing pricing configs or transactions")
		return
	}
	a.redirectProjects(w, r, "success", "Project deleted")
}

func (a *Admin) archiveProject(w http.ResponseWriter, r *http.Request, id int64) {
	if err := a.repo.Archive(r.Context(), id); err != nil {
		a.redirectProjects(w, r, "error", "Failed to archive: "+err.Error())
		return
	}
}
`
	violations := NewErrorCauseDroppedRule().AnalyzeFile(rulestest.GoFile(t, "admin/projects.go", source))
	assert.Equal(t, []int{6}, violationLines(violations))
}

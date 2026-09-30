package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A status written as a string literal in a project that declares its
// statuses as constants: the literal does not follow a renamed value, and the
// reader cannot tell which set it belongs to - "confirmed" of deposits ended
// up in the ledger, whose statuses say "completed".
func TestStatusLiteral(t *testing.T) {
	files := map[string]string{
		"models/status.go": `package models

type LedgerStatus string

const (
	LedgerStatusPending   LedgerStatus = "pending"
	LedgerStatusCompleted LedgerStatus = "completed"
	LedgerStatusFailed    LedgerStatus = "failed"
)

type TransferStatus string

const (
	TransferStatusPending   TransferStatus = "pending"
	TransferStatusConfirmed TransferStatus = "confirmed"
)

type Entry struct {
	Status *string
	Kind   string
}

type Order struct{ Status LedgerStatus }
`,
		"ledger/ledger.go": `package ledger

import (
	"fmt"

	"example.com/rulestest/models"
)

type Repo struct{}

func (Repo) Count(status, kind string) int { return len(status) + len(kind) }

func Build(r Repo, e *models.Entry, o *models.Order) (int, error) {
	confirmedStatus := "confirmed" // want status-literal
	e.Status = &confirmedStatus
	o.Status = "completed" // want status-literal
	order := models.Order{Status: "failed"} // want status-literal
	_ = order
	if o.Status == "pending" { // want status-literal
		return 0, nil
	}
	switch string(o.Status) {
	case "active":
		return 1, nil
	case string(models.LedgerStatusFailed):
		return 2, nil
	}
	validStatuses := map[string]bool{"pending": true, "done": true} // want status-literal
	health := struct{ Status string }{Status: "healthy"}
	_ = health
	_ = validStatuses
	kind := "withdrawal"
	_ = kind
	e.Kind = "withdrawal"
	if e.Kind == "deposit" {
		return 3, fmt.Errorf("status %s", "unknown")
	}
	return r.Count("confirmed", "withdrawal"), nil // want status-literal
}

func mapProviderStatus(s string) string {
	if s == "" {
		return ""
	}
	return "confirmed" // want status-literal
}
`,
	}
	violations, err := NewStatusLiteralRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "status-literal"), foundLines(violations))
}

// Without status constants there is no set a literal could bypass.
func TestStatusLiteralNoEnums(t *testing.T) {
	files := map[string]string{
		"app/app.go": `package app

type Job struct{ Status string }

func Mark(j *Job) { j.Status = "done" }
`,
	}
	violations, err := NewStatusLiteralRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

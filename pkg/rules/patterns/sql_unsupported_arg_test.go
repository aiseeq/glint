package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// lib/pq encodes no slice but []byte: the permissions list fails the
// update on every run, "unsupported type []string".
func TestSQLUnsupportedArg(t *testing.T) {
	files := map[string]string{
		"go.mod":                "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/lib/pq v1.0.0\n\nreplace github.com/lib/pq => ./third_party/pq\n",
		"third_party/pq/go.mod": "module github.com/lib/pq\n\ngo 1.24\n",
		"third_party/pq/pq.go": `package pq

import "database/sql/driver"

type StringArray []string

func (a StringArray) Value() (driver.Value, error) { return nil, nil }

func Array(a any) any { return a }
`,
		"storage/sessions.go": `package storage

import (
	"context"
	"database/sql"
	"encoding/json"

	_ "github.com/lib/pq"
	"github.com/lib/pq"
)

type Session struct {
	ID          string
	Permissions []string
	Labels      map[string]string
	Token       []byte
}

func Update(ctx context.Context, db *sql.DB, s *Session) error {
	_, err := db.ExecContext(ctx, "UPDATE sessions SET permissions = $1, labels = $2, token = $3 WHERE id = $4",
		s.Permissions, s.Labels, s.Token, s.ID)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(s.Permissions)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "UPDATE sessions SET permissions = $1, roles = $2, scopes = $3 WHERE id = $4",
		encoded, pq.Array(s.Permissions), pq.StringArray(s.Permissions), s.ID)
	return err
}

func Delete(ctx context.Context, db *sql.DB, args []any) error {
	_, err := db.ExecContext(ctx, "DELETE FROM sessions WHERE id = $1", args...)
	return err
}
`,
	}
	violations, err := NewSQLUnsupportedArgRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"storage/sessions.go:21", "storage/sessions.go:21"}, foundLines(violations))
}

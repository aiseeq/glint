package dbrules

import (
	"maps"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const constraintMigration = `
CREATE TABLE tariffs (
    id SERIAL PRIMARY KEY,
    project_id INT NOT NULL,
    corridor TEXT NOT NULL,
    CONSTRAINT tariffs_project_corridor_key UNIQUE (project_id, corridor)
);
CREATE TABLE operators (id SERIAL PRIMARY KEY, login TEXT NOT NULL);
CREATE TABLE orders (
    id UUID PRIMARY KEY,
    tariff_id INT REFERENCES tariffs(id),
    operator_id INT REFERENCES operators(id) ON DELETE SET NULL,
    note TEXT
);
`

// Deleting a tariff the orders still point at, or creating a second tariff
// for a corridor, fails on a constraint the operator could be told about in
// words; with no check of the database error the failure comes back as a
// generic server error.
func TestSQLConstraintViolationUnmapped(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": constraintMigration,
		"storage/tariffs.go": `package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrConflict = errors.New("conflict")

// PgError stands for the driver's error type.
type PgError struct{ Code string }

func (e *PgError) Error() string { return e.Code }

type Repo struct{ db *sql.DB }

func (r *Repo) Delete(ctx context.Context, id int) error {
	query := ` + "`DELETE FROM tariffs WHERE id = $1`" + ` // want sql-constraint-violation-unmapped
	if _, err := r.db.ExecContext(ctx, query, id); err != nil {
		return fmt.Errorf("delete tariff: %w", err)
	}
	return nil
}

func (r *Repo) Create(ctx context.Context, projectID int, corridor string) (int, error) {
	var id int
	err := r.db.QueryRowContext(ctx, ` + "`INSERT INTO tariffs (project_id, corridor) VALUES ($1, $2) RETURNING id`" + `, projectID, corridor).Scan(&id) // want sql-constraint-violation-unmapped
	return id, err
}

func (r *Repo) CreateMapped(ctx context.Context, projectID int, corridor string) error {
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO tariffs (project_id, corridor) VALUES ($1, $2)`" + `, projectID, corridor)
	return mapWriteError(err)
}

func (r *Repo) DeleteChecked(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, ` + "`DELETE FROM tariffs WHERE id = $1`" + `, id)
	var pgErr *PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrConflict
	}
	return err
}

func (r *Repo) DeleteOperator(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, ` + "`DELETE FROM operators WHERE id = $1`" + `, id)
	return err
}

func (r *Repo) DeleteOrder(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, ` + "`DELETE FROM orders WHERE id = $1`" + `, id)
	return err
}

func (r *Repo) AddOrder(ctx context.Context, id string, note string) error {
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO orders (id, note) VALUES ($1, $2)`" + `, id, note)
	return err
}

// Import runs from a job: its duplicate reaches no user.
func (r *Repo) Import(ctx context.Context, projectID int) error {
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO tariffs (project_id, corridor) VALUES ($1, 'x')`" + `, projectID)
	return err
}

func mapWriteError(err error) error {
	var pgErr *PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return err
}
`,
		"web/handlers.go": `package web

import (
	"context"
	"errors"
	"net/http"

	"example.com/rulestest/storage"
)

type tariffStore interface {
	Delete(ctx context.Context, id int) error
	CreateMapped(ctx context.Context, projectID int, corridor string) error
	DeleteChecked(ctx context.Context, id int) error
	DeleteOperator(ctx context.Context, id int) error
	DeleteOrder(ctx context.Context, id string) error
	AddOrder(ctx context.Context, id string, note string) error
}

type Server struct {
	store tariffStore
	repo  *storage.Repo
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.Context(), 1); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleItemCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := s.create(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) create(ctx context.Context) (int, error) {
	return s.repo.Create(ctx, 1, "x")
}

func (s *Server) handleOthers(w http.ResponseWriter, r *http.Request) {
	_ = s.store.CreateMapped(r.Context(), 1, "x")
	_ = s.store.DeleteChecked(r.Context(), 1)
	_ = s.store.DeleteOperator(r.Context(), 1)
	_ = s.store.DeleteOrder(r.Context(), "x")
	_ = s.store.AddOrder(r.Context(), "x", "y")
}

// handleCreateConflict tells the duplicate apart.
func (s *Server) handleCreateConflict(w http.ResponseWriter, r *http.Request) {
	if _, err := s.repo.Create(r.Context(), 1, "x"); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			http.Error(w, "exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) importAll(ctx context.Context) error {
	return s.repo.Import(ctx, 1)
}
`,
	}
	violations, err := NewSQLConstraintViolationUnmappedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "sql-constraint-violation-unmapped"), patterntest.FoundLines(violations))
}

const replaceSetMigration = `
CREATE TABLE staff (id SERIAL PRIMARY KEY, email TEXT NOT NULL UNIQUE);
CREATE TABLE staff_roles (
    staff_id INT NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    PRIMARY KEY (staff_id, role)
);
CREATE TABLE fee_schedules (id SERIAL PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE fee_links (fee_schedule_id INT NOT NULL REFERENCES fee_schedules(id), tx TEXT NOT NULL);
`

func TestSQLConstraintViolationUnmappedStillReportsAtInsert(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": `CREATE TABLE entries (id UUID PRIMARY KEY, document_number TEXT NOT NULL UNIQUE);`,
		"storage/entries.go": `package storage

import (
	"context"
	"database/sql"
)

type Entry struct { DocumentNumber string }
type Repo struct { db *sql.DB }

func (r *Repo) Add(ctx context.Context, entry Entry) error {
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO entries (document_number) VALUES ($1)`" + `, entry.DocumentNumber) // want sql-constraint-violation-unmapped
	return err
}
`,
		"web/handler.go": `package web

import (
	"crypto/rand"
	"fmt"
	"net/http"

	"example.com/rulestest/storage"
)

type Server struct { repo *storage.Repo }

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var id [16]byte
	_, _ = rand.Read(id[:])
	number := fmt.Sprintf("REC-%08X", id[:4])
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: number}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
`,
	}
	violations, err := NewSQLConstraintViolationUnmappedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "sql-constraint-violation-unmapped"), patterntest.FoundLines(violations))
}

func TestTruncatedRandomIDAsUniqueNumber(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": `CREATE TABLE entries (id UUID PRIMARY KEY, document_number TEXT NOT NULL UNIQUE);`,
		"storage/entries.go": `package storage
import ("context"; "database/sql")
type Entry struct { DocumentNumber string }
type Repo struct { db *sql.DB }
func (r *Repo) Add(ctx context.Context, entry Entry) error {
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO entries (document_number) VALUES ($1)`" + `, entry.DocumentNumber) // want sql-constraint-violation-unmapped
	return err
}`,
		"web/handler.go": `package web
import ("crypto/rand"; "fmt"; "net/http"; "example.com/rulestest/storage")
type Server struct { repo *storage.Repo }
func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var id [16]byte
	_, _ = rand.Read(id[:])
	number := fmt.Sprintf("REC-%08X", id[:4]) // want truncated-random-id-as-unique-number
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: number}); err != nil { http.Error(w, err.Error(), 500) }
}`,
	}
	rule := NewTruncatedRandomIDAsUniqueNumberRule()
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, rule.Name()), patterntest.FoundLines(violations))
}

func TestSQLConstraintViolationUnmappedIgnoresSafeUniqueIdentifiers(t *testing.T) {
	base := map[string]string{
		"storage/migrations/001_init.up.sql": `CREATE TABLE entries (id UUID PRIMARY KEY, document_number TEXT NOT NULL UNIQUE);`,
		"storage/entries.go": `package storage

import (
	"context"
	"database/sql"
)

type Entry struct { DocumentNumber string }
type Repo struct { db *sql.DB }

func (r *Repo) Add(ctx context.Context, entry Entry) error {
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO entries (document_number) VALUES ($1)`" + `, entry.DocumentNumber) // want sql-constraint-violation-unmapped
	return err
}
`,
		"web/handler.go": `package web

import (
	"crypto/rand"
	"fmt"
	"net/http"

	"example.com/rulestest/storage"
)

type Server struct { repo *storage.Repo }

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var id [16]byte
	_, _ = rand.Read(id[:])
	number := fmt.Sprintf("REC-%08X", id[:4])
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: number}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
`,
	}
	cases := map[string]string{
		"retries unique conflicts": `for attempt := 0; attempt < 3; attempt++ {
		var id [16]byte
		_, _ = rand.Read(id[:])
		number := fmt.Sprintf("REC-%08X", id[:4])
		err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: number})
		if err == nil { return }
		if isUniqueConflict(err) { continue }
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
`,
		"keeps the full random value": `var id [16]byte
	_, _ = rand.Read(id[:])
	number := fmt.Sprintf("%x", id[:])
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: number}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
`,
		"ignores an unrelated truncated random value": `var id [16]byte
	_, _ = rand.Read(id[:])
	_ = id[:4]
	number := fmt.Sprintf("%x", id[:])
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: number}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
`,
		"allows database conflict handling": `var id [16]byte
	_, _ = rand.Read(id[:])
	number := fmt.Sprintf("REC-%08X", id[:4])
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: number}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
`,
		"does not truncate a nonrandom value": `id := []byte("fixed-value")
	number := fmt.Sprintf("REC-%08X", id[:4])
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: number}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			files := make(map[string]string, len(base))
			maps.Copy(files, base)
			files["web/handler.go"] = strings.Replace(files["web/handler.go"], `	var id [16]byte
	_, _ = rand.Read(id[:])
	number := fmt.Sprintf("REC-%08X", id[:4])
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: number}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
`, body, 1)
			if name == "retries unique conflicts" {
				files["web/handler.go"] = strings.Replace(files["web/handler.go"], "func (s *Server) create", "func isUniqueConflict(error) bool { return false }\n\nfunc (s *Server) create", 1)
			}
			if name == "allows database conflict handling" {
				files["storage/entries.go"] = strings.Replace(files["storage/entries.go"], "VALUES ($1)`", "VALUES ($1) ON CONFLICT DO NOTHING`", 1)
			}
			if name == "does not truncate a nonrandom value" {
				files["web/handler.go"] = strings.Replace(files["web/handler.go"], "\t\"crypto/rand\"\n", "", 1)
			}
			project := rulestest.Project(t, files)
			violations, err := NewSQLConstraintViolationUnmappedRule().AnalyzeGoProject(project)
			require.NoError(t, err)
			for _, finding := range patterntest.FoundLines(violations) {
				assert.False(t, strings.HasPrefix(finding, "web/handler.go:"), finding)
			}
			truncated, err := NewTruncatedRandomIDAsUniqueNumberRule().AnalyzeGoProject(project)
			require.NoError(t, err)
			assert.Empty(t, truncated)
		})
	}
}

// A child row keyed by a parent the function has just inserted, a set of
// rows replaced after a DELETE of the same table, a parent deleted after the
// rows pointing at it: the function itself rules the violation out.
func TestSQLConstraintViolationUnmappedRuledOutInFunction(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": replaceSetMigration,
		"storage/staff.go": `package storage

import (
	"context"
	"database/sql"
)

type Repo struct{ db *sql.Tx }

// EnsureSeeded gives a staff member it has just created a role.
func (r *Repo) EnsureSeeded(ctx context.Context, email, role string) error {
	var id int
	if err := r.db.QueryRowContext(ctx, ` + "`INSERT INTO staff (email) VALUES ($1) ON CONFLICT (email) DO NOTHING RETURNING id`" + `, email).Scan(&id); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO staff_roles (staff_id, role) VALUES ($1, $2)`" + `, id, role)
	return err
}

// ReplaceRoles replaces the set of roles of one staff member.
func (r *Repo) ReplaceRoles(ctx context.Context, id int, roles map[string]bool) error {
	if _, err := r.db.ExecContext(ctx, ` + "`DELETE FROM staff_roles WHERE staff_id = $1`" + `, id); err != nil {
		return err
	}
	for role := range roles {
		if _, err := r.db.ExecContext(ctx, ` + "`INSERT INTO staff_roles (staff_id, role) VALUES ($1, $2)`" + `, id, role); err != nil {
			return err
		}
	}
	return nil
}

// AssignRole inserts one role; what makes it unique is not seen here.
func (r *Repo) AssignRole(ctx context.Context, id int, role string) error {
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO staff_roles (staff_id, role) VALUES ($1, $2)`" + `, id, role) // want sql-constraint-violation-unmapped
	return err
}

// DeleteFee removes the links to a schedule before the schedule.
func (r *Repo) DeleteFee(ctx context.Context, id int) error {
	if _, err := r.db.ExecContext(ctx, ` + "`DELETE FROM fee_links WHERE fee_schedule_id = $1`" + `, id); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, ` + "`DELETE FROM fee_schedules WHERE id = $1`" + `, id)
	return err
}

func (r *Repo) DeleteFeeOnly(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, ` + "`DELETE FROM fee_schedules WHERE id = $1`" + `, id) // want sql-constraint-violation-unmapped
	return err
}
`,
		"web/handlers.go": `package web

import (
	"net/http"

	"example.com/rulestest/storage"
)

type Server struct{ repo *storage.Repo }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.repo.EnsureSeeded(ctx, "a", "admin"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if err := s.repo.ReplaceRoles(ctx, 1, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if err := s.repo.AssignRole(ctx, 1, "x"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if err := s.repo.DeleteFee(ctx, 1); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if err := s.repo.DeleteFeeOnly(ctx, 1); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
`,
	}
	violations, err := NewSQLConstraintViolationUnmappedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "sql-constraint-violation-unmapped"), patterntest.FoundLines(violations))
}

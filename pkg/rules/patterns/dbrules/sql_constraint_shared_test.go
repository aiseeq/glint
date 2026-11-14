package dbrules

import (
	"go/ast"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checksConstraintsEager is the check of a function against the names of
// every function of its file matched up front: the path constraintChecks
// replaces with matching on demand.
func checksConstraintsEager(ctx *core.FileContext, fn *ast.FuncDecl) bool {
	checkers := make(map[string]bool)
	for _, decl := range ctx.GoAST.Decls {
		if decl, ok := decl.(*ast.FuncDecl); ok && decl.Body != nil && constraintCheck.MatchString(funcText(ctx, decl)) {
			checkers[decl.Name.Name] = true
		}
	}
	if constraintCheck.MatchString(funcText(ctx, fn)) {
		return true
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		name := helpers.CalleeName(call)
		if checkers[name] || constraintMapper.MatchString(name) {
			found = true
		}
		return !found
	})
	return found
}

func TestConstraintChecksMatchEagerScan(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"storage/a.go": `package storage
import "errors"
type PgError struct{ Code string }
func (e *PgError) Error() string { return e.Code }
type A struct{}
type B struct{}
func (A) inspect(err error) bool { var pg *PgError; return errors.As(err, &pg) }
func (B) inspect(err error) bool { return err != nil }
func itself(err error) bool { return err != nil && err.Error() == "23505" }
func viaChecker(err error) bool { return A{}.inspect(err) }
func viaFunc(err error) bool { return isDuplicate(err) }
func isDuplicate(err error) bool { return err != nil && err.Error() == "duplicate key" }
func viaMapper(err error) error { return mapPgErr(err) }
func mapPgErr(err error) error { return err }
func plain(err error) error { return err }
func viaOtherFile(err error) bool { return looksAtCode(err) }
// external has no body (assembly, linkname): it is no checker, whatever its
// signature names.
func external(e *PgError) bool
func viaExternal(err error) bool { return external(nil) }
`,
		"storage/b.go": `package storage
func looksAtCode(err error) bool { return err != nil && err.Error() == "23503" }
func callsPlain(err error) error { return plain(err) }
`,
	})
	checks := newConstraintChecks()
	results := map[string]bool{}
	for _, file := range project.Files {
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			want := checksConstraintsEager(file, fn)
			assert.Equal(t, want, checks.checksConstraints(file, fn), "%s in %s", fn.Name.Name, file.RelPath)
			results[fn.Name.Name] = results[fn.Name.Name] || want
		}
	}
	assert.True(t, results["itself"])
	assert.True(t, results["viaChecker"], "a method of the name checks, though the other receiver's does not")
	assert.True(t, results["viaFunc"])
	assert.True(t, results["viaMapper"])
	assert.False(t, results["plain"])
	assert.False(t, results["callsPlain"])
	assert.True(t, results["looksAtCode"])
	assert.False(t, results["viaOtherFile"], "a checker of another file does not count")
	assert.False(t, results["viaExternal"], "a function without a body checks nothing")
	assert.Contains(t, results, "viaExternal")
}

// The two rules start from the same refusals: one project run builds them
// once, and each rule reports what it reports on a project of its own.
func TestProjectRefusalsSharedByBothRules(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": `CREATE TABLE entries (id UUID PRIMARY KEY, document_number TEXT NOT NULL UNIQUE);
CREATE TABLE notes (id SERIAL PRIMARY KEY, entry_id UUID NOT NULL REFERENCES entries(id));`,
		"storage/entries.go": `package storage
import ("context"; "database/sql")
type Entry struct { DocumentNumber string }
type Repo struct { db *sql.DB }
func (r *Repo) Add(ctx context.Context, entry Entry) error {
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO entries (document_number) VALUES ($1)`" + `, entry.DocumentNumber) // want sql-constraint-violation-unmapped
	return err
}
func (r *Repo) Remove(ctx context.Context, id string) error {
	var found string
	if err := r.db.QueryRowContext(ctx, ` + "`SELECT id FROM entries WHERE id = $1`" + `, id).Scan(&found); err != nil { return err }
	_, err := r.db.ExecContext(ctx, ` + "`DELETE FROM entries WHERE id = $1`" + `, id) // want sql-constraint-violation-unmapped
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
}
func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	if err := s.repo.Remove(r.Context(), r.URL.Query().Get("id")); err != nil { http.Error(w, err.Error(), 500) }
}`,
	}
	constraint, truncated := NewSQLConstraintViolationUnmappedRule(), NewTruncatedRandomIDAsUniqueNumberRule()

	shared := rulestest.Project(t, files)
	first, err := projectRefusals(shared, constraint.BaseRule)
	require.NoError(t, err)
	second, err := projectRefusals(shared, truncated.BaseRule)
	require.NoError(t, err)
	assert.Same(t, first, second, "both rules read one build of the refusals")
	require.Len(t, first.funcs, 2)
	require.Len(t, first.conflicts, 1)

	for _, rule := range []interface {
		Name() string
		AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
	}{constraint, truncated} {
		together, err := rule.AnalyzeGoProject(shared)
		require.NoError(t, err)
		alone, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
		require.NoError(t, err)
		assert.Equal(t, patterntest.WantedLines(files, rule.Name()), patterntest.FoundLines(together), rule.Name())
		assert.Equal(t, patterntest.FoundLines(alone), patterntest.FoundLines(together), rule.Name())
	}

	// A run reporting on the handlers alone reports no DELETE of the storage
	// file, which it reads for the index.
	scopedProject := rulestest.Project(t, files)
	for _, file := range scopedProject.Files {
		if file.RelPath == "web/handler.go" {
			scopedProject.SetReportFiles([]*core.FileContext{file})
		}
	}
	require.True(t, scopedProject.HasReportScope())
	scoped, err := constraint.AnalyzeGoProject(scopedProject)
	require.NoError(t, err)
	for _, v := range scoped {
		assert.NotContains(t, v.Message, "deleted", "%s:%d", v.File, v.Line)
	}

	// Other migration directories are another schema: their refusals are
	// built apart.
	other := NewTruncatedRandomIDAsUniqueNumberRule()
	require.NoError(t, other.Configure(map[string]any{"migrations": "elsewhere"}))
	third, err := projectRefusals(shared, other.BaseRule)
	require.NoError(t, err)
	assert.NotSame(t, first, third)
}

// The words in front of the regular expression only skip texts it cannot
// match: on every text the answer is the expression's own.
func TestMatchesConstraintCheckAgreesWithExpression(t *testing.T) {
	texts := []string{
		"", "return err", "var pgErr *PgError", "if e, ok := err.(*pq.Error); ok {}", "pq Error", `code == "23505"`, `code == "23503"`,
		`code == "23P01"`, "23505 without quotes", "pgerrcode.UniqueViolation", "UniqueViolation", "ForeignKeyViolation",
		"Violation", "pgerrcode", "e.ConstraintName", "Constraint", "Constraints", "Constraint(", "constraint",
		"duplicate key", "DUPLICATE KEY", "Duplicate Key value", "duplicate Key", "duplicate  key", "duplicatekey",
		"dupl1cate key", "a duplicate keyword",
	}
	// Pieces glued two by two: a word split across them, or one next to
	// another, is matched the same way.
	pieces := []string{"Pg", "Error", "pq.", "Unique", "Violation", "Constraint", "Name", "dupli", "cate ", "KEY", `"235`, `05"`, " ", "x"}
	for _, a := range pieces {
		for _, b := range pieces {
			texts = append(texts, a+b, b+a+b)
		}
	}
	matched := 0
	for _, text := range texts {
		want := constraintCheck.MatchString(text)
		assert.Equal(t, want, matchesConstraintCheck(text), "%q", text)
		if want {
			matched++
		}
	}
	assert.Greater(t, matched, 20)
	assert.False(t, matchesConstraintCheck("Constraints"), "Constraint is a whole word")
	assert.True(t, matchesConstraintCheck("duplicate Key"), "the Kelvin sign folds to k under (?i)")
}

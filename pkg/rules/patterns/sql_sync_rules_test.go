package patterns

import (
	"fmt"
	"go/parser"
	"go/token"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const syncMigrations = `CREATE TABLE journals (id UUID PRIMARY KEY, status TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE postings (id UUID PRIMARY KEY, journal_id UUID NOT NULL REFERENCES journals(id), account TEXT, amount NUMERIC, period TEXT);
CREATE TABLE batches (id UUID PRIMARY KEY, name TEXT, notes TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE batch_members (batch_id UUID NOT NULL REFERENCES batches(id), member TEXT NOT NULL);
CREATE TABLE items (id UUID PRIMARY KEY, batch_id UUID REFERENCES batches(id), note TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());

CREATE OR REPLACE FUNCTION touch_row() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER batches_touch BEFORE UPDATE ON batches FOR EACH ROW EXECUTE FUNCTION touch_row();
`

// projectSQLRuleLines runs a project-files rule over a module with its
// migrations and returns the lines it reports in one file.
func projectSQLRuleLines(t *testing.T, rule interface {
	UseProjectFiles([]*core.FileContext)
	AnalyzeFile(*core.FileContext) []*core.Violation
}, files map[string]string, path string) []int {
	t.Helper()
	_, contexts := rulestest.Module(t, files)
	for _, ctx := range contexts {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, ctx.Path, ctx.Content, parser.ParseComments)
		require.NoError(t, err)
		ctx.SetGoAST(fset, file)
	}
	rule.UseProjectFiles(contexts)
	for _, ctx := range contexts {
		if ctx.RelPath == path {
			return sqlRuleLines(t, rule, ctx)
		}
	}
	t.Fatalf("no file %s in the module", path)
	return nil
}

// The trial balance sums the postings of every journal, reversed ones too,
// while the project itself leaves reversed journals out elsewhere. A list of
// postings answers another question than a total and is left out.
func TestSQLChildRowsIncludeVoidedParent(t *testing.T) {
	assert.Equal(t, []int{9}, projectSQLRuleLines(t, NewSQLChildRowsIncludeVoidedParentRule(), map[string]string{
		"repo/migrations/001_init.up.sql": syncMigrations,
		"repo/ledger.go": `package repo

type DB interface{ Select(dest any, query string, args ...any) error }

type Ledger struct{ db DB }

func (l *Ledger) TrialBalance(out any) error {
	return l.db.Select(out, ` + "`SELECT account, SUM(amount) AS total\n\t\tFROM postings\n\t\tGROUP BY account`" + `)
}

func (l *Ledger) Period(out any, period string) error {
	return l.db.Select(out, ` + "`SELECT *\n\t\tFROM postings\n\t\tWHERE period = $1`" + `, period)
}

func (l *Ledger) OfJournal(out any, id string) error {
	return l.db.Select(out, "SELECT * FROM postings WHERE journal_id = $1", id)
}

func (l *Ledger) Live(out any) error {
	return l.db.Select(out, "SELECT p.* FROM postings p JOIN journals j ON j.id = p.journal_id WHERE j.status <> 'reversed'")
}
`,
	}, "repo/ledger.go"))
}

// Without a filter of the parent by a void status anywhere, the children are
// read as they are.
func TestSQLChildRowsIncludeVoidedParentNeedsExclusion(t *testing.T) {
	assert.Empty(t, projectSQLRuleLines(t, NewSQLChildRowsIncludeVoidedParentRule(), map[string]string{
		"repo/migrations/001_init.up.sql": syncMigrations,
		"repo/ledger.go": `package repo

type DB interface{ Select(dest any, query string, args ...any) error }

type Ledger struct{ db DB }

func (l *Ledger) TrialBalance(out any) error {
	return l.db.Select(out, "SELECT account, SUM(amount) FROM postings GROUP BY account")
}

func (l *Ledger) Drafts(out any) error {
	return l.db.Select(out, "SELECT id FROM journals WHERE status <> 'draft'")
}
`,
	}, "repo/ledger.go"))
}

// A delta transfer reads batches changed since the last one; unlinking a
// member or an item changes the batch, but leaves its updated_at, so the
// next transfer never carries the removal.
func TestDeltaExportMissesUnlink(t *testing.T) {
	assert.Equal(t, []int{12, 16}, moduleSQLRuleLines(t, NewDeltaExportMissesUnlinkRule(), map[string]string{
		"repo/migrations/001_init.up.sql": syncMigrations,
		"repo/batches.go": `package repo

type DB interface{ Exec(query string, args ...any) error }

type Batches struct{ db DB }

func (b *Batches) ExportSince(since string) error {
	return b.db.Exec("SELECT * FROM batches WHERE updated_at >= $1", since)
}

func (b *Batches) RemoveMember(batch, member string) error {
	return b.db.Exec("DELETE FROM batch_members WHERE batch_id = $1 AND member = $2", batch, member)
}

func (b *Batches) DetachItem(batch, item string) error {
	return b.db.Exec("UPDATE items SET batch_id = NULL WHERE batch_id = $1 AND id = $2", batch, item)
}

func (b *Batches) RemoveMemberTouching(batch, member string) error {
	return b.db.Exec(` + "`WITH gone AS (DELETE FROM batch_members WHERE batch_id = $1 AND member = $2 RETURNING 1)\n\t\tUPDATE batches SET updated_at = NOW() WHERE id = $1 AND EXISTS (SELECT 1 FROM gone)`" + `, batch, member)
}

func (b *Batches) DetachItemTouching(batch, item string) error {
	if err := b.db.Exec("UPDATE items SET batch_id = NULL WHERE batch_id = $1 AND id = $2", batch, item); err != nil {
		return err
	}
	return b.db.Exec("UPDATE batches SET updated_at = NOW() WHERE id = $1", batch)
}
`,
	}, "repo/batches.go"))
}

// The delta read is often built in steps: the base query, then the filter
// of the change time appended when a bound is given, among other terms.
func TestDeltaExportMissesUnlinkBuiltQuery(t *testing.T) {
	assert.Equal(t, []int{22}, moduleSQLRuleLines(t, NewDeltaExportMissesUnlinkRule(), map[string]string{
		"repo/migrations/001_init.up.sql": syncMigrations,
		"repo/batches.go": `package repo

type DB interface{ Exec(query string, args ...any) error }

type Batches struct{ db DB }

const batchColumns = "id, name, updated_at"

func (b *Batches) ExportSince(since *string) error {
	query := "SELECT " + batchColumns + " FROM batches"
	args := []any{}
	if since != nil {
		query += ` + "` WHERE updated_at >= $1\n\t\t\tOR EXISTS (SELECT 1 FROM items i WHERE i.batch_id = batches.id AND i.note IS NOT NULL)`" + `
		args = append(args, *since)
	}
	query += " ORDER BY name"
	return b.db.Exec(query, args...)
}

func (b *Batches) RemoveMember(batch, member string) error {
	return b.db.Exec("DELETE FROM batch_members WHERE batch_id = $1 AND member = $2", batch, member)
}
`,
	}, "repo/batches.go"))
}

// Without a delta read of the parent, an unlink is nobody's concern.
func TestDeltaExportMissesUnlinkNeedsDeltaRead(t *testing.T) {
	assert.Empty(t, moduleSQLRuleLines(t, NewDeltaExportMissesUnlinkRule(), map[string]string{
		"repo/migrations/001_init.up.sql": syncMigrations,
		"repo/batches.go": `package repo

type DB interface{ Exec(query string, args ...any) error }

type Batches struct{ db DB }

func (b *Batches) RemoveMember(batch, member string) error {
	return b.db.Exec("DELETE FROM batch_members WHERE batch_id = $1 AND member = $2", batch, member)
}
`,
	}, "repo/batches.go"))
}

func typedSyncFindings(t *testing.T, rule interface {
	AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
}, files map[string]string) []string {
	t.Helper()
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

const syncStoreSource = `package store

import "time"

type DB interface{ Exec(query string, args ...any) error }

type Batch struct {
	ID        string
	Name      string
	UpdatedAt time.Time
}

func (b *Batch) Same(other *Batch) bool { return b.Name == other.Name }

type Store struct{ db DB }

func (s *Store) Update(b *Batch) error {
	return s.db.Exec("UPDATE batches SET name = $1, updated_at = $2 WHERE id = $3", b.Name, b.UpdatedAt, b.ID)
}

func (s *Store) UpdateItem(id, note string, at time.Time) error {
	return s.db.Exec("UPDATE items SET note = $1, updated_at = $2 WHERE id = $3", note, at, id)
}
`

// An import takes the newer row by updated_at, but the trigger stamps the
// written row with the time of the write: the receiving copy becomes newer
// than its source, and each transfer copies the row back.
func TestSyncNewerWinsOnStampedTable(t *testing.T) {
	assert.ElementsMatch(t, []string{"sync/sync.go:9", "sync/sync.go:26", "sync/sync.go:40"}, typedSyncFindings(t, NewSyncNewerWinsOnStampedTableRule(), map[string]string{
		"migrations/001_init.up.sql": syncMigrations,
		"store/store.go":             syncStoreSource,
		"sync/sync.go": `package sync

import "example.com/rulestest/store"

type Importer struct{ store *store.Store }

func (i *Importer) Import(incoming, existing *store.Batch) error {
	switch {
	case incoming.UpdatedAt.After(existing.UpdatedAt):
		return i.store.Update(incoming)
	}
	return nil
}

func (i *Importer) ImportChecked(incoming, existing *store.Batch) error {
	switch {
	case incoming.Same(existing):
		return nil
	case incoming.UpdatedAt.After(existing.UpdatedAt):
		return i.store.Update(incoming)
	}
	return nil
}

func (i *Importer) ImportIf(incoming, existing *store.Batch) error {
	if existing.UpdatedAt.Before(incoming.UpdatedAt) {
		return i.store.Update(incoming)
	}
	return nil
}

func (i *Importer) ImportItem(id, note string, incoming, existing *store.Batch) error {
	if incoming.UpdatedAt.After(existing.UpdatedAt) {
		return i.store.UpdateItem(id, note, incoming.UpdatedAt)
	}
	return nil
}

func (i *Importer) ImportVia(incoming, existing *store.Batch) error {
	if incoming.UpdatedAt.After(existing.UpdatedAt) {
		return i.SaveBatch(incoming)
	}
	return nil
}

func (i *Importer) SaveBatch(b *store.Batch) error {
	return i.store.Update(b)
}
`,
	}))
}

// An import from a source of truth links each record's children but never
// takes away a link the source no longer has.
func TestMirrorImportNeverRemoves(t *testing.T) {
	ctx := rulestest.GoFile(t, "sync/import.go", `package sync

type Record struct {
	ID    string
	Items []string
}

type Repo interface {
	LinkItems(id string, items []string) error
	UnlinkItemsExcept(id string, items []string) error
}

type Importer struct{ repo Repo }

func (i *Importer) ImportBatches(records []Record) error {
	for _, record := range records {
		if err := i.repo.LinkItems(record.ID, record.Items); err != nil {
			return err
		}
	}
	return nil
}

func (i *Importer) ImportMirrored(records []Record) error {
	for _, record := range records {
		if err := i.repo.LinkItems(record.ID, record.Items); err != nil {
			return err
		}
		if err := i.repo.UnlinkItemsExcept(record.ID, record.Items); err != nil {
			return err
		}
	}
	return nil
}

func (i *Importer) LinkFresh(records []Record) error {
	for _, record := range records {
		if err := i.repo.LinkItems(record.ID, record.Items); err != nil {
			return err
		}
	}
	return nil
}
`)
	assert.Equal(t, []int{17}, sqlRuleLines(t, NewMirrorImportNeverRemovesRule(), ctx))
}

// A pass over the first page of a pending queue that skips some items
// leaves them pending at the head: the next pass takes the same page.
func TestPendingPageSkipsStayAtHead(t *testing.T) {
	ctx := rulestest.GoFile(t, "work/link.go", `package work

type Item struct{ ID string }

type Repo interface {
	GetUnmatchedByOwner(owner string, limit int) ([]Item, error)
	GetPendingAfter(owner, after string, limit int) ([]Item, error)
}

type Linker struct{ repo Repo }

func (l *Linker) LinkAll(owner string, limit int) (int, int, error) {
	items, err := l.repo.GetUnmatchedByOwner(owner, limit)
	if err != nil {
		return 0, 0, err
	}
	linked, skipped := 0, 0
	for _, item := range items {
		if l.link(item) {
			linked++
		} else {
			skipped++
		}
	}
	return linked, skipped, nil
}

func (l *Linker) LinkPaged(owner, after string, limit int) (int, error) {
	items, err := l.repo.GetPendingAfter(owner, after, limit)
	if err != nil {
		return 0, err
	}
	skipped := 0
	for _, item := range items {
		if !l.link(item) {
			skipped++
		}
	}
	return skipped, nil
}

func (l *Linker) LinkEach(owner string, limit int) (int, error) {
	items, err := l.repo.GetUnmatchedByOwner(owner, limit)
	if err != nil {
		return 0, err
	}
	linked := 0
	for _, item := range items {
		if l.link(item) {
			linked++
		}
	}
	return linked, nil
}

func (l *Linker) link(item Item) bool { return item.ID != "" }

type tally struct{ linked, skipped int }

func (l *Linker) LinkInPasses(owner string, limit int) (tally, error) {
	items, err := l.repo.GetUnmatchedByOwner(owner, limit)
	if err != nil {
		return tally{}, err
	}
	return runPasses(items, l.link), nil
}

func runPasses(items []Item, link func(Item) bool) tally {
	var t tally
	for _, item := range items {
		if link(item) {
			t.linked++
		} else {
			t.skipped++
		}
	}
	return t
}
`)
	assert.Equal(t, []int{13, 61}, sqlRuleLines(t, NewPendingPageSkipsStayAtHeadRule(), ctx))
}

package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// dbStubSource stands for the database/sql and sqlx calls the rules read.
const dbStubSource = `package db

import "context"

type Result interface{ RowsAffected() (int64, error) }

type DB struct{}

func (DB) ExecContext(ctx context.Context, query string, args ...any) (Result, error) { return nil, nil }
func (DB) NamedExecContext(ctx context.Context, query string, arg any) (Result, error) { return nil, nil }

func Named(query string, arg any) (string, []any, error) { return query, nil, nil }
`

// An upsert's affected count includes the rows it updated: every re-sync of
// a known row counts as a new one. The conflict clause comes from the
// callers.
func TestUpsertAffectedCountedAsInserted(t *testing.T) {
	assert.Equal(t, []string{"store/store.go:29", "store/store.go:40"}, projectRuleLines(t, NewUpsertAffectedCountedAsInsertedRule(), map[string]string{
		"db/db.go": dbStubSource,
		"store/store.go": `package store

import (
	"context"

	"example.com/rulestest/db"
)

type Row struct{ Key, Value string }

type Store struct{ db db.DB }

func (s *Store) Upsert(ctx context.Context, rows []*Row) (int, error) {
	return s.insert(ctx, rows, ` + "`" + `ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value` + "`" + `)
}

func (s *Store) Create(ctx context.Context, rows []*Row) (int, error) {
	return s.insert(ctx, rows, "ON CONFLICT DO NOTHING")
}

func (s *Store) insert(ctx context.Context, rows []*Row, conflict string) (int, error) {
	query := ` + "`" + `INSERT INTO rows (key, value) VALUES (:key, :value) ` + "`" + ` + conflict
	inserted := 0
	for _, row := range rows {
		result, err := s.db.NamedExecContext(ctx, query, row)
		if err != nil {
			return inserted, err
		}
		affected, _ := result.RowsAffected()
		inserted += int(affected)
	}
	return inserted, nil
}

func (s *Store) Put(ctx context.Context, key, value string) (int64, error) {
	result, err := s.db.ExecContext(ctx, "INSERT INTO rows (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", key, value)
	if err != nil {
		return 0, err
	}
	created, err := result.RowsAffected()
	return created, err
}

func (s *Store) Touch(ctx context.Context, key string) (int64, error) {
	result, err := s.db.ExecContext(ctx, "INSERT INTO rows (key) VALUES ($1) ON CONFLICT (key) DO UPDATE SET value = rows.value", key)
	if err != nil {
		return 0, err
	}
	written, err := result.RowsAffected()
	return written, err
}

func (s *Store) Add(ctx context.Context, key string) (int64, error) {
	result, err := s.db.ExecContext(ctx, "INSERT INTO rows (key) VALUES ($1) ON CONFLICT DO NOTHING", key)
	if err != nil {
		return 0, err
	}
	inserted, err := result.RowsAffected()
	return inserted, err
}
`,
	}))
}

// Two rows with one conflict key fail the multi-row upsert as a whole.
func TestBatchUpsertDuplicateConflictKeys(t *testing.T) {
	assert.Equal(t, []string{"store/store.go:23"}, projectRuleLines(t, NewBatchUpsertDuplicateConflictKeysRule(), map[string]string{
		"db/db.go": dbStubSource,
		"store/store.go": `package store

import (
	"context"
	"errors"
	"slices"

	"example.com/rulestest/db"
)

type Row struct{ Key, Value string }

type Store struct{ db db.DB }

func (s *Store) Upsert(ctx context.Context, rows []*Row) error {
	return s.insert(ctx, rows, "ON CONFLICT (key) DO UPDATE SET value = "+keptValue()+", note = EXCLUDED.note")
}

func keptValue() string { return "EXCLUDED.value" }

func (s *Store) insert(ctx context.Context, rows []*Row, conflict string) error {
	for chunk := range slices.Chunk(rows, 500) {
		q, _, err := db.Named("INSERT INTO rows (key, value) VALUES (:key, :value) "+conflict, chunk)
		if err != nil {
			return err
		}
		_ = q
	}
	return nil
}

func (s *Store) UpsertUnique(ctx context.Context, rows []*Row) error {
	rows = dedupe(rows)
	_, err := s.db.NamedExecContext(ctx, "INSERT INTO rows (key, value) VALUES (:key, :value) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", rows)
	return err
}

func (s *Store) Insert(ctx context.Context, rows []*Row) error {
	_, err := s.db.NamedExecContext(ctx, "INSERT INTO rows (key, value) VALUES (:key, :value) ON CONFLICT DO NOTHING", rows)
	return err
}

func (s *Store) UpsertChecked(ctx context.Context, rows []*Row) error {
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if seen[row.Key] {
			return errors.New("duplicate key")
		}
		seen[row.Key] = true
	}
	_, err := s.db.NamedExecContext(ctx, "INSERT INTO rows (key, value) VALUES (:key, :value) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", rows)
	return err
}

func dedupe(rows []*Row) []*Row { return rows }
`,
	}))
}

// A DATE column scanned into a string arrives as RFC 3339: the date-only
// parse fails on every row.
func TestSQLDateStringParsedAsDate(t *testing.T) {
	assert.Equal(t, []string{"store/vesting.go:16"}, projectRuleLines(t, NewSQLDateStringParsedAsDateRule(), map[string]string{
		"store/migrations/001_init.up.sql": `CREATE TABLE rounds (id UUID PRIMARY KEY, close_date DATE, label TEXT, note_day TEXT);`,
		"store/vesting.go": `package store

import "time"

type Round struct {
	ID        string  ` + "`db:\"id\"`" + `
	CloseDate *string ` + "`db:\"close_date\"`" + `
	Label     string  ` + "`db:\"label\"`" + `
	NoteDay   string  ` + "`db:\"note_day\"`" + `
}

func Vested(r *Round) bool {
	if r.CloseDate == nil {
		return false
	}
	day, err := time.Parse("2006-01-02", *r.CloseDate)
	if err != nil {
		return false
	}
	return day.Before(time.Now())
}

func Fixed(r *Round) (time.Time, error) {
	text := *r.CloseDate
	if len(text) > 10 {
		text = text[:10]
	}
	return time.Parse("2006-01-02", text)
}

func Moment(r *Round) (time.Time, error) { return time.Parse(time.RFC3339, *r.CloseDate) }

func Noted(r *Round) (time.Time, error) { return time.Parse("2006-01-02", r.NoteDay) }
`,
	}))
}

// The legacy key the builder sets never reaches the snapshot the
// materializer reads back: there it is always empty.
func TestJSONIgnoredFieldLostInRoundTrip(t *testing.T) {
	assert.Equal(t, []string{"holdings/holdings.go:7"}, projectRuleLines(t, NewJSONIgnoredFieldLostInRoundTripRule(), map[string]string{
		"holdings/holdings.go": `package holdings

import "encoding/json"

type Holding struct {
	Key       string ` + "`json:\"key\"`" + `
	LegacyKey string ` + "`json:\"-\"`" + `
	Cached    string ` + "`json:\"-\"`" + `
	Local     string ` + "`json:\"-\"`" + `
}

type Snapshot struct {
	Holdings []Holding ` + "`json:\"holdings\"`" + `
}

func Build(keys []string) []byte {
	var s Snapshot
	for _, k := range keys {
		s.Holdings = append(s.Holdings, Holding{Key: k, LegacyKey: "old-" + k, Local: k})
	}
	raw, _ := json.Marshal(s)
	return raw
}

func Materialize(raw []byte) int {
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0
	}
	migrated := 0
	for i := range s.Holdings {
		s.Holdings[i].Cached = s.Holdings[i].Key
		if s.Holdings[i].LegacyKey != "" || s.Holdings[i].Cached != "" {
			migrated++
		}
	}
	return migrated
}
`,
	}))
}

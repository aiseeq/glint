package errrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nil is the empty value of a slice, a map, a channel and a function: a
// (nil, nil) return from such a function reports "nothing", not a missing
// error. A pointer first result still is suspicious.
const nilCollectionSource = `package svc

type Item struct{ ID int }

type Items []Item

type Report struct{}

func Collect(ids []int) ([]Item, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return []Item{{ID: ids[0]}}, nil
}

func Index(ids []int) (map[int]Item, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return map[int]Item{}, nil
}

func Named(ids []int) (Items, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return Items{}, nil
}

func Stream(ids []int) (<-chan Item, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return make(chan Item), nil
}

func Hook(ids []int) (func() error, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return func() error { return nil }, nil
}

func Build(ids []int) (*Report, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return &Report{}, nil
}
`

func TestReturnNilErrorRule_NilCollectionIsEmptyValueTyped(t *testing.T) {
	violations := rulestest.RunRuleOnFiles(t, NewReturnNilErrorRule(), map[string]string{"svc/svc.go": nilCollectionSource})
	require.Len(t, violations, 1)
	assert.Equal(t, 46, violations[0].Line, "only the pointer result is reported")
}

func TestReturnNilErrorRule_NilCollectionIsEmptyValueUntyped(t *testing.T) {
	ctx := rulestest.GoFile(t, "svc/svc.go", nilCollectionSource)
	// Without types the named slice type is unknown and stays reported.
	assert.Equal(t, []int{25, 46}, rulestest.ViolationLines(NewReturnNilErrorRule().AnalyzeFile(ctx)))
}

// (nil, nil) is the answer "there is none" when every caller tests the record
// for nil before it uses it: no caller counts the missing record as zero.
// Repro from an admin whose optional links (the request of a transaction, the
// last staff comment) were read that way.
func TestReturnNilErrorKeepsAnswerEveryCallerTestsForNil(t *testing.T) {
	violations, err := NewReturnNilErrorRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"store/store.go": `package store

import (
	"database/sql"
	"errors"
)

type Brief struct{ ID int }

type Repo struct{ db *sql.DB }

// briefOf returns the brief of a transaction, or nil when it has none.
func (r *Repo) briefOf(id int) (*Brief, error) {
	if id == 0 {
		return nil, nil
	}
	return &Brief{ID: id}, nil
}

// LastComment returns the newest comment, nil when there is none.
func (r *Repo) LastComment(id int) (*Brief, error) {
	var b Brief
	if err := r.db.QueryRow("SELECT id FROM c WHERE r = $1", id).Scan(&b.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &b, nil
}

// keyed is read by a caller that takes the record for granted.
func (r *Repo) keyed(id int) (*Brief, error) {
	if id < 0 {
		return nil, nil
	}
	return &Brief{ID: id}, nil
}

// Orphan has no caller in the module: its callers are out of sight.
func (r *Repo) Orphan(id int) (*Brief, error) {
	if id < 0 {
		return nil, nil
	}
	return &Brief{ID: id}, nil
}

func (r *Repo) Page(id int) (int, error) {
	b, err := r.briefOf(id)
	if err != nil {
		return 0, err
	}
	if b == nil {
		return 0, nil
	}
	last, err := r.LastComment(id)
	if err != nil {
		return 0, err
	}
	if last != nil {
		return last.ID, nil
	}
	k, err := r.keyed(id)
	if err != nil {
		return 0, err
	}
	return b.ID + k.ID, nil
}
`,
	}))
	require.NoError(t, err)
	lines := make([]int, 0, len(violations))
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{35, 43}, lines)
}

// A function handed on as a value is called where the module cannot see
// whether the result is tested.
func TestReturnNilErrorReportsFunctionUsedAsValue(t *testing.T) {
	violations, err := NewReturnNilErrorRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"store/store.go": `package store

type Brief struct{ ID int }

func briefOf(id int) (*Brief, error) {
	if id == 0 {
		return nil, nil
	}
	return &Brief{ID: id}, nil
}

func run(read func(int) (*Brief, error)) { _, _ = read(1) }

func Page(id int) int {
	run(briefOf)
	b, _ := briefOf(id)
	if b == nil {
		return 0
	}
	return b.ID
}
`,
	}))
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, 7, violations[0].Line)
}

// The caller may leave the test to the function it hands the record to, or
// keep the absence as a nil field (a nullable reference). A function that
// reads the record without a test does not count.
func TestReturnNilErrorKeepsNilHandedOnOrStored(t *testing.T) {
	violations, err := NewReturnNilErrorRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"store/store.go": `package store

type Entry struct{ Body string }

type Comment struct{ TemplateID *int }

func lastStaff(id int) (*Entry, error) {
	if id == 0 {
		return nil, nil
	}
	return &Entry{Body: "b"}, nil
}

func templateID(raw string) (*int, error) {
	if raw == "" {
		return nil, nil
	}
	id := len(raw)
	return &id, nil
}

func lastAny(id int) (*Entry, error) {
	if id == 0 {
		return nil, nil
	}
	return &Entry{Body: "b"}, nil
}

func state(e *Entry) string {
	if e != nil {
		return e.Body
	}
	return ""
}

func quote(e *Entry) string { return e.Body }

func Page(id int, raw string) (string, *Comment, error) {
	last, err := lastStaff(id)
	if err != nil {
		return "", nil, err
	}
	tpl, err := templateID(raw)
	if err != nil {
		return "", nil, err
	}
	c := &Comment{}
	c.TemplateID = tpl
	other, err := lastAny(id)
	if err != nil {
		return "", nil, err
	}
	return state(last) + quote(other), c, nil
}
`,
	}))
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, 24, violations[0].Line)
}

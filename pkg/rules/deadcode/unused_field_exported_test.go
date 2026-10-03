package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeFieldsApp(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	rule := NewUnusedFieldRule()
	require.NoError(t, rule.Configure(map[string]any{"application": true}))
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

// A second ordering computed at setup and stored in an exported field that
// nothing reads any more: the switch that chose it was removed, the field and
// the work filling it stayed, and the comment still promises the choice.
const gameWithDeadOrdering = `package game

type Game struct {
	Bases      []int
	BasesZones []int
}

func New(bases []int) *Game {
	g := &Game{Bases: bases}
	g.BasesZones = reorder(bases)
	return g
}

func reorder(b []int) []int { return append([]int{}, b...) }

func (g *Game) Next() int { return g.Bases[0] }
`

// An application has no readers outside the tree: an exported field written
// and never read there is dead state.
func TestUnusedFieldApplicationReportsExportedWrittenField(t *testing.T) {
	violations := analyzeFieldsApp(t, map[string]string{"game/game.go": gameWithDeadOrdering})
	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Game.BasesZones is kept up to date but never read")
}

// A library's exported field may be read by its importers, so without the
// setting the same code stays silent.
func TestUnusedFieldLibraryKeepsExportedField(t *testing.T) {
	assert.Empty(t, analyzeFields(t, map[string]string{"game/game.go": gameWithDeadOrdering}))
}

// Nothing outside the module can import an internal package: its exported
// fields are judged without the setting.
func TestUnusedFieldInternalPackageJudgesExportedField(t *testing.T) {
	violations := analyzeFields(t, map[string]string{"internal/game/game.go": gameWithDeadOrdering})
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Game.BasesZones")
}

// An exported field read anywhere, or of a struct an encoder reads on the
// program's behalf, is alive in an application too.
func TestUnusedFieldApplicationKeepsReadAndEncodedFields(t *testing.T) {
	violations := analyzeFieldsApp(t, map[string]string{
		"game/game.go": `package game

import (
	"encoding/json"
	"os"
)

type Game struct {
	Bases []int
	Seen  int
}

type Report struct {
	Name  string
	Loops int
}

func New(bases []int) *Game { return &Game{Bases: bases, Seen: 1} }

func (g *Game) Next() int { return g.Bases[g.Seen] }

func Save(name string, loops int) error {
	return json.NewEncoder(os.Stdout).Encode(Report{Name: name, Loops: loops})
}
`,
	})
	assert.Empty(t, violations)
}

func TestUnusedFieldApplicationSettingMustBeBool(t *testing.T) {
	assert.Error(t, NewUnusedFieldRule().Configure(map[string]any{"application": "yes"}))
}

// Page data handed to a renderer as any - by pointer, inside a map of any, or
// through a variadic ...any - is read by the template through reflection.
func TestUnusedFieldApplicationKeepsFieldsBoxedIntoAny(t *testing.T) {
	violations := analyzeFieldsApp(t, map[string]string{
		"web/web.go": `package web

import (
	"html/template"
	"io"
)

type PageData struct{ Title string }

type Row struct{ Name string }

type Item struct{ Label string }

var page = template.Must(template.New("p").Parse("{{.Title}}"))

func render(w io.Writer, data any) { _ = page.Execute(w, data) }

func logf(format string, args ...any) {}

func Page(w io.Writer) {
	render(w, &PageData{Title: "t"})
	render(w, map[string]any{"rows": []Row{{Name: "n"}}})
	logf("%+v", Item{Label: "l"})
}
`,
	})
	assert.Empty(t, violations)
}

// A fake's counter is asserted by the tests of the package it stands in for,
// not by its own: a read in any test of the module keeps an exported field.
func TestUnusedFieldApplicationKeepsFieldReadByOtherPackageTest(t *testing.T) {
	violations := analyzeFieldsApp(t, map[string]string{
		"internal/testutil/store.go": `package testutil

type FakeStore struct{ Batches int }

func (k *FakeStore) Load() { k.Batches++ }
`,
		"internal/storage/storage_test.go": `package storage

import (
	"testing"

	"example.com/rulestest/internal/testutil"
)

func TestPage(t *testing.T) {
	fake := &testutil.FakeStore{}
	fake.Load()
	if fake.Batches != 1 {
		t.Fatal(fake.Batches)
	}
}
`,
		"internal/storage/storage.go": `package storage
`,
	})
	assert.Empty(t, violations)
}

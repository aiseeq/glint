package gorules

import (
	"fmt"
	"slices"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestTombstoneCommentRule(t *testing.T) {
	rule := NewTombstoneCommentRule()

	tests := []struct {
		name      string
		filename  string
		code      string
		wantCount int
	}{
		{
			name:     "removed function tombstone",
			filename: "handler.go",
			code: `package routing

// GetDB removed — architectural boundary violation eliminated
func other() {}
`,
			wantCount: 1,
		},
		{
			name:     "russian tombstone with colon",
			filename: "labels.ts",
			code: `// УДАЛЕНО: processed статус (дубликат approved)
export const x = 1
`,
			wantCount: 1,
		},
		{
			name:     "russian tombstone lowercase",
			filename: "service.go",
			code: `package svc

// Удалён dead field balanceRepo
type Service struct{}
`,
			wantCount: 1,
		},
		{
			name:     "removed with count",
			filename: "repo.go",
			code: `package repo

// SIMPLIFIED: Removed 38 stub methods that returned "not implemented"
type Repo struct{}
`,
			wantCount: 1,
		},
		{
			name:     "trailing tombstone after dead assignment",
			filename: "config.go",
			code: `package config

func f(disableFixes bool) {
	_ = disableFixes // CryptoProv fixes removed
}
`,
			wantCount: 1,
		},
		{
			name:     "no longer used tombstone",
			filename: "helpers.go",
			code: `package svc

// Removed canonicalUserService parameter (was unused)
func helper() {}
`,
			wantCount: 1,
		},
		{
			name:     "behavior description is not a tombstone",
			filename: "cache.go",
			code: `package cache

// Entries are removed from the cache after TTL expires.
func (c *Cache) sweep() {}

// Stale sessions will be removed by the janitor goroutine.
func (c *Cache) janitor() {}

// The item gets removed when the user confirms deletion.
func (c *Cache) confirm() {}
`,
			wantCount: 0,
		},
		{
			name:     "russian behavior description is not a tombstone",
			filename: "session.go",
			code: `package session

// Старые сессии будут удалены фоновой задачей.
func cleanup() {}

// Записи удаляются по расписанию.
func schedule() {}
`,
			wantCount: 0,
		},
		{
			name:     "policy quote is not a tombstone",
			filename: "linter.go",
			code: `package rules

// CLAUDE.md: deprecated aliases must be removed immediately, never created.
func check() {}
`,
			wantCount: 0,
		},
		{
			name:     "deprecated marker is deprecated-comment territory",
			filename: "api.go",
			code: `package api

// Deprecated: use NewHandler instead; this alias will be removed in v5.
func OldHandler() {}
`,
			wantCount: 0,
		},
		{
			name:     "code that calls remove is not a comment",
			filename: "list.go",
			code: `package list

func f() {
	removed := list.Remove(el)
	_ = removed
}
`,
			wantCount: 0,
		},
		{
			name:     "data-flow and state-machine docs are not tombstones",
			filename: "capital.go",
			code: `package svc

// WithdrawalPipelineCapital returns principal removed from user investments.
func capital() {}

// deleted -> * (удаленные пользователи нельзя восстановить)
func transitions() {}

// Исключаем soft deleted транзакции
func filter() {}

// что удалено: {"wallets": 2, "user": 1}
func counts() {}
`,
			wantCount: 0,
		},
		{
			// Godoc of an error or a condition in the past tense describes behaviour.
			name:     "was/were past-tense behaviour is not a tombstone",
			filename: "store.go",
			code: `package store

// ErrGone is returned when the key was deleted concurrently.
var ErrGone = errors.New("gone")

// Get fails with ErrGone if the record was removed by another worker.
func Get() error { return ErrGone }

// Rows that were deleted by the sweeper are skipped.
func List() {}
`,
			wantCount: 0,
		},
		{
			// A godoc code block (//<tab>) quotes an example; it does not annotate this code.
			name:     "godoc code block example is not a tombstone",
			filename: "rules/doc.go",
			code: `package rules

// Rule detects notes like these:
//
//	// GetDB removed — architectural boundary violation eliminated
//	_ = disableFixes // provider fixes removed
func Rule() {}
`,
			wantCount: 0,
		},
		{
			name:     "file named like a glint source is checked",
			filename: "rules/tombstone_comment.go",
			code: `package rules

// GetDB removed — architectural boundary violation eliminated
func Serve() {}
`,
			wantCount: 1,
		},
		{
			name:     "test files are skipped",
			filename: "handler_test.go",
			code: `package routing

// GetDB removed — check the new path
func TestX(t *testing.T) {}
`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), nil)
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d; violations: %+v",
					len(violations), tt.wantCount, violations)
			}
		})
	}
}

// Репро аудита 2026-07-02: реальные frontend-надгробия, пропущенные правилом
// (вычищены вручную в projectA@8f7c1a6bd).
func TestTombstoneComment_RussianColonAndDashForms(t *testing.T) {
	rule := NewTombstoneCommentRule()
	code := `const LABEL_MAPPINGS = {
  // УДАЛЕНО: investmentStatuses теперь используется из централизованного модуля investment-status-validation.ts
  transactionStatuses: {},
  // networks: УДАЛЕНО - используйте getNetworkName из @shared/config/networks
  currencies: {},
}
`
	ctx := core.NewFileContext("frontend/shared/lib/label-utils.ts", ".", []byte(code), nil)
	violations := rule.AnalyzeFile(ctx)
	if len(violations) != 2 {
		t.Fatalf("want 2 violations (оба «УДАЛЕНО»-надгробия), got %d: %+v", len(violations), violations)
	}
}

// «если он был удалён cleanup-системой» — описание условия/поведения, не надгробие.
func TestTombstoneComment_PastConditionIsBehavior(t *testing.T) {
	rule := NewTombstoneCommentRule()
	code := `// Создаём пользователя заново если он был удалён cleanup системой
export const ensureUser = 1
`
	ctx := core.NewFileContext("e2e/utils/real-auth-helpers.ts", ".", []byte(code), nil)
	violations := rule.AnalyzeFile(ctx)
	if len(violations) != 0 {
		t.Fatalf("past-condition behavior must not be flagged, got: %+v", violations)
	}
}

// A state named among alternatives ("удалено или нередактируемо", "deleted or
// archived") describes an object the code handles, not code that was deleted.
func TestTombstoneComment_StateAmongAlternativesIsBehavior(t *testing.T) {
	code := `package notify

// recreate replaces the pinned note only if the service rejected the edit
// (сообщение удалено или нередактируемо); a network failure is returned.
func recreate() {}

// The upstream record may be deleted or archived by its owner.
func refresh() {}

// Old pin handler removed.
func pin() {}
`
	ctx := core.NewFileContext("notify/pin.go", ".", []byte(code), nil)
	violations := NewTombstoneCommentRule().AnalyzeFile(ctx)
	if len(violations) != 1 || violations[0].Line != 10 {
		t.Fatalf("want only the tombstone on line 10, got: %+v", violations)
	}
}

// A status word in capitals that the file also spells inside a string literal
// (an SQL filter, a status constant) names that value, not deleted code.
func TestTombstoneComment_StatusWordSpelledInLiteral(t *testing.T) {
	code := `package store

// DELETED rows are excluded everywhere.
const where = "WHERE status <> 'DELETED'"

const listQuery = ` + "`" + `
SELECT id FROM items
WHERE state <> 'REMOVED'` + "`" + `

// REMOVED and DELETED states are terminal.
func terminal() {}

const label = "УДАЛЕНО"

// УДАЛЕНО: метка статуса в выгрузке.
func exportLabel() {}
`
	ctx := core.NewFileContext("store/items.go", ".", []byte(code), nil)
	violations := NewTombstoneCommentRule().AnalyzeFile(ctx)
	if len(violations) != 0 {
		t.Fatalf("status words spelled in literals must not be flagged, got: %+v", violations)
	}
}

// A capitalised tombstone with no literal spelling the word stays a tombstone,
// and so does a lower-case note even when a literal holds the word.
func TestTombstoneComment_StatusWordWithoutLiteralStillFlagged(t *testing.T) {
	code := `package store

const msg = "item deleted"

// DELETED: old sync worker (moved to the queue)
func sync() {}

// legacy importer deleted
func importer() {}
`
	ctx := core.NewFileContext("store/sync.go", ".", []byte(code), nil)
	violations := NewTombstoneCommentRule().AnalyzeFile(ctx)
	if len(violations) != 2 {
		t.Fatalf("want both tombstones, got: %+v", violations)
	}
}

// "Added and removed" counts a change both ways (the lines of a diff, the
// members of a set): it describes what the code reports, not deleted code.
func TestTombstoneComment_AddedAndRemovedIsCount(t *testing.T) {
	code := `// Command stats collects the size of the files over time and how much each
// night added and removed. It reads the logs in the runs directory.
package main

// nightLines sums lines added and removed in the files by the
// commits of one night.
func nightLines() {}

// diff reports the keys removed or added between two snapshots.
func diff() {}

// Added/removed members are logged once per sync.
func sync() {}

// Old sync handler removed.
func legacy() {}
`
	ctx := core.NewFileContext("stats/main.go", ".", []byte(code), nil)
	violations := NewTombstoneCommentRule().AnalyzeFile(ctx)
	if len(violations) != 1 || violations[0].Line != 15 {
		t.Fatalf("want only the tombstone on line 15, got: %+v", violations)
	}
}

// A record deleted since some moment ("a channel deleted since", "removed in
// the meantime") is a state of the data the code handles, not code that went
// away; "removed since v2" still dates a removal of code.
func TestTombstoneComment_DeletedSinceIsState(t *testing.T) {
	code := `package tomb

// channelToEdit finds the channel named by the edit link among the existing
// ones. A link to a channel deleted since, or a malformed one, is an error the
// page shows instead of an empty form.
func channelToEdit() {}

// A row removed in the meantime is skipped; one removed concurrently too.
func skip() {}

// legacyHandler removed since v2.
var x = 1

// GetDB removed since 1.4 — use the pool.
var y = 2
`
	var lines []int
	for _, v := range NewTombstoneCommentRule().AnalyzeFile(core.NewFileContext("a.go", ".", []byte(code), nil)) {
		lines = append(lines, v.Line)
	}
	if len(lines) != 2 || lines[0] != 11 || lines[1] != 14 {
		t.Fatalf("want findings on lines 11 and 14 only, got %v", lines)
	}
}

// A note about deleted code names what went away and stops there ("GetDB
// removed.", "Removed the fallback"); a removal word inside a sentence about
// what the program does to files, rows and records goes on to say when, by
// whom or with what ("removed afterwards", "deleted in the work tree"), or
// names the thing as removed ("a deleted file"). A sentence wrapped onto the
// next comment line goes on there, and one wrapped from the line above
// started there ("was / deleted").
func TestTombstoneComment_RemovalInsideABehaviourSentence(t *testing.T) {
	code := `package store

// gate writes the message to a temporary file, removed afterwards.
// changed lists the paths, removed files left out.
// The first entry is the main one: never removed.
// status reports a path tracked, but deleted in the work tree.
// weight counts a deleted file as much as changed lines.
// net is a bridge for the container, created and removed with it.
// The file is replaced by rename and removed whole, so a read sees one.
// A file another run removed first is skipped.
// Reports a file removed before its replacement is written.
// A role removed in the admin screen comes back with the next request.
// The removed row leaves no trace the transfer could see.
// sweep finds the cookie set and deleted in different files.
// The rule reports the lines the commit removed (defect) or added.
// normalize reports a comma or a dot removed
// from a number before it is parsed.
// A comment there documents no entry: the entry it described was
// deleted, or the declaration it documented went away.
func f() {}

// Old cache warmer removed.
// Removed the retry fallback (was unused)
// SIMPLIFIED: removed 3 wrappers
// sync: watcher deleted, use the queue
// Cleanup — removed the second handler.
// importer deleted
func g() {}
`
	var lines []int
	for _, v := range NewTombstoneCommentRule().AnalyzeFile(core.NewFileContext("store/a.go", ".", []byte(code), nil)) {
		lines = append(lines, v.Line)
	}
	if fmt.Sprint(lines) != "[22 23 24 25 26 27]" {
		t.Fatalf("want findings on lines 22-27 only, got %v", lines)
	}
}

func TestTombstoneComment_RuntimeRemovalConditionsAreBehavior(t *testing.T) {
	code := `package runtime

// resolve reads the project metadata; if it cannot be read (worktree removed, not a repo) — empty.
func resolve() string { return "" }

// If the file was deleted, returns an empty result.
func readFile() string { return "" }

// Use the cache when the worktree is removed during execution.
func readWorktree() {}

// Если каталог удалён во время работы, возвращаем пустое значение.
func readDir() string { return "" }

// Старый обработчик удалён.
func oldHandler() {}

// УДАЛЕНО: старая функция повторной отправки.
func oldRetry() {}
`
	var lines []int
	for _, v := range NewTombstoneCommentRule().AnalyzeFile(core.NewFileContext("runtime/state.go", ".", []byte(code), nil)) {
		lines = append(lines, v.Line)
	}
	if fmt.Sprint(lines) != "[15 18]" {
		t.Fatalf("want only the two tombstones on lines 15 and 18, got %v", lines)
	}
}

// A pronoun before the removal word is the one that removes: "a line the
// commit added or one it removed" is the object of a clause about what the
// code does. "X removed." names the code that went away.
func TestTombstoneComment_RemovalByAPronounIsBehaviour(t *testing.T) {
	code := `package store

// undo reports a staged diff that removes a line the commit added or adds one it removed; blank lines do not count.
// restore brings back the rows they deleted.
// keep the entries we have removed, the rest are rebuilt.
func f() {}

// Old cache warmer removed.
// It removed.
func g() {}
`
	var lines []int
	for _, v := range NewTombstoneCommentRule().AnalyzeFile(core.NewFileContext("store/a.go", ".", []byte(code), nil)) {
		lines = append(lines, v.Line)
	}
	if fmt.Sprint(lines) != "[8]" {
		t.Fatalf("want a finding on line 8 only, got %v", lines)
	}
}

// A removal word at the end of a series of changes ("rows inserted, updated
// or deleted") names what the program does to the data, as "added and
// removed" does. A note on code that went away stays one.
func TestTombstoneComment_SeriesOfChangesIsBehaviour(t *testing.T) {
	code := `package store

// The statistics list the tables with rows inserted, updated or deleted,
// and the files created and removed by the job.
// A key written or deleted since the snapshot is read again.
func f() {}

// Old parser deprecated and removed.
// GetDB removed, replaced by Open.
func g() {}
`
	var lines []int
	for _, v := range NewTombstoneCommentRule().AnalyzeFile(core.NewFileContext("store/a.go", ".", []byte(code), nil)) {
		lines = append(lines, v.Line)
	}
	if fmt.Sprint(lines) != "[8 9]" {
		t.Fatalf("want findings on lines 8 and 9 only, got %v", lines)
	}
}

// «Устранён» says removed as often as «удалён»: a note that a wrapper or a
// duplicate was eliminated names code that went away. Eliminating a defect
// the code does now ("устранение дублей" as a noun, "будет устранена") is
// behavior.
func TestTombstoneComment_EliminatedIsRemoved(t *testing.T) {
	rule := NewTombstoneCommentRule()
	code := `package auth

// RefreshToken DELEGATION WRAPPER ФИЗИЧЕСКИ УСТРАНЕН
// loadKeyDeprecated - дубликат устранен
// CreateOrder и CreateRefund физически устранены - используйте orders.Service напрямую.

// Merge объединяет записи для устранения дублей.
func Merge() {}

// Ошибка будет устранена повторной попыткой.
func Retry() {}
`
	ctx := core.NewFileContext("auth/service.go", ".", []byte(code), nil)
	var lines []int
	for _, v := range rule.AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	if !slices.Equal(lines, []int{3, 4, 5}) {
		t.Fatalf("want tombstones on lines 3, 4, 5, got %v", lines)
	}
}

// A doc comment opens with the name it documents: a field or a function
// named Removed or Deleted is described, not buried. The same word opening a
// comment over code that does not declare it is still a tombstone.
func TestTombstoneComment_DocOfIdentifierNamedRemoved(t *testing.T) {
	rule := NewTombstoneCommentRule()
	code := `package notice

type Notice struct {
	// Removed — titles of the sections the agent has and the file no longer does
	Removed []string
}

// Deleted reports a record gone from the store.
func (n Notice) Deleted() bool { return len(n.Removed) > 0 }

// Removed the fallback to the old parser.
func Parse() {}
`
	ctx := core.NewFileContext("notice/notice.go", ".", []byte(code), nil)
	var lines []int
	for _, v := range rule.AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	if !slices.Equal(lines, []int{11}) {
		t.Fatalf("want the tombstone on line 11 alone, got %v", lines)
	}
}

// A godoc first sentence opens with the name declared below and describes
// it: "Stats counts the rows a sweep deleted" says what the type records.
// A later sentence of the same doc, or a name the code below does not
// declare, can still be a note on code that went away.
func TestTombstoneComment_GodocSentenceDescribesTheName(t *testing.T) {
	rule := NewTombstoneCommentRule()
	code := `package sweep

// Stats counts the rows a sweep deleted, or would delete, and kept.
type Stats struct {
	Deleted, Kept int
}

// Run sweeps the store and returns
// the rows it kept and the ones a pass removed.
func Run() Stats { return Stats{} }

// Prune drops stale rows. Legacy fallback removed.
func Prune() {}

// Cleaner counts the rows a sweep deleted.
func other() {}

// Load reads the config.
//
// Load legacy env fallback removed
func Load(c Stats) {}

// Store legacy env fallback removed
func Store() {}

func body() {
	// Retry loop removed, call once
	err := call(Retry)
	// Stats field Timeout removed
	var c Stats
}
`
	ctx := core.NewFileContext("sweep/sweep.go", ".", []byte(code), nil)
	var lines []int
	for _, v := range rule.AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	if !slices.Equal(lines, []int{12, 15, 20, 23, 27, 29}) {
		t.Fatalf("want tombstones on lines 12, 15, 20, 23, 27, 29 only, got %v", lines)
	}

	ts := `/** Fetcher counts the rows a sweep deleted. */
export class Fetcher {}

// Loader legacy env fallback removed
export function Loader() {}
`
	lines = nil
	for _, v := range rule.AnalyzeFile(core.NewFileContext("sweep/fetch.ts", ".", []byte(ts), nil)) {
		lines = append(lines, v.Line)
	}
	if !slices.Equal(lines, []int{4}) {
		t.Fatalf("want the TypeScript tombstone on line 4 alone, got %v", lines)
	}

	// A plural noun after the name is no verb: these stay notes on code.
	notes := `package sweep

// Client options removed, pass a Config instead
type Client struct{}

// Rows status column deleted
var Rows int

// Sync пакет старый удалён
func Sync() {}

type Config struct {
	// Name settings removed
	Name string
}
`
	lines = nil
	for _, v := range rule.AnalyzeFile(core.NewFileContext("sweep/notes.go", ".", []byte(notes), nil)) {
		lines = append(lines, v.Line)
	}
	if !slices.Equal(lines, []int{3, 6, 9, 13}) {
		t.Fatalf("want tombstones on lines 3, 6, 9, 13, got %v", lines)
	}
}

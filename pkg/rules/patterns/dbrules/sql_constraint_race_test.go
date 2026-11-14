package dbrules

import (
	"go/types"
	"slices"
	"sync"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// raceFiles has a method called directly from three handlers - its call
// sites in the shared index have room past their length - and through the
// interface it implements from a fourth: following its callers adds the
// interface's sites to its own.
var raceFiles = map[string]string{
	"storage/migrations/001_init.up.sql": `CREATE TABLE entries (id UUID PRIMARY KEY, document_number TEXT NOT NULL UNIQUE);`,
	"storage/entries.go": `package storage
import ("context"; "database/sql")
type Entry struct { DocumentNumber string }
type Adder interface { Add(ctx context.Context, entry Entry) error }
type Repo struct { db *sql.DB }
func (r *Repo) Add(ctx context.Context, entry Entry) error {
	_, err := r.db.ExecContext(ctx, ` + "`INSERT INTO entries (document_number) VALUES ($1)`" + `, entry.DocumentNumber) // want sql-constraint-violation-unmapped
	return err
}`,
	"web/handler.go": `package web
import ("crypto/rand"; "fmt"; "net/http"; "example.com/rulestest/storage")
type Server struct { repo *storage.Repo; adder storage.Adder }
func (s *Server) first(w http.ResponseWriter, r *http.Request) {
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: r.URL.Query().Get("n")}); err != nil { http.Error(w, err.Error(), 500) }
}
func (s *Server) second(w http.ResponseWriter, r *http.Request) {
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: r.URL.Query().Get("n")}); err != nil { http.Error(w, err.Error(), 500) }
}
func (s *Server) third(w http.ResponseWriter, r *http.Request) {
	if err := s.repo.Add(r.Context(), storage.Entry{DocumentNumber: r.URL.Query().Get("n")}); err != nil { http.Error(w, err.Error(), 500) }
}
func (s *Server) viaInterface(w http.ResponseWriter, r *http.Request) {
	var id [16]byte
	_, _ = rand.Read(id[:])
	number := fmt.Sprintf("REC-%08X", id[:4]) // want truncated-random-id-as-unique-number
	if err := s.adder.Add(r.Context(), storage.Entry{DocumentNumber: number}); err != nil { http.Error(w, err.Error(), 500) }
}`,
}

// raceRounds is how many fresh projects the concurrent run is tried on.
const raceRounds = 8

type projectRule interface {
	Name() string
	AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
}

// The two rules run at once on one project, as glint check runs project
// rules, and follow callers over the call sites every rule of the load
// shares: neither writes into them, so the race detector sees no race and
// each rule reports what it reports alone. A rule with migrations of its own
// builds its refusals apart, alongside the other's.
func TestRefusalRulesRunConcurrentlyOnSharedCallSites(t *testing.T) {
	cases := map[string]map[string]any{
		"same migrations": nil,
		"own migrations":  {"migrations": "storage/migrations"},
	}
	for name, settings := range cases {
		t.Run(name, func(t *testing.T) {
			constraint, truncated := NewSQLConstraintViolationUnmappedRule(), NewTruncatedRandomIDAsUniqueNumberRule()
			if settings != nil {
				require.NoError(t, truncated.Configure(settings))
			}
			list := []projectRule{constraint, truncated}
			// Whether the two goroutines meet in the index is up to the
			// scheduler: a few fresh projects give them several chances.
			for range raceRounds {
				project := rulestest.Project(t, raceFiles)
				results := make([][]*core.Violation, len(list))
				errs := make([]error, len(list))
				start := make(chan struct{})
				var wg sync.WaitGroup
				for i, rule := range list {
					wg.Go(func() {
						<-start
						results[i], errs[i] = rule.AnalyzeGoProject(project)
					})
				}
				close(start)
				wg.Wait()
				for i, rule := range list {
					require.NoError(t, errs[i], rule.Name())
					assert.Equal(t, patterntest.WantedLines(raceFiles, rule.Name()), patterntest.FoundLines(results[i]), rule.Name())
				}
			}
		})
	}
}

// Following the callers of a method reads the shared index and leaves it as
// it was, past the length of each slice too: the sites of the interface the
// method implements are added to a copy.
func TestCallSitesOfLeavesSharedIndexUntouched(t *testing.T) {
	callers, err := newCallerIndex(rulestest.Project(t, raceFiles))
	require.NoError(t, err)
	var add *types.Func
	for _, fn := range callers.funcs {
		if fn.Decl.Name.Name == "Add" && fn.Decl.Recv != nil {
			add, _ = fn.Info.Defs[fn.Decl.Name].(*types.Func)
		}
	}
	require.NotNil(t, add)
	direct := callers.sites[add]
	require.Len(t, direct, 3)
	require.Greater(t, cap(direct), len(direct), "the shared slice has room an append would write into")
	before := slices.Clone(direct[:cap(direct)])

	assert.Len(t, callers.callSitesOf(add), 4, "three direct sites and the interface's")
	assert.True(t, callers.reachesHandlerUnmapped(add, 0, map[*types.Func]bool{}))
	assert.NotNil(t, truncatedRandomUniqueOrigin(callers, add))

	assert.Len(t, callers.sites[add], 3)
	assert.Equal(t, before, direct[:cap(direct)], "nothing is written past the length of the shared slice")
}

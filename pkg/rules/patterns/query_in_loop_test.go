package patterns

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestQueryInLoopRule_Metadata(t *testing.T) {
	rule := NewQueryInLoopRule()
	assert.Equal(t, "query-in-loop", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

// queryInLoopModule holds the receivers the cases call. The receiver's name
// says "repository"; whether a call can reach a database is decided by the
// package its concrete type comes from.
var queryInLoopModule = map[string]string{
	// A repository over database/sql.
	"store/store.go": `package store

import "database/sql"

type UserRepo struct{ db *sql.DB }

func (r *UserRepo) GetByID(id string) (string, error) {
	var name string
	err := r.db.QueryRow("SELECT name FROM users WHERE id = $1", id).Scan(&name)
	return name, err
}
`,
	// A repository whose own package only reaches the database through a
	// project package in between.
	"dbconn/dbconn.go": `package dbconn

import "database/sql"

type Conn struct{ DB *sql.DB }
`,
	"orders/orders.go": `package orders

import "example.com/rulestest/dbconn"

type Repo struct{ conn *dbconn.Conn }

func (r *Repo) Load(id string) error { _ = r.conn; _ = id; return nil }
`,
	// A store backed by a remote API.
	"remote/remote.go": `package remote

import "net/http"

type Store struct{ client *http.Client }

func (s *Store) Fetch(id string) error { _ = s.client; _ = id; return nil }
`,
	// A version-control repository: a git binary wrapper, not a database.
	"vcs/vcs.go": `package vcs

import "os/exec"

type Repo struct{ Root string }

func (r *Repo) Git(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	return string(out), err
}
`,
	// An in-memory store.
	"memo/memo.go": `package memo

type Store struct{ items map[string]string }

func (s *Store) Get(id string) string { return s.items[id] }
`,
	"svc/service.go": `package svc

import (
	"context"
	"database/sql"
	"log"

	"example.com/rulestest/memo"
	"example.com/rulestest/orders"
	"example.com/rulestest/remote"
	"example.com/rulestest/store"
	"example.com/rulestest/vcs"
)

type GroupRepo interface {
	GetUserGroupAssignment(id string) (string, error)
}

type Service struct {
	repo   *store.UserRepo
	db     *sql.DB
	logger *log.Logger
}

func repoFieldInRange(s *Service, ids []string) {
	for _, id := range ids {
		s.repo.GetByID(id)
	}
}

func dbFieldInFor(ctx context.Context, s *Service) {
	for i := 0; i < 10; i++ {
		s.db.QueryRowContext(ctx, "SELECT 1")
	}
}

func interfaceRepoInLoop(groupRepo GroupRepo, ids []string) {
	for _, id := range ids {
		groupRepo.GetUserGroupAssignment(id)
	}
}

func transitiveRepoInLoop(orderRepo *orders.Repo, ids []string) {
	for _, id := range ids {
		orderRepo.Load(id)
	}
}

func remoteStoreInLoop(remoteStore *remote.Store, ids []string) {
	for _, id := range ids {
		remoteStore.Fetch(id)
	}
}

func loggerInLoop(s *Service, ids []string) {
	for _, id := range ids {
		s.logger.Print(id)
	}
}

func repoOutsideLoop(s *Service, id string) {
	s.repo.GetByID(id)
	for i := 0; i < 3; i++ {
		_ = i
	}
}

func repoInFuncLiteral(s *Service, ids []string) {
	for _, id := range ids {
		go func() { s.repo.GetByID(id) }()
	}
}

func gitRepoInLoop(repo *vcs.Repo, remotes []string) {
	for _, remote := range remotes {
		repo.Git("push", remote)
	}
}

func memoryStoreInLoop(cacheStore *memo.Store, ids []string) {
	for _, id := range ids {
		cacheStore.Get(id)
	}
}
`,
}

func TestQueryInLoopRule_Detection(t *testing.T) {
	project := rulestest.Project(t, queryInLoopModule)

	violations, err := NewQueryInLoopRule().AnalyzeGoProject(project)
	require.NoError(t, err)

	var reported []string
	for _, v := range violations {
		assert.Equal(t, "query_in_loop", v.Context["pattern"])
		reported = append(reported, v.Context["function"].(string))
	}
	sort.Strings(reported)
	assert.Equal(t, []string{
		"dbFieldInFor",
		"interfaceRepoInLoop",
		"remoteStoreInLoop",
		"repoFieldInRange",
		"transitiveRepoInLoop",
	}, reported)
}

func TestQueryInLoopRule_TestFilesExcluded(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"svc/repo.go": `package svc

type Repo interface{ GetByID(id string) error }
`,
		"svc/service_test.go": `package svc

func ex(repo Repo, ids []string) {
	for _, id := range ids {
		repo.GetByID(id)
	}
}
`,
	})

	violations, err := NewQueryInLoopRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func createQueryContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   strings.Split(code, "\n"),
		Content: []byte(code),
	}
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile(path, []byte(code))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx.SetGoAST(fset, astFile)
	return ctx
}

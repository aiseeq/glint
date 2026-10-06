package patterns

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func checkConstraintInputFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	base := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"migrations/001_init.up.sql": `CREATE TABLE protocols (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    category VARCHAR(32) NOT NULL CHECK (category IN ('dex', 'lending', 'yield')),
    risk_score SMALLINT CHECK (risk_score BETWEEN 1 AND 10)
);`,
		"db/db.go": `package db

import "context"

type Result struct{}

type Pool struct{}

func (p *Pool) ExecContext(ctx context.Context, sql string, args ...any) (Result, error) { return Result{}, nil }
`,
		"store/repo.go": `package store

import (
	"context"

	"example.com/rulestest/db"
)

type Protocol struct {
	ID        string
	Name      string
	Category  string
	RiskScore *int
}

type Repo struct{ pool *db.Pool }

func (r *Repo) Create(ctx context.Context, p *Protocol) error {
	query := ` + "`INSERT INTO protocols (id, name, category, risk_score) VALUES ($1, $2, $3, $4)`" + `
	_, err := r.pool.ExecContext(ctx, query, p.ID, p.Name, p.Category, p.RiskScore)
	return err
}
`,
	}
	for name, content := range files {
		base[name] = content
	}
	violations, err := NewSQLCheckConstraintInputUnvalidatedRule().AnalyzeGoProject(rulestest.Project(t, base))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

// A request body field written to a column the migration keeps within a set
// fails in the database when the client sends a value outside it: a check
// only for emptiness on the way does not keep it out, a check against the
// set does.
func TestSQLCheckConstraintInputUnvalidated(t *testing.T) {
	got := checkConstraintInputFindings(t, map[string]string{
		"service/service.go": `package service

import (
	"context"
	"errors"
	"slices"

	"example.com/rulestest/store"
)

var categories = []string{"dex", "lending", "yield"}

type Service struct{ repo *store.Repo }

func (s *Service) Create(ctx context.Context, p *store.Protocol) error {
	if p.Name == "" || p.Category == "" {
		return errors.New("name and category are required")
	}
	return s.repo.Create(ctx, p)
}

func validate(p *store.Protocol) error {
	if !slices.Contains(categories, p.Category) {
		return errors.New("unknown category")
	}
	if p.RiskScore != nil && *p.RiskScore > 10 {
		return errors.New("risk score out of range")
	}
	return nil
}

func (s *Service) CreateViaHelper(ctx context.Context, p *store.Protocol) error {
	if err := validate(p); err != nil {
		return err
	}
	return s.repo.Create(ctx, p)
}

func (s *Service) CreateChecked(ctx context.Context, p *store.Protocol) error {
	if !slices.Contains(categories, p.Category) {
		return errors.New("unknown category")
	}
	if p.RiskScore != nil && (*p.RiskScore < 1 || *p.RiskScore > 10) {
		return errors.New("risk score out of range")
	}
	return s.repo.Create(ctx, p)
}
`,
		"api/api.go": `package api

import (
	"encoding/json"
	"net/http"

	"example.com/rulestest/service"
	"example.com/rulestest/store"
)

type Router struct{ service *service.Service }

func (r *Router) Create(w http.ResponseWriter, req *http.Request) {
	var p store.Protocol
	if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := r.service.Create(req.Context(), &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (r *Router) CreateChecked(w http.ResponseWriter, req *http.Request) {
	var p store.Protocol
	if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := r.service.CreateChecked(req.Context(), &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (r *Router) CreateViaHelper(w http.ResponseWriter, req *http.Request) {
	var p store.Protocol
	if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := r.service.CreateViaHelper(req.Context(), &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (r *Router) CreateSwitched(w http.ResponseWriter, req *http.Request) {
	var p store.Protocol
	if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	switch p.Category {
	case "dex", "lending", "yield":
	default:
		http.Error(w, "unknown category", http.StatusBadRequest)
		return
	}
	p.RiskScore = nil
	if err := r.service.Create(req.Context(), &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
`,
	})
	assert.Equal(t, []string{"api/api.go:19"}, got)
}

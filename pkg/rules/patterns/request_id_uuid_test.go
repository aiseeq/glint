package patterns

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func requestIDUUIDFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	base := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n\nrequire (\n\tgithub.com/gorilla/mux v1.8.0\n\tgithub.com/google/uuid v1.6.0\n)\n\n" +
			"replace github.com/gorilla/mux => ./third_party/mux\n\nreplace github.com/google/uuid => ./third_party/uuid\n",
		"third_party/mux/go.mod":   "module github.com/gorilla/mux\n\ngo 1.24\n",
		"third_party/mux/mux.go":   "package mux\n\nimport \"net/http\"\n\nfunc Vars(r *http.Request) map[string]string { return nil }\n",
		"third_party/uuid/go.mod":  "module github.com/google/uuid\n\ngo 1.24\n",
		"third_party/uuid/uuid.go": "package uuid\n\ntype UUID [16]byte\n\nfunc Parse(s string) (UUID, error) { return UUID{}, nil }\n",
		"db/migrations/000001_init.up.sql": `CREATE TABLE accounts (id uuid PRIMARY KEY, name text NOT NULL);
CREATE TABLE entries (id uuid PRIMARY KEY, account_id uuid NOT NULL REFERENCES accounts(id), slug text NOT NULL, amount numeric NOT NULL);
CREATE TABLE audit (id bigserial PRIMARY KEY, note text);`,
		"store/store.go": `package store

import (
	"context"

	"github.com/google/uuid"
)

type Store struct{}

func (s *Store) Entry(ctx context.Context, id string) (string, error)        { return id, nil }
func (s *Store) Entries(ctx context.Context, accountID string) ([]string, error) { return nil, nil }
func (s *Store) BySlug(ctx context.Context, slug string) (string, error)      { return slug, nil }

func checkAccount(id string) error {
	_, err := uuid.Parse(id)
	return err
}

// Move checks the account itself before it reads anything.
func (s *Store) Move(ctx context.Context, entryID, accountID string) error {
	if err := checkAccount(accountID); err != nil {
		return err
	}
	return nil
}
`,
	}
	for name, content := range files {
		base[name] = content
	}
	violations, err := NewRequestIDUnparsedForUUIDColumnRule().AnalyzeGoProject(rulestest.Project(t, base))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

// An id the client sent in the path, the query or the body reaches a call
// unparsed while its column is uuid: a malformed one fails in the database
// and the client gets a 500 for its own mistake.
func TestRequestIDUnparsedForUUIDColumn(t *testing.T) {
	assert.Equal(t, []string{"api/api.go:20", "api/api.go:28", "api/api.go:41"}, requestIDUUIDFindings(t, map[string]string{
		"api/api.go": `package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"example.com/rulestest/store"
)

type Router struct{ store *store.Store }

func fail(w http.ResponseWriter, err error) { http.Error(w, err.Error(), http.StatusInternalServerError) }

func (r *Router) entry(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	id := mux.Vars(req)["id"]
	if _, err := r.store.Entry(ctx, id); err != nil {
		fail(w, err)
	}
}

func (r *Router) entries(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	accountID := query.Get("account_id")
	if _, err := r.store.Entries(req.Context(), accountID); err != nil {
		fail(w, err)
	}
}

func (r *Router) link(w http.ResponseWriter, req *http.Request) {
	var body struct {
		AccountID string ` + "`json:\"accountId\"`" + `
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		return
	}
	if _, err := r.store.Entries(req.Context(), body.AccountID); err != nil {
		fail(w, err)
	}
}

// Parsed first, a text column, a number column and an id the callee checks
// itself are fine.
func (r *Router) parsed(w http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)["id"]
	if _, err := uuid.Parse(id); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	_, _ = r.store.Entry(req.Context(), id)
	_, _ = r.store.BySlug(req.Context(), req.URL.Query().Get("slug"))
	_ = r.store.Move(req.Context(), "", req.URL.Query().Get("account_id"))
}

type client struct{ accounts []string }

func (c client) Allows(id string) bool {
	for _, a := range c.accounts {
		if a == id {
			return true
		}
	}
	return false
}

func resolve(c client, requested string) (string, error) {
	if requested == "" {
		return "", errors.New("required")
	}
	if !c.Allows(requested) {
		return "", errors.New("forbidden")
	}
	return requested, nil
}

// An id checked against the client's allowed set is refused before the
// database sees it.
func (r *Router) scoped(w http.ResponseWriter, req *http.Request) {
	id, err := resolve(client{}, req.URL.Query().Get("account_id"))
	if err != nil {
		return
	}
	_, _ = r.store.Entries(req.Context(), id)
	other := mux.Vars(req)["id"]
	if !(client{}).Allows(other) {
		return
	}
	_, _ = r.store.Entry(req.Context(), other)
}
`,
	}))
}

package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A layer that answers "not found" with its own sentinel, or with text, leaves
// a caller's check for the driver's sentinel dead: the check never matches,
// and a missing record leaves as a server error.
func TestErrorsIsTargetUnreachable(t *testing.T) {
	violations, err := NewErrorsIsTargetUnreachableRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"store/store.go": `package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("not found")

var ErrAbsent = ErrNotFound

type Helper struct{}

func (h *Helper) Wrap(err error, op string) error {
	if err == nil {
		return nil
	}
	if err == sql.ErrNoRows {
		return fmt.Errorf("%s: no record", op)
	}
	return fmt.Errorf("%s: %w", op, err)
}

type Repo struct {
	db     *sql.DB
	helper *Helper
}

func (r *Repo) Touch(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE items SET seen = true WHERE id = $1", id)
	if err != nil {
		return r.helper.Wrap(err, "touch")
	}
	return nil
}

func (r *Repo) Find(ctx context.Context, id string) (string, error) {
	var name string
	err := r.db.QueryRowContext(ctx, "SELECT name FROM items WHERE id = $1", id).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrAbsent
		}
		return "", r.helper.Wrap(err, "find")
	}
	return name, nil
}

func (r *Repo) Load(ctx context.Context, id string) (string, error) {
	var name string
	if err := r.db.QueryRowContext(ctx, "SELECT name FROM items WHERE id = $1", id).Scan(&name); err != nil {
		return "", fmt.Errorf("load: %w", err)
	}
	return name, nil
}

func (r *Repo) Mark(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, "UPDATE items SET marked = true WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("item %s not found", id)
	}
	return nil
}

type Status string

type Code struct{ value string }

func (c *Code) Scan(src any) error {
	if src == nil {
		return ErrNotFound
	}
	return nil
}

func (r *Repo) State(ctx context.Context, id string) (Status, error) {
	var state Status
	err := r.db.QueryRowContext(ctx, "SELECT state FROM items WHERE id = $1", id).Scan(&state)
	return state, err
}

func (r *Repo) Coded(ctx context.Context, id string) (Code, error) {
	var code Code
	err := r.db.QueryRowContext(ctx, "SELECT code FROM items WHERE id = $1", id).Scan(&code)
	return code, err
}

type MissingError struct{ cause error }

func (e *MissingError) Error() string { return "missing" }

func (e *MissingError) Unwrap() error { return e.cause }

func (r *Repo) Drop(ctx context.Context, id string) error {
	if id == "" {
		return &MissingError{}
	}
	return nil
}
`,
		"service/service.go": `package service

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"example.com/rulestest/store"
)

type Store interface {
	Touch(ctx context.Context, id string) error
	Find(ctx context.Context, id string) (string, error)
	Load(ctx context.Context, id string) (string, error)
	Mark(ctx context.Context, id string) error
	Drop(ctx context.Context, id string) error
	State(ctx context.Context, id string) (store.Status, error)
	Coded(ctx context.Context, id string) (store.Code, error)
}

var ErrMissing = errors.New("missing")

type Service struct{ store Store }

func (s *Service) Touch(ctx context.Context, id string) error {
	err := s.store.Touch(ctx, id)
	if err == sql.ErrNoRows {
		return ErrMissing
	}
	return err
}

func (s *Service) Find(ctx context.Context, id string) error {
	_, err := s.store.Find(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMissing
	}
	if errors.Is(err, store.ErrNotFound) {
		return ErrMissing
	}
	return err
}

func (s *Service) Load(ctx context.Context, id string) error {
	_, err := s.store.Load(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMissing
	}
	return err
}

func (s *Service) Mark(ctx context.Context, id string) error {
	if err := s.store.Mark(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrMissing
		}
		return err
	}
	return nil
}

func (s *Service) Drop(ctx context.Context, id string) error {
	err := s.store.Drop(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrMissing
	}
	return err
}

func (s *Service) State(ctx context.Context, id string) error {
	_, err := s.store.State(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrMissing
	}
	return err
}

func (s *Service) Coded(ctx context.Context, id string) error {
	_, err := s.store.Coded(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrMissing
	}
	return err
}

func (s *Service) Serve(srv *http.Server) error {
	err := srv.ListenAndServe()
	if errors.Is(err, store.ErrNotFound) {
		return ErrMissing
	}
	return err
}

func (s *Service) Run(ctx context.Context, run func() error) error {
	err := run()
	if errors.Is(err, store.ErrNotFound) {
		return ErrMissing
	}
	return err
}

type CodeError struct{ Code string }

func (e *CodeError) Error() string { return e.Code }

type Result struct{ Err *CodeError }

func NotFound(r Result) bool {
	return errors.Is(r.Err, store.ErrNotFound)
}

type LinkedError struct{ cause error }

func (e *LinkedError) Error() string { return "linked" }

func (e *LinkedError) Unwrap() error { return e.cause }

type Linked struct{ Err *LinkedError }

func LinkedNotFound(r Linked) bool {
	return errors.Is(r.Err, store.ErrNotFound)
}

var setupFailure error

func Setup(ok bool) {
	if !ok {
		setupFailure = errors.New("setup failed")
	}
}

func Ready() error {
	if setupFailure != nil {
		return setupFailure
	}
	return nil
}
`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"service/service.go:110", "service/service.go:28", "service/service.go:36", "service/service.go:55", "service/service.go:73"}, foundLines(violations))
}

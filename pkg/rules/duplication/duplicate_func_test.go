package duplication

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func duplicateFuncLines(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewDuplicateFuncAcrossPackagesRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var lines []string
	for _, v := range violations {
		lines = append(lines, v.File+":"+strconv.Itoa(v.Line))
	}
	return lines
}

// Two packages keep their own copy of one small helper: the bodies differ in
// details, so cross-file-duplicate does not see them, and a fix of one (the
// second copy does not wrap a cause twice) never reaches the other.
func TestDuplicateFuncAcrossPackages(t *testing.T) {
	files := map[string]string{
		"poller/poller.go": `package poller

import (
	"context"
	"fmt"
)

func withContextCause(ctx context.Context, err error) error {
	if err == nil || ctx.Err() == nil {
		return err
	}
	return fmt.Errorf("%w: %w", ctx.Err(), err)
}
`,
		"sender/sender.go": `package sender

import (
	"context"
	"errors"
	"fmt"
)

func withContextCause(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	return err
}
`,
	}
	assert.Equal(t, []string{"poller/poller.go:8", "sender/sender.go:9"}, duplicateFuncLines(t, files))
}

// One name with another signature, a one-word name every package has its own
// of (run, handle), a constructor of the package's own type, a thin wrapper
// over a shared helper, an exported function, a method, a function without
// parameters, a test file, a mock package and a stand-in package for tests
// (settingstest next to the real api) are not copies.
func TestDuplicateFuncAcrossPackagesAllowed(t *testing.T) {
	files := map[string]string{
		"shared/errs/errs.go": `package errs

import "context"

func WithCause(ctx context.Context, err error) error { return err }
`,
		"a/a.go": `package a

import (
	"context"

	"example.com/rulestest/shared/errs"
)

type store struct{}

func newStore(dsn string) *store { return &store{} }

func parseAmount(s string) (int, error) { return len(s), nil }

func run(ctx context.Context) error { return nil }

func wrapCause(ctx context.Context, err error) error {
	return errs.WithCause(ctx, err)
}

func FormatAmount(n int) string { return "" }

func (s *store) loadRows(limit int) error { return nil }

func defaultLimit() int { return 10 }
`,
		"a/a_test.go": `package a

func mustParse(s string) int { return 0 }
`,
		"b/b.go": `package b

import (
	"context"

	"example.com/rulestest/shared/errs"
)

type store struct{}

func newStore(dsn string) *store { return &store{} }

func parseAmount(s string) (int64, error) { return int64(len(s)), nil }

func run(ctx context.Context) error { return ctx.Err() }

func wrapCause(ctx context.Context, err error) error {
	return errs.WithCause(ctx, err)
}

func FormatAmount(n int) string { return "n" }

func (s *store) loadRows(limit int) error { return nil }

func defaultLimit() int { return 20 }
`,
		"b/b_test.go": `package b

func mustParse(s string) int { return 1 }
`,
		"a/mocks/mocks.go": `package mocks

func parseAmount(s string) (int, error) { return 0, nil }
`,
		"api/server.go": `package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write json", "error", err)
	}
}
`,
		"settings/settingstest/server.go": `// Package settingstest is an in-memory stand-in for the settings API.
package settingstest

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}
`,
	}
	assert.Empty(t, duplicateFuncLines(t, files))
}

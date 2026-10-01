package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A query parameter that does not parse is the client's mistake: answering
// it with page 1 hides the mistake and serves a page nobody asked for.
func TestErrorMasking_CompoundGuardOnRequestInput(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

import (
	"net/http"
	"strconv"
)

type Pagination struct{ Page, Limit int }

func FromQuery(r *http.Request, defaultLimit int) Pagination {
	query := r.URL.Query()
	page := 1
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	limit := defaultLimit
	if l := query.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	return Pagination{Page: page, Limit: limit}
}
`)
	assert.Len(t, found, 2, "both parameters fall back silently: %v", found)
}

// A failed lookup reads as "not done yet": the duplicate is processed again.
// The err of the lookup lives in its own block; the err checked later in the
// function is another variable.
func TestErrorMasking_CompoundGuardOnLookupInBlock(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

type store interface {
	Status(hash string, out *string) error
	Save(hash string) error
}

type logger interface{ Info(msg string) }

func Process(s store, log logger, hash string) error {
	var alreadyDone bool
	if hash != "" {
		var status string
		err := s.Status(hash, &status)
		if err == nil && status == "completed" {
			alreadyDone = true
			log.Info("duplicate")
		}
	}
	if alreadyDone {
		return nil
	}
	err := s.Save(hash)
	if err != nil {
		return err
	}
	return nil
}
`)
	require.Len(t, found, 1, "lookup failure taken for not-done: %v", found)
}

// A setting read from the environment keeps its default when it does not
// parse: the default is next to the guard, and the value is not a request.
func TestErrorMasking_CompoundGuardRefiningDefault(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

import (
	"os"
	"strconv"
)

func workers() int {
	n := 4
	if v, err := strconv.Atoi(os.Getenv("WORKERS")); err == nil && v > 0 {
		n = v
	}
	return n
}
`)
	assert.Empty(t, found)
}

// A parse inside a compound guard tests the shape of a value the code
// already holds: an expression that does not parse is simply not a selector.
func TestErrorMasking_CompoundGuardOnParse(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

import (
	"go/ast"
	"go/parser"
)

func classify(text string) string {
	kind := "other"
	if expr, err := parser.ParseExpr(text); err == nil && isSelector(expr) {
		kind = "selector"
	}
	return kind
}

func isSelector(expr ast.Expr) bool {
	_, ok := expr.(*ast.SelectorExpr)
	return ok
}
`)
	assert.Empty(t, found)
}

// A server's main package keeps request handling too: the regex patterns
// stay off command packages, the success-only guard does not.
func TestErrorMasking_SuccessOnlyGuardInCommandPackage(t *testing.T) {
	ctx := rulestest.GoFile(t, "cmd/server/main.go", `package main

type store interface{ Status(hash string, out *string) error }

func alreadyDone(s store, hash string) bool {
	var done bool
	var status string
	err := s.Status(hash, &status)
	if err == nil && status == "completed" {
		done = true
	}
	return done
}
`)
	var found []any
	for _, v := range NewErrorMaskingRule().AnalyzeFile(ctx) {
		found = append(found, v.Context["pattern"])
	}
	assert.Equal(t, []any{"success_only_guard"}, found)
}

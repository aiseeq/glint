package patterns

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorWrapFindings runs error-wrap over a typed project and lists findings as
// file:line plus message.
func errorWrapFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	var got []string
	for _, v := range runRuleOnFiles(t, NewErrorWrapRule(), files) {
		got = append(got, fmt.Sprintf("%s:%d %s", v.File, v.Line, v.Message))
	}
	return got
}

// An error from another package of the project already carries the context
// its function added — that function is checked where the error arises — so
// passing it on is not a lost context. The standard library's error is.
func TestErrorWrapReportsOnlyErrorsFromForeignCode(t *testing.T) {
	got := errorWrapFindings(t, map[string]string{
		"store/store.go": `package store

import (
	"fmt"
	"os"
)

// Load wraps its own failures.
func Load(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load ledger %s: %w", path, err)
	}
	return data, nil
}
`,
		"app/app.go": `package app

import (
	"os"

	"example.com/rulestest/store"
)

func Run(path string) error {
	if _, err := store.Load(path); err != nil {
		return err
	}
	if err := prepare(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return nil
}

func prepare(path string) error {
	_, err := store.Load(path)
	return err
}
`,
	})
	assert.Equal(t, []string{
		"app/app.go:17 Error from os.Remove returned without context; say what failed with fmt.Errorf",
	}, got)
}

// An interface method belongs to the package that declares the interface: a
// project interface is implemented and checked in the project, an interface of
// the standard library is foreign code.
func TestErrorWrapInterfaceMethodBelongsToItsDeclaringPackage(t *testing.T) {
	got := errorWrapFindings(t, map[string]string{
		"ledger/ledger.go": `package ledger

import (
	"context"
	"io"
)

type Store interface {
	Save(ctx context.Context, id string) error
}

type Service struct {
	store Store
	out   io.Writer
}

func (s *Service) Record(ctx context.Context, id string) error {
	if err := s.store.Save(ctx, id); err != nil {
		return err
	}
	if _, err := s.out.Write([]byte(id)); err != nil {
		return err
	}
	return nil
}
`,
	})
	assert.Equal(t, []string{
		"ledger/ledger.go:22 Error from (io.Writer).Write returned without context; say what failed with fmt.Errorf",
	}, got)
}

// A context's Err reports the caller's own cancellation: context.Canceled
// needs no call-site context, and the standard library returns it as is.
func TestErrorWrapIgnoresContextErr(t *testing.T) {
	got := errorWrapFindings(t, map[string]string{
		"poller/poller.go": `package poller

import "context"

func Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
`,
	})
	assert.Empty(t, got)
}

// A branch that wraps the error before returning it adds the context the rule
// asks for, even though the return itself hands back the variable.
func TestErrorWrapIgnoresErrorRewrappedInBranch(t *testing.T) {
	got := errorWrapFindings(t, map[string]string{
		"script/script.go": `package script

import (
	"errors"
	"fmt"
	"os"
)

func Write(path, body string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create script: %w", err)
	}
	_, err = file.WriteString(body)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		err = fmt.Errorf("write script: %w", err)
		if removeErr := os.Remove(path); removeErr != nil {
			err = errors.Join(err, removeErr)
		}
		return err
	}
	return nil
}
`,
	})
	assert.Empty(t, got)
}

// A decoding hook (json.Unmarshaler, yaml.Unmarshaler) hands the error back to
// the package that called it: that package reports it with its own position,
// and the hook has nothing to add.
func TestErrorWrapIgnoresErrorReturnedToTheCallingPackage(t *testing.T) {
	got := errorWrapFindings(t, map[string]string{
		"settle/lock.go": `package settle

import "encoding/json"

type Lock struct {
	Name string
	Mode string
}

// UnmarshalJSON accepts "read", "write" or {name, mode}.
func (l *Lock) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		l.Name = "work-tree"
		return json.Unmarshal(data, &l.Mode)
	}
	type plain Lock
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*l = Lock(p)
	return nil
}

// Parse is not a hook: its caller does not know json was involved.
func Parse(data []byte) (Lock, error) {
	var l Lock
	if err := json.Unmarshal(data, &l); err != nil {
		return Lock{}, err
	}
	return l, nil
}
`,
	})
	assert.Equal(t, []string{
		"settle/lock.go:29 Error from json.Unmarshal returned without context; say what failed with fmt.Errorf",
	}, got)
}

// With type information the source of an error assigned in another block is
// the latest earlier assignment to the same variable.
func TestErrorWrapFindsSourceAssignedInAnotherBlock(t *testing.T) {
	got := errorWrapFindings(t, map[string]string{
		"cache/cache.go": `package cache

import "os"

func Reset(path string, force bool) error {
	var err error
	if force {
		err = os.RemoveAll(path)
	}
	if err != nil {
		return err
	}
	return nil
}
`,
	})
	assert.Equal(t, []string{
		"cache/cache.go:11 Error from os.RemoveAll returned without context; say what failed with fmt.Errorf",
	}, got)
}

// Without type information only a call qualified by an import counts, and a
// project import is not foreign.
func TestErrorWrapUntypedReportsOnlyForeignImports(t *testing.T) {
	violations := runRuleOnBrokenFiles(t, NewErrorWrapRule(), map[string]string{
		"store/store.go": "package store\n\nfunc Load(path string) error { return nil }\n",
		"app/app.go": `package app

import (
	"os"

	"example.com/rulestest/store"
)

func Run(path string) error {
	if err := store.Load(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return nil
}

func broken() int { return "not an int" }
`,
	})
	require.Len(t, violations, 1)
	assert.Equal(t, 14, violations[0].Line)
	assert.Contains(t, violations[0].Message, "os.Remove")
}

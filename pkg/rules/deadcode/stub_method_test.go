package deadcode

import (
	"strings"
	"testing"
)

// A domain error constructor formats its parameters into the message; a word
// like "removed" in that message must not make the function a stub.
func TestStubMethodIgnoresDomainErrorConstructor(t *testing.T) {
	code := `package svc

import "fmt"

func ErrUserRemoved(id string) error {
	return fmt.Errorf("user %s was removed", id)
}
`
	violations := NewStubMethodRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 0 {
		t.Fatalf("expected no findings, got %d: %s", len(violations), violations[0].Message)
	}
}

func TestStubMethodReportsFixedNotImplementedError(t *testing.T) {
	code := `package svc

import "errors"

type Service struct{}

func (s *Service) Process() error {
	return errors.New("not implemented")
}
`
	violations := NewStubMethodRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
	if !strings.Contains(violations[0].Message, "Service.Process") {
		t.Fatalf("message %q does not name Service.Process", violations[0].Message)
	}
}

// Generic receivers must keep the type name in the finding.
func TestStubMethodNamesGenericReceiver(t *testing.T) {
	code := `package svc

import "errors"

type Box[T any] struct{}

func (b *Box[T]) Close() error {
	return errors.New("not implemented")
}
`
	violations := NewStubMethodRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
	if !strings.Contains(violations[0].Message, "Box.Close") {
		t.Fatalf("message %q does not name Box.Close", violations[0].Message)
	}
}

func TestStubMethodReportsPanicWithDeprecatedMessage(t *testing.T) {
	code := `package svc

func Old() {
	panic("deprecated: use New instead")
}
`
	violations := NewStubMethodRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
}

// A real parser whose fallback error happens to say "not implemented" is not
// a stub: other return paths do the work.
func TestStubMethodIgnoresFallbackErrorOfRealFunction(t *testing.T) {
	code := `package svc

import "errors"

type Mode int

const (
	Fast Mode = iota + 1
	Safe
)

func ParseMode(s string) (Mode, error) {
	switch s {
	case "fast":
		return Fast, nil
	case "safe":
		return Safe, nil
	}
	return 0, errors.New("mode not implemented")
}
`
	violations := NewStubMethodRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 0 {
		t.Fatalf("expected no findings, got %d: %s", len(violations), violations[0].Message)
	}
}

// Work before the only return does not make a stub real: every path still
// ends in "not implemented".
func TestStubMethodReportsStubWithLoggingBeforeReturn(t *testing.T) {
	code := `package svc

import (
	"errors"
	"log"
)

type Client struct{}

func (c *Client) Sync() error {
	log.Println("sync requested")
	return errors.New("not implemented")
}
`
	violations := NewStubMethodRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
}

// A production file whose name merely contains "test_" (latest_release.go)
// is not a test utility.
func TestStubMethodChecksFileNamedLikeTestPrefix(t *testing.T) {
	code := `package svc

import "errors"

type Client struct{}

func (c *Client) Fetch() error { return errors.New("not implemented") }
`
	violations := NewStubMethodRule().AnalyzeFile(parseGoContext(t, "latest_release.go", code))
	if len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
}

package deadcode

import (
	"strings"
	"testing"
)

func TestNilReturnStubReportsMultiNilReturn(t *testing.T) {
	code := `package svc

type Service struct{}

func (s *Service) GetData() (any, error) {
	return nil, nil
}
`
	violations := NewNilReturnStubRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
	if !strings.Contains(violations[0].Message, "Service.GetData") {
		t.Fatalf("message %q does not name Service.GetData", violations[0].Message)
	}
}

func TestNilReturnStubReportsComplianceComment(t *testing.T) {
	code := `package svc

type Service struct{}

// Process exists for INTERFACE COMPLIANCE only.
func (s *Service) Process() error {
	return nil
}
`
	violations := NewNilReturnStubRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
}

// A single bare "return nil" without a compliance comment is a legitimate
// no-op implementation, not a reported stub.
func TestNilReturnStubIgnoresSingleNilWithoutComment(t *testing.T) {
	code := `package svc

type Service struct{}

func (s *Service) Close() error {
	return nil
}
`
	violations := NewNilReturnStubRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 0 {
		t.Fatalf("expected no findings, got %d: %s", len(violations), violations[0].Message)
	}
}

func TestNilReturnStubIgnoresMethodWithLogic(t *testing.T) {
	code := `package svc

type Service struct{ n int }

func (s *Service) Get() (any, error) {
	s.n++
	return nil, nil
}
`
	violations := NewNilReturnStubRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 0 {
		t.Fatalf("expected no findings, got %d: %s", len(violations), violations[0].Message)
	}
}

// Receivers with multiple type parameters must keep the type name too.
func TestNilReturnStubNamesGenericReceiverWithTypeParamList(t *testing.T) {
	code := `package svc

type Pair[K comparable, V any] struct{}

func (p *Pair[K, V]) Values() (any, any) {
	return nil, nil
}
`
	violations := NewNilReturnStubRule().AnalyzeFile(parseGoContext(t, "svc.go", code))
	if len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
	if !strings.Contains(violations[0].Message, "Pair.Values") {
		t.Fatalf("message %q does not name Pair.Values", violations[0].Message)
	}
}

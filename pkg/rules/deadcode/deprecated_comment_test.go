package deadcode

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

// A rule that documents the pattern it detects used to report itself: the
// example inside its godoc block was read as a deprecation marker.
func TestDeprecatedCommentIgnoresGodocExamples(t *testing.T) {
	code := `package svc

// Finder reports declarations that should be reviewed.
//
// Detects patterns like:
//
//	// Deprecated: use NewFunction instead
//	func OldFunction() {}
//
//	// DEPRECATED - this will be removed
//	func LegacyMethod() {}
type Finder struct{}
`
	ctx := deprecatedCommentContext(t, "svc.go", code)
	if violations := NewDeprecatedCommentRule().AnalyzeFile(ctx); len(violations) != 0 {
		t.Fatalf("expected no findings, got %d: %s", len(violations), violations[0].Code)
	}
}

// A loose phrase continuing a sentence is prose, not a marker.
func TestDeprecatedCommentIgnoresMidParagraphMention(t *testing.T) {
	code := `package svc

// Finder reports comments that admit a runtime
// legacy code path — "Legacy mode", "Legacy compatibility".
type Finder struct{}
`
	ctx := deprecatedCommentContext(t, "svc.go", code)
	if violations := NewDeprecatedCommentRule().AnalyzeFile(ctx); len(violations) != 0 {
		t.Fatalf("expected no findings, got %d: %s", len(violations), violations[0].Code)
	}
}

// The canonical marker is still reported wherever it appears.
func TestDeprecatedCommentStillReportsCanonicalMarker(t *testing.T) {
	code := `package svc

// OldFinder finds things.
// Deprecated: use Finder instead.
type OldFinder struct{}
`
	ctx := deprecatedCommentContext(t, "svc.go", code)
	if violations := NewDeprecatedCommentRule().AnalyzeFile(ctx); len(violations) != 1 {
		t.Fatalf("got %d findings, want 1", len(violations))
	}
}

func deprecatedCommentContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := core.NewFileContext("/"+path, "/", []byte(code), core.DefaultConfig())
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile(path, []byte(code))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx.SetGoAST(fset, astFile)
	return ctx
}

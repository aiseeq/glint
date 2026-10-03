package deadcode

import (
	"path/filepath"

	"github.com/aiseeq/glint/pkg/core"
)

// testMentions answers "does a Go file outside the typed load in this
// package's directory mention this name". Test packages are not part of the
// typed load (packages.Load runs with Tests:false), so a white-box test
// reading an internal field or symbol is invisible to typed analysis; this
// name-based scan keeps such members from being reported as dead. Name
// matching is coarse on purpose: erring toward "mentioned" only costs a
// finding, erring the other way reports live code.
type testMentions struct {
	// identifiers mentioned in the scanned files, keyed by package directory
	names map[string]map[string]bool
}

type mentionsKey struct{}

// projectMentions is the name scan of every Go file outside the typed load —
// tests, build-excluded files, and package files the configuration excluded
// from analysis — built once per project and shared by the dead-code rules.
func projectMentions(ctx *core.GoProjectContext) (*testMentions, error) {
	return core.Shared(ctx, mentionsKey{}, func() (*testMentions, error) {
		mentions := newUntypedMentions(ctx)
		for _, pkg := range ctx.Packages {
			if pkg == nil || pkg.Package == nil {
				continue
			}
			if err := mentions.addUnloadedPackageFiles(pkg); err != nil {
				return nil, err
			}
		}
		return mentions, nil
	})
}

// newUntypedMentions scans every Go file the typed load leaves out: test
// files, and files the build excludes on this platform (foo_windows.go, a
// build tag). Such a file can still use a package's symbols; the scan reads
// the text, so a file that does not even parse (a template behind
// //go:build ignore) costs nothing but a few spurious words.
func newUntypedMentions(ctx *core.GoProjectContext) *testMentions {
	typed := make(map[*core.FileContext]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil {
			continue
		}
		for _, fileCtx := range pkg.Files {
			typed[fileCtx] = true
		}
	}
	mentions := &testMentions{names: make(map[string]map[string]bool)}
	for _, fileCtx := range ctx.Files {
		if fileCtx == nil || !fileCtx.IsGoFile() || (typed[fileCtx] && !fileCtx.IsTestFile()) {
			continue
		}
		mentions.add(fileCtx)
	}
	return mentions
}

// add records the identifier-shaped words of one file under its directory.
func (m *testMentions) add(fileCtx *core.FileContext) {
	dir := filepath.Dir(fileCtx.Path)
	set := m.names[dir]
	if set == nil {
		set = make(map[string]bool)
		m.names[dir] = set
	}
	collectIdentifierWords(string(fileCtx.Content), set)
}

// mentioned reports whether a scanned file in the package directory of
// declCtx uses the identifier.
func (m *testMentions) mentioned(declCtx *core.FileContext, name string) bool {
	return m.names[filepath.Dir(declCtx.Path)][name]
}

// mentionedAnywhere reports whether any scanned file of the project uses the
// identifier: an exported member is reachable from tests of other packages
// (a test helper's counter asserted by the package it fakes for).
func (m *testMentions) mentionedAnywhere(name string) bool {
	for _, set := range m.names {
		if set[name] {
			return true
		}
	}
	return false
}

// collectIdentifierWords splits source text into identifier-shaped words. A
// lexer would also see through strings and comments, but a mention in either
// still signals intent, and over-matching is the safe direction here.
func collectIdentifierWords(content string, into map[string]bool) {
	start := -1
	for i := 0; i <= len(content); i++ {
		isWord := i < len(content) && isIdentifierChar(content[i])
		switch {
		case isWord && start < 0:
			start = i
		case !isWord && start >= 0:
			into[content[start:i]] = true
			start = -1
		}
	}
}

func isIdentifierChar(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

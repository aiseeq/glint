package deadcode

import (
	"path/filepath"

	"github.com/aiseeq/glint/pkg/core"
)

// testMentions answers "does a *_test.go file of this package mention this
// name". Test packages are not part of the typed load (packages.Load runs with
// Tests:false), so a white-box test reading an internal field or symbol is
// invisible to typed analysis; this name-based scan keeps such members from
// being reported as dead. Name matching is coarse on purpose: erring toward
// "mentioned" only costs a finding, erring the other way reports live code.
type testMentions struct {
	// identifiers mentioned in test files, keyed by package directory
	names map[string]map[string]bool
}

// newTestMentions scans every *_test.go context once.
func newTestMentions(files []*core.FileContext) *testMentions {
	mentions := &testMentions{names: make(map[string]map[string]bool)}
	for _, fileCtx := range files {
		if fileCtx == nil || !fileCtx.IsTestFile() || !fileCtx.IsGoFile() {
			continue
		}
		dir := filepath.Dir(fileCtx.Path)
		set := mentions.names[dir]
		if set == nil {
			set = make(map[string]bool)
			mentions.names[dir] = set
		}
		collectIdentifierWords(string(fileCtx.Content), set)
	}
	return mentions
}

// mentioned reports whether a test file in the package directory of declCtx
// uses the identifier.
func (m *testMentions) mentioned(declCtx *core.FileContext, name string) bool {
	return m.names[filepath.Dir(declCtx.Path)][name]
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

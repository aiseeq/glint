package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestMockIdentifierRule(t *testing.T) {
	rule := NewMockIdentifierRule()

	tests := []struct {
		name          string
		path          string
		code          string
		expectedCount int
	}{
		{
			// The founding case: a "mock" quote path that is in fact the live
			// path for manual execution, and silently drifted from the real one.
			name: "method with Mock in middle",
			path: "/src/backend/quote.go",
			code: `package quote
type Admin struct{}
func (a *Admin) createMockQuote() {}`,
			expectedCount: 1,
		},
		{
			name: "function with Fake prefix",
			path: "/src/backend/payload.go",
			code: `package payload
func FakePayload() {}`,
			expectedCount: 1,
		},
		{
			name: "type with Stub prefix",
			path: "/src/backend/notify.go",
			code: `package notify
type StubNotifier struct{}`,
			expectedCount: 1,
		},
		{
			name: "const with Dummy segment",
			path: "/src/backend/config.go",
			code: `package config
const DummyTimeout = 30`,
			expectedCount: 1,
		},
		{
			name: "camelCase lowercase marker at name start",
			path: "/src/backend/quote.go",
			code: `package quote
var mockMode = false`,
			expectedCount: 1,
		},
		{
			name: "snake_case marker",
			path: "/src/backend/flags.go",
			code: `package flags
var mock_response = "{}"`,
			expectedCount: 1,
		},
		{
			name: "marker as suffix",
			path: "/src/backend/flags.go",
			code: `package flags
var allowMock = false`,
			expectedCount: 1,
		},
		{
			name: "bare marker name",
			path: "/src/backend/flags.go",
			code: `package flags
var mock = false`,
			expectedCount: 1,
		},
		{
			name: "Mockingbird NOT flagged (incidental substring)",
			path: "/src/backend/birds.go",
			code: `package birds
func MockingbirdSong() {}`,
			expectedCount: 0,
		},
		{
			name: "smock and fakest NOT flagged",
			path: "/src/backend/cloth.go",
			code: `package cloth
var smockPattern = 1
func FakestNews() {}`,
			expectedCount: 0,
		},
		{
			name: "Stubborn NOT flagged",
			path: "/src/backend/traits.go",
			code: `package traits
type StubbornRetry struct{}`,
			expectedCount: 0,
		},
		{
			name: "test file skipped",
			path: "/src/backend/quote_test.go",
			code: `package quote
type MockRepo struct{}`,
			expectedCount: 0,
		},
		{
			// Generated code is recognised by its header and dropped by the core.
			name: "gen.go name without the generated header is checked",
			path: "/src/backend/types.gen.go",
			code: `package types
type MockUser struct{}`,
			expectedCount: 1,
		},
		{
			name: "nolint opt-out honored",
			path: "/src/backend/sandbox.go",
			code: `package sandbox
var AllowMockMode = false //nolint:mock-identifier // config-gated simulation sandbox`,
			expectedCount: 0,
		},
		{
			name: "two markers in same file",
			path: "/src/backend/quote.go",
			code: `package quote
type Admin struct{}
func (a *Admin) createMockOrderQuote() {}
func (a *Admin) createMockRegistryQuote() {}`,
			expectedCount: 2,
		},
		{
			// Go does not share _test.go files between packages: helpers several
			// packages' tests use live in a test-support package of their own.
			name: "exported helper in a testutil package NOT flagged",
			path: "/src/internal/testutil/auth.go",
			code: `package testutil
func FakeJWT(subject string) string { return subject }`,
			expectedCount: 0,
		},
		{
			name: "test-support packages by prefix and suffix NOT flagged",
			path: "/src/internal/testdb/db.go",
			code: `package testdb
type FakeStore struct{}`,
			expectedCount: 0,
		},
		{
			name: "helpers package with the test suffix NOT flagged",
			path: "/src/internal/paytest/server.go",
			code: `package paytest
func NewFakeServer() {}`,
			expectedCount: 0,
		},
		{
			name: "package merely holding the word test still checked",
			path: "/src/backend/attestation/entry.go",
			code: `package attestation
func FakeEntry() {}`,
			expectedCount: 1,
		},
		{
			name: "clean code NOT flagged",
			path: "/src/backend/quote.go",
			code: `package quote
type Admin struct{}
func (a *Admin) createLocalQuote() {}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := rulestest.InMemoryGoFile(t, tt.path, "/src", tt.code, core.DefaultConfig())
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

// A project file that happens to share a name with a glint source is checked
// like any other file.
func TestMockIdentifierRuleChecksFilesNamedLikeGlintSources(t *testing.T) {
	code := `package quote
type MockQuote struct{}`
	ctx := core.NewFileContext("/src/quote/mock_identifier.go", "/src", []byte(code), core.DefaultConfig())
	parser := core.NewParser()
	fset, file, err := parser.ParseGoFile(ctx.Path, ctx.Content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)

	require.Len(t, NewMockIdentifierRule().AnalyzeFile(ctx), 1)
}

// MockGen output carries the generated-code header; the rule itself does not
// skip it — the core drops findings in files marked as generated, for every rule.
func TestMockIdentifierMockGenOutputIsGeneratedCode(t *testing.T) {
	code := `// Code generated by MockGen. DO NOT EDIT.
// Source: store.go

package mocks

// MockStore is a mock of Store interface.
type MockStore struct{}
`
	ctx := core.NewFileContext("/src/internal/mocks/mock_store.go", "/src", []byte(code), core.DefaultConfig())
	parser := core.NewParser()
	fset, file, err := parser.ParseGoFile(ctx.Path, ctx.Content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)

	require.True(t, ctx.IsGenerated(), "MockGen output must be recognised as generated")
}

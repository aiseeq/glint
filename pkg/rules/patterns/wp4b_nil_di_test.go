package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Parameter names are split into words: "catalog" does not contain the word
// "log", "blog" neither.
func TestNilDIRule_HighRiskParamWords(t *testing.T) {
	rule := NewNilDIRule()
	for hint, want := range map[string]bool{
		"catalog":     false,
		"blog":        false,
		"dialog":      false,
		"restore":     false,
		"userRepo":    true,
		"dbConn":      true,
		"HTTPClient":  true,
		"auditLogger": true,
		"event_store": true,
		"loggers":     true,
	} {
		assert.Equal(t, want, rule.isHighRiskParam(hint), hint)
	}
}

// A nil slice is an empty collection, not a missing dependency: with types
// only pointer and interface parameters can be a dependency left unset.
func TestNilDITypedRequiresPointerOrInterfaceParam(t *testing.T) {
	violations := runRuleOnFiles(t, NewNilDIRule(), map[string]string{
		"index/index.go": `package index

type Logger interface{ Print(string) }

type Index struct{ items []string }

func NewIndex(catalog []string) *Index { return &Index{items: catalog} }

func NewLoggedIndex(loggers []Logger, store map[string]int) *Index { return &Index{} }

func NewStoredIndex(store *Index, logger Logger) *Index { return store }

var defaultIndex = NewIndex(nil)

var loggedIndex = NewLoggedIndex(nil, nil)

var storedIndex = NewStoredIndex(nil, nil)
`,
	})
	require.Len(t, violations, 2)
	assert.Contains(t, violations[0].Message, "Nil store argument")
	assert.Contains(t, violations[1].Message, "Nil logger argument")
}

// Without types the declared parameter type still rules out collections.
func TestNilDIUntypedSliceParamIsSilent(t *testing.T) {
	violations := runRuleOnBrokenFiles(t, NewNilDIRule(), map[string]string{
		"svc/service.go": `package svc

type Service struct{}

func NewLogService(logs []string, logHandlers map[string]Handler) *Service { return &Service{} }

func wire() {
	_ = NewLogService(nil, nil)
}

func broken() int { return "not an int" }
`,
	})
	assert.Empty(t, violations)
}

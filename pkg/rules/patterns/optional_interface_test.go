package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// The repository a service holds is always the adapter, and the adapter
// has no batch method: the fast branch never runs, every call takes the
// slow one.
func TestOptionalInterfaceUnsatisfied(t *testing.T) {
	files := map[string]string{
		"store/store.go": `package store

type Member struct{ Name string }

type MemberRepo interface {
	GetMember(id string) (*Member, error)
}

type SQLMembers struct{}

func (SQLMembers) GetMember(id string) (*Member, error)                 { return nil, nil }
func (SQLMembers) GetMembers(ids []string) (map[string]*Member, error) { return nil, nil }

// Adapter is what the services get: it forwards one lookup only.
type Adapter struct{ inner SQLMembers }

func (a *Adapter) GetMember(id string) (*Member, error) { return a.inner.GetMember(id) }

// NewRepo wires the services: they always get the adapter.
func NewRepo() MemberRepo { return &Adapter{} }

// Members reads with the batch method, on the concrete type.
func Members(ids []string) { _, _ = SQLMembers{}.GetMembers(ids) }

type Cache interface{ Get(key string) string }

type memoryCache struct{}

func (memoryCache) Get(key string) string { return key }
func (memoryCache) Purge()                {}

func NewCache() Cache { return memoryCache{} }

type Sink interface{ Write(p []byte) (int, error) }
`,
		"svc/svc.go": `package svc

import "example.com/rulestest/store"

type batchMembers interface {
	GetMembers(ids []string) (map[string]*store.Member, error)
}

type purger interface{ Purge() }

type flusher interface{ Flush() error }

type Service struct {
	repo  store.MemberRepo
	cache store.Cache
}

func NewService() *Service { return &Service{repo: store.NewRepo(), cache: store.NewCache()} }

func (s *Service) Names(ids []string) []string {
	repo := s.repo
	if batch, ok := repo.(batchMembers); ok { // want optional-interface-unsatisfied
		_, _ = batch.GetMembers(ids)
	}
	switch repo.(type) {
	case batchMembers: // want optional-interface-unsatisfied
	}
	return nil
}

func (s *Service) Reset() {
	if p, ok := s.cache.(purger); ok {
		p.Purge()
	}
}

// Close takes a sink from callers the program does not show.
func Close(sink store.Sink) {
	if f, ok := sink.(flusher); ok {
		_ = f.Flush()
	}
}

func Any(v any) {
	if p, ok := v.(purger); ok {
		p.Purge()
	}
}
`,
	}
	violations, err := NewOptionalInterfaceUnsatisfiedRule().AnalyzeGoProject(rulestest.ProjectWithSSA(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "optional-interface-unsatisfied"), foundLines(violations))
}

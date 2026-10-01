package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func constructorGoroutineFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule := NewConstructorGoroutineNeverStopsRule()
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	return foundLines(violations)
}

// Every constructed middleware starts a cleanup loop that nothing can end:
// tests and re-created routers pile the goroutines up.
func TestConstructorGoroutineNeverStops(t *testing.T) {
	assert.Equal(t, []string{"mw/mw.go:12", "mw/mw.go:21"}, constructorGoroutineFindings(t, map[string]string{
		"mw/mw.go": `package mw

import "time"

type Tracker struct {
	cache map[string]time.Time
	done  chan struct{}
}

func NewTracker() *Tracker {
	t := &Tracker{cache: map[string]time.Time{}}
	go t.cleanupLoop()
	return t
}

type Poller struct{}

func NewPoller(fetch func()) *Poller {
	p := &Poller{}
	// polls forever
	go func() {
		for {
			fetch()
			time.Sleep(time.Second)
		}
	}()
	return p
}
`,
		"mw/loop.go": `package mw

import "time"

func (t *Tracker) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		t.prune()
	}
}
`,
	}))
}

// A loop with a way out, a goroutine draining a channel someone can close,
// and a loop outside a constructor are left alone.
func TestConstructorGoroutineNeverStopsAllowed(t *testing.T) {
	assert.Empty(t, constructorGoroutineFindings(t, map[string]string{
		"svc/svc.go": `package svc

import (
	"context"
	"time"
)

type Service struct {
	done  chan struct{}
	queue chan int
}

func NewService(ctx context.Context) *Service {
	s := &Service{done: make(chan struct{}), queue: make(chan int)}
	go s.loop()
	go s.consume()
	go func() {
		t := time.NewTicker(time.Second)
		for {
			select {
			case <-t.C:
				s.tick()
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for i := 0; i < 3; i++ {
			s.tick()
		}
	}()
	return s
}

func (s *Service) loop() {
	t := time.NewTicker(time.Second)
	for {
		select {
		case <-t.C:
			s.tick()
		case <-s.done:
			return
		}
	}
}

func (s *Service) consume() {
	for v := range s.queue {
		_ = v
	}
}

func (s *Service) Run() {
	go func() {
		for range time.Tick(time.Second) {
			s.tick()
		}
	}()
}
`,
	}))
}

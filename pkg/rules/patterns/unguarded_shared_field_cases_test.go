package patterns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A channel is safe for concurrent use: closing it under a lock that guards
// a closed flag does not make every receive a race.
func TestUnguardedSharedFieldAcceptsChannelReceiveWithoutLock(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Stream struct {
	mu     sync.Mutex
	closed bool
	ch     chan int
}

func (s *Stream) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		close(s.ch)
		s.closed = true
	}
}

func (s *Stream) Recv() int { return <-s.ch }
`)
	assert.Empty(t, violations)
}

// Replacing the channel under the lock still makes the field itself shared.
func TestUnguardedSharedFieldReportsChannelReplacedUnderLock(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Stream struct {
	mu sync.Mutex
	ch chan int
}

func (s *Stream) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ch = make(chan int)
}

func (s *Stream) Recv() int { return <-s.ch }
`)
	require.Len(t, violations, 1)
	assert.Equal(t, 16, violations[0].Line)
}

// A helper called under the lock of one type does not excuse a method of
// another type that happens to have the same name.
func TestUnguardedSharedFieldHelperIsPerType(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type A struct {
	mu sync.Mutex
	n  int
}

func (a *A) Inc() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	a.reset()
}

func (a *A) reset() {}

type B struct {
	mu    sync.Mutex
	count int
}

func (b *B) Inc() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.count++
}

func (b *B) reset() { b.count = 0 }
`)
	require.Len(t, violations, 1)
	assert.Equal(t, 30, violations[0].Line)
	assert.Contains(t, violations[0].Message, "count")
}

// sync/atomic is recognized by the package the function comes from, not by
// the name the file imports it under.
func TestUnguardedSharedFieldAcceptsRenamedAtomicImport(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import (
	"sync"
	atom "sync/atomic"
)

type Stats struct {
	mu    sync.Mutex
	total int64
}

func (s *Stats) Add() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
}

func (s *Stats) Bump() {
	atom.AddInt64(&s.total, 1)
}
`)
	assert.Empty(t, violations)
}

// A package of the project that happens to be called atomic is not
// sync/atomic: its functions do not synchronize anything.
func TestUnguardedSharedFieldReportsLookalikeAtomicPackage(t *testing.T) {
	project := map[string]string{
		"atomic/atomic.go": `package atomic

func AddInt64(p *int64, d int64) { *p += d }
`,
		"cache.go": `package cache

import (
	"sync"

	"example.com/rulestest/atomic"
)

type Stats struct {
	mu    sync.Mutex
	total int64
}

func (s *Stats) Add() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
}

func (s *Stats) Bump() {
	atomic.AddInt64(&s.total, 1)
}
`,
	}
	violations := runRuleOnFiles(t, NewUnguardedSharedFieldRule(), project)
	require.Len(t, violations, 1)
	assert.Equal(t, "cache.go", violations[0].File)
	assert.Equal(t, 21, violations[0].Line)
}

// A slice set only by the constructor's literal and never written afterwards
// is immutable: a method that happens to read it under the lock does not make
// it shared state, and a read without the lock is no race.
func TestUnguardedSharedFieldAcceptsFieldSetOnlyByConstructor(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type S struct {
	mu      sync.Mutex
	n       int
	wallets []string
}

func New(w []string) *S { return &S{wallets: w} }

func (s *S) A() {
	s.mu.Lock()
	s.n = len(s.wallets)
	s.mu.Unlock()
}

func (s *S) B() bool { return len(s.wallets) > 0 }
`)
	assert.Empty(t, violations)
}

// The same read pattern stays reported when anything changes the slice after
// construction: an element write in a method, a plain function replacing it,
// or the slice handed to a function that may write into it.
func TestUnguardedSharedFieldReportsSliceChangedAfterConstructor(t *testing.T) {
	base := `package cache

import (
	"sort"
	"sync"
)

type S struct {
	mu      sync.Mutex
	wallets []string
}

func New(w []string) *S { return &S{wallets: w} }

func (s *S) A() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.wallets)
}

func (s *S) B() bool { return len(s.wallets) > 0 }
`
	for name, extra := range map[string]string{
		"element write":    "\nfunc (s *S) C() { s.mu.Lock(); s.wallets[0] = \"\"; s.mu.Unlock() }\n",
		"plain function":   "\nfunc reload(s *S, w []string) { s.wallets = w }\n",
		"handed to a call": "\nfunc (s *S) C() { s.mu.Lock(); sort.Strings(s.wallets); s.mu.Unlock() }\n",
	} {
		t.Run(name, func(t *testing.T) {
			source := base + extra
			line := 21 // B's read
			if name != "handed to a call" {
				source = strings.Replace(source, "\t\"sort\"\n", "", 1)
				line--
			}
			var lines []int
			for _, v := range analyzeGuardedFields(t, source) {
				lines = append(lines, v.Line)
			}
			assert.Contains(t, lines, line)
		})
	}
}

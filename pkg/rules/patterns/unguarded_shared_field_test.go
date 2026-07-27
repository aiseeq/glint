package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func analyzeGuardedFields(t *testing.T, source string) []*core.Violation {
	t.Helper()
	project := rulestest.Project(t, map[string]string{"cache.go": source})
	violations, err := NewUnguardedSharedFieldRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	return violations
}

// The field is guarded everywhere except one method — exactly the shape that
// -race only catches when the timing happens to line up.
func TestUnguardedSharedFieldReportsMissingLock(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Counter struct {
	mu    sync.Mutex
	value int
}

func (c *Counter) Add(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value += n
}

func (c *Counter) Reset() {
	c.value = 0
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 17, violations[0].Line)
	assert.Contains(t, violations[0].Message, "value")
	assert.Contains(t, violations[0].Message, "mu")
}

func TestUnguardedSharedFieldAcceptsConsistentLocking(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Counter struct {
	mu    sync.Mutex
	value int
}

func (c *Counter) Add(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value += n
}

func (c *Counter) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value = 0
}
`)

	assert.Empty(t, violations)
}

// An RWMutex read lock guards reads; a write that skips the lock is still a race.
func TestUnguardedSharedFieldReportsWriteBesideReadLock(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Registry struct {
	mu    sync.RWMutex
	items map[string]int
}

func (r *Registry) Get(key string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.items[key]
}

func (r *Registry) Set(key string, value int) {
	r.items[key] = value
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 17, violations[0].Line)
	assert.Contains(t, violations[0].Message, "items")
}

// A helper called from inside a critical section runs under the lock already.
func TestUnguardedSharedFieldAcceptsHelperCalledUnderLock(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Counter struct {
	mu    sync.Mutex
	value int
}

func (c *Counter) Add(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apply(n)
}

func (c *Counter) apply(n int) {
	c.value += n
}
`)

	assert.Empty(t, violations)
}

// A name that promises the caller holds the lock is a contract, not an omission.
func TestUnguardedSharedFieldAcceptsLockedNameConvention(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Counter struct {
	mu    sync.Mutex
	value int
}

func (c *Counter) Add(n int) {
	c.mu.Lock()
	c.value += n
	c.mu.Unlock()
}

func (c *Counter) resetLocked() {
	c.value = 0
}
`)

	assert.Empty(t, violations)
}

// A field nobody ever guards is not part of the mutex contract: it may well be
// immutable after construction.
func TestUnguardedSharedFieldIgnoresNeverGuardedField(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Counter struct {
	mu    sync.Mutex
	name  string
	value int
}

func (c *Counter) Add(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value += n
}

func (c *Counter) Name() string {
	return c.name
}
`)

	assert.Empty(t, violations)
}

// An embedded mutex is locked on the receiver itself.
func TestUnguardedSharedFieldHandlesEmbeddedMutex(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Counter struct {
	sync.Mutex
	value int
}

func (c *Counter) Add(n int) {
	c.Lock()
	defer c.Unlock()
	c.value += n
}

func (c *Counter) Reset() {
	c.value = 0
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 17, violations[0].Line)
	assert.Contains(t, violations[0].Message, "value")
}

// The lock released early still covers the statements before the Unlock call,
// and stops covering the ones after it.
func TestUnguardedSharedFieldRespectsExplicitUnlockRange(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Counter struct {
	mu    sync.Mutex
	value int
	total int
}

func (c *Counter) Add(n int) {
	c.mu.Lock()
	c.value += n
	c.mu.Unlock()
	c.total = n
}

func (c *Counter) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total = 0
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 15, violations[0].Line)
	assert.Contains(t, violations[0].Message, "total")
}

// Repro from glint itself: a setting written once by Configure and only read
// afterwards happened to be read inside a critical section that protects other
// state. Reading a plain value under a lock does not put it under the lock's
// contract.
func TestUnguardedSharedFieldIgnoresSettingReadInsideSection(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Rule struct {
	mu       sync.Mutex
	seen     map[string]bool
	minSize  int
}

func (r *Rule) Configure(size int) {
	r.minSize = size
}

func (r *Rule) Analyze(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen[key] = true
	return r.minSize
}

func (r *Rule) Threshold() int {
	return r.minSize
}
`)

	assert.Empty(t, violations)
}

// Repro from saga: the early-exit branch releases the lock and returns, so the
// statements after the branch are still inside the critical section.
func TestUnguardedSharedFieldRespectsEarlyUnlockInBranch(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Service struct {
	mu     sync.Mutex
	closed bool
	queue  []int
}

func (s *Service) Enqueue(event int) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	s.queue = append(s.queue, event)
	full := len(s.queue) >= 10
	s.mu.Unlock()
	return full
}

func (s *Service) Flush() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := s.queue
	s.queue = nil
	return batch
}
`)

	assert.Empty(t, violations)
}

// A mutex of a nested object covers that object's fields.
func TestUnguardedSharedFieldFollowsNestedMutex(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type metrics struct {
	mu    sync.Mutex
	times []int
}

type Service struct {
	metrics *metrics
}

func (s *Service) Record(d int) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.times = append(s.metrics.times, d)
}

func (s *Service) Reset() {
	s.metrics.times = nil
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "times")
	assert.Contains(t, violations[0].Message, "s.metrics.mu")
}

// Repro from saga: sync/atomic carries its own synchronization, so a counter
// read with atomic.LoadInt64 needs no lock.
func TestUnguardedSharedFieldIgnoresAtomicAccess(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import (
	"sync"
	"sync/atomic"
)

type Service struct {
	mu    sync.Mutex
	total int64
	times []int
}

func (s *Service) Record(d int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.times = append(s.times, d)
	atomic.AddInt64(&s.total, 1)
}

func (s *Service) Total() int64 {
	return atomic.LoadInt64(&s.total)
}
`)

	assert.Empty(t, violations)
}

// A constructor holds the only reference to the value, so nothing can race yet.
func TestUnguardedSharedFieldIgnoresConstructor(t *testing.T) {
	violations := analyzeGuardedFields(t, `package cache

import "sync"

type Counter struct {
	mu    sync.Mutex
	value int
}

func NewCounter(start int) *Counter {
	c := &Counter{}
	c.value = start
	return c
}

func (c *Counter) Add(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value += n
}
`)

	assert.Empty(t, violations)
}

func TestUnguardedSharedFieldMetadata(t *testing.T) {
	rule := NewUnguardedSharedFieldRule()
	assert.Equal(t, "unguarded-shared-field", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
	assert.Nil(t, rule.AnalyzeFile(nil))
}

func TestUnguardedSharedFieldRejectsNilProject(t *testing.T) {
	_, err := NewUnguardedSharedFieldRule().AnalyzeGoProject(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil Go project context")
}

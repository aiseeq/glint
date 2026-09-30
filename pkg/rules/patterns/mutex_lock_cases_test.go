package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mutexLockReturnsUnlock = `package projecta

import "sync"

type Store struct{ mu sync.Mutex }

func (s *Store) lock() func() {
	s.mu.Lock()
	return s.mu.Unlock
}

func (s *Store) Do() {
	defer s.lock()()
}
`

// Returning the Unlock method value hands the release to the caller: the
// `defer s.lock()()` idiom.
func TestMutexLockAcceptsReturnedUnlockMethodValue(t *testing.T) {
	assert.Empty(t, runRuleOnFiles(t, NewMutexLockRule(), map[string]string{"store.go": mutexLockReturnsUnlock}))
	assert.Empty(t, NewMutexLockRule().AnalyzeFile(createMutexContext(t, "store.go", mutexLockReturnsUnlock)))
}

func TestMutexLockTypedReportsSyncMutexWithoutUnlock(t *testing.T) {
	violations := runRuleOnFiles(t, NewMutexLockRule(), map[string]string{"store.go": `package projecta

import "sync"

type Store struct {
	mu sync.RWMutex
	n  int
}

func (s *Store) Get() int {
	s.mu.RLock()
	return s.n
}
`})
	require.Len(t, violations, 1)
	assert.Equal(t, "store.go", violations[0].File)
	assert.Equal(t, 11, violations[0].Line)
}

// With types a Lock method of something that is not a sync mutex is not a
// critical section: a file lock released by Close, a lease renewed elsewhere.
func TestMutexLockTypedIgnoresNonMutexLock(t *testing.T) {
	violations := runRuleOnFiles(t, NewMutexLockRule(), map[string]string{"lease.go": `package projecta

type Lease struct{ held bool }

func (l *Lease) Lock()  { l.held = true }
func (l *Lease) Close() { l.held = false }

func acquire(l *Lease) {
	l.Lock()
}
`})
	assert.Empty(t, violations)
}

package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A mutex per user serializes one process: a second instance checks the
// same balance at the same time.
func TestPerKeyMutexMap(t *testing.T) {
	assert.Equal(t, []int{6}, sqlFileRuleLines(t, NewPerKeyMutexMapRule(), "service/invest.go", `package service

import "sync"

var (
	userLocks   = make(map[string]*sync.Mutex)
	userLocksMu sync.Mutex
)

func (s *Service) Invest(ctx context.Context, userID string, amount decimal.Decimal) error {
	lock := userLock(userID)
	lock.Lock()
	defer lock.Unlock()
	balance, err := s.repo.Balance(ctx, userID)
	if err != nil || balance.LessThan(amount) {
		return ErrFunds
	}
	return s.repo.Invest(ctx, userID, amount)
}
`))
	assert.Empty(t, sqlFileRuleLines(t, NewPerKeyMutexMapRule(), "cache/keyed.go", `package cache

import "sync"

type Keyed struct {
	locks map[string]*sync.Mutex
}

func (k *Keyed) Load(key string, build func() []byte) []byte {
	return build()
}
`))
}

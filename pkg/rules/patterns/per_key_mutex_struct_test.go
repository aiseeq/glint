package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A service mutex guarding no state of its own, only database work: a second
// instance runs the same sync at the same time.
func TestPerKeyMutexMapStructMutexGuardingDatabaseWork(t *testing.T) {
	assert.Equal(t, []int{14}, sqlFileRuleLines(t, NewPerKeyMutexMapRule(), "service/sync.go", `package service

import "sync"

type Service struct {
	txRepo *TxRepository
	logger *Logger
	syncMu sync.Mutex
	every  time.Duration
}

// SyncWallet stores the wallet's transactions.
func (s *Service) SyncWallet(ctx context.Context, wallet string) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	s.logger.Info("sync", wallet)
	return s.syncChain(ctx, wallet)
}

func (s *Service) syncChain(ctx context.Context, wallet string) error {
	return s.txRepo.UpsertBatch(ctx, wallet)
}
`))
	assert.Empty(t, sqlFileRuleLines(t, NewPerKeyMutexMapRule(), "service/prices.go", `package service

import "sync"

type Prices struct {
	repo  *PriceRepository
	mu    sync.RWMutex
	cache map[string]float64
}

func (p *Prices) Refresh(ctx context.Context) error {
	rows, err := p.repo.Load(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache = rows
	return err
}

func (p *Prices) Get(key string) float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cache[key]
}
`), "the mutex guards the cache")
}

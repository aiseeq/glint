package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const pollMonitorSource = `package monitor

import (
	"context"
	"log/slog"
	"time"
)

type Record struct{ Hash string }

type client interface {
	ListSince(ctx context.Context, address string, since time.Time) ([]Record, error)
}

type ledger interface {
	RecordTransfer(ctx context.Context, r Record) (bool, error)
}

type Monitor struct {
	client    client
	ledger    ledger
	logger    *slog.Logger
	address   string
	lastCheck time.Time
	lastPing  time.Time
}

func widen(since time.Time) time.Time { return since.Add(-time.Minute) }
`

// A poll that sets its window start to the current time after the fetch and
// the processing never sees what arrived while the tick ran.
func TestPollWindowStartSetAfterFetch(t *testing.T) {
	assert.Equal(t, []string{"monitor/tick.go:15", "monitor/tick.go:18"}, typedFuncFindings(t, NewPollWindowStartSetAfterFetchRule(), map[string]string{
		"monitor/monitor.go": pollMonitorSource,
		"monitor/tick.go": `package monitor

import (
	"context"
	"time"
)

func (m *Monitor) Tick(ctx context.Context) error {
	since := widen(m.lastCheck)
	records, err := m.client.ListSince(ctx, m.address, since)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		m.lastCheck = time.Now().UTC()
		return nil
	}
	m.lastCheck = time.Now()
	return nil
}

func (m *Monitor) TickFixed(ctx context.Context) error {
	fetchedAt := time.Now().UTC()
	if _, err := m.client.ListSince(ctx, m.address, m.lastCheck); err != nil {
		return err
	}
	m.lastCheck = fetchedAt
	return nil
}

func (m *Monitor) Ping(ctx context.Context) {
	if time.Since(m.lastPing) < time.Minute {
		return
	}
	_, _ = m.client.ListSince(ctx, m.address, time.Time{})
	m.lastPing = time.Now()
}
`,
	}))
}

// A poll that hands the fetched records to a helper which only logs a failed
// write, and then moves its window on, never fetches the failed record again.
func TestPollWindowAdvancedPastLoggedFailure(t *testing.T) {
	assert.Equal(t, []string{"monitor/tick.go:15"}, typedFuncFindings(t, NewPollWindowAdvancedPastLoggedFailureRule(), map[string]string{
		"monitor/monitor.go": pollMonitorSource,
		"monitor/tick.go": `package monitor

import (
	"context"
	"errors"
	"time"
)

func (m *Monitor) Tick(ctx context.Context) error {
	fetchedAt := time.Now()
	records, err := m.client.ListSince(ctx, m.address, m.lastCheck)
	if err != nil {
		return err
	}
	m.recordAll(ctx, records)
	m.lastCheck = fetchedAt
	return nil
}

func (m *Monitor) recordAll(ctx context.Context, records []Record) {
	for _, r := range records {
		m.recordOne(ctx, r)
	}
}

func (m *Monitor) recordOne(ctx context.Context, r Record) {
	if _, err := m.ledger.RecordTransfer(ctx, r); err != nil {
		m.logger.Error("record failed", "hash", r.Hash, "error", err)
		return
	}
}

func (m *Monitor) TickKept(ctx context.Context) error {
	fetchedAt := time.Now()
	records, err := m.client.ListSince(ctx, m.address, m.lastCheck)
	if err != nil {
		return err
	}
	if err := m.recordAllErr(ctx, records); err != nil {
		return err
	}
	m.lastCheck = fetchedAt
	return nil
}

func (m *Monitor) recordAllErr(ctx context.Context, records []Record) error {
	var errs []error
	for _, r := range records {
		if _, err := m.ledger.RecordTransfer(ctx, r); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *Monitor) TickLogOnly(ctx context.Context) error {
	fetchedAt := time.Now()
	records, err := m.client.ListSince(ctx, m.address, m.lastCheck)
	if err != nil {
		return err
	}
	m.logCount(records)
	m.lastCheck = fetchedAt
	return nil
}

func (m *Monitor) logCount(records []Record) {
	m.logger.Info("fetched", "count", len(records))
}
`,
	}))
}

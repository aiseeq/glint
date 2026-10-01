package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func channelCloseLines(t *testing.T, source string) []int {
	t.Helper()
	return violationLines(NewChannelCloseNotIdempotentRule().AnalyzeFile(rulestest.GoFile(t, "limiter/limiter.go", source)))
}

// A second Stop - the shutdown path and a deferred cleanup, or two owners -
// closes the channel again and panics.
func TestChannelCloseNotIdempotent(t *testing.T) {
	assert.Equal(t, []int{4, 10}, channelCloseLines(t, `package limiter

func (l *Limiter) Stop() {
	close(l.stopCleanup)
}

func (s *Sessions) Close() {
	if s.ticker != nil {
		s.ticker.Stop()
		close(s.stop)
	}
}
`))
}

// sync.Once, a closed flag the method sets, a field reset to nil, and a
// non-blocking receive that sees the channel already closed all guard it.
func TestChannelCloseNotIdempotentGuarded(t *testing.T) {
	assert.Empty(t, channelCloseLines(t, `package limiter

func (l *Limiter) Stop() {
	l.once.Do(func() { close(l.stop) })
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.done)
	return nil
}

func (w *Worker) Shutdown() {
	if w.quit != nil {
		close(w.quit)
		w.quit = nil
	}
}

func (p *Pool) Stop() {
	select {
	case <-p.done:
		return
	default:
		close(p.done)
	}
}

func (p *Pool) drain() {
	close(p.items)
}
`))
}

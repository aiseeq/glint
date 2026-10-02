package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A polling goroutine stops on its stop channel, but the work it runs is
// under context.Background(): stopping waits for a refresh nobody can cancel,
// and a shutdown cuts it mid-write.
func TestContextBackground_StoppableLoopRunsDetachedWork(t *testing.T) {
	const source = `package poll

import (
	"context"
	"time"
)

func (s *Service) StartPolling(interval time.Duration) {
	s.stop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				if err := s.refresh(context.Background()); err != nil {
					s.logger.Error("refresh failed", "error", err)
				}
			}
		}
	}()
}

func (s *Service) StartForever(interval time.Duration) {
	go func() {
		for range time.Tick(interval) {
			_ = s.refresh(context.Background())
		}
	}()
}

func (s *Service) StartWithRoot(root context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		for {
			select {
			case <-root.Done():
				return
			case <-ticker.C:
				_ = s.refresh(root)
			}
		}
	}()
}
`
	violations := NewContextBackgroundRule().AnalyzeFile(rulestest.GoFile(t, "poll/poll.go", source))
	assert.Equal(t, []int{18}, violationLines(violations))
}

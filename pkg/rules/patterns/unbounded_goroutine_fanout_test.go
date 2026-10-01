package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestUnboundedGoroutineFanoutRule_Metadata(t *testing.T) {
	rule := NewUnboundedGoroutineFanoutRule()
	assert.Equal(t, "unbounded-goroutine-fanout", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
}

func TestUnboundedGoroutineFanoutRule_Detection(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		expects []string
	}{
		{
			// Репро: обновление балансов запускало по горутине на каждый кошелёк
			// из настроек — все запросы к внешнему API уходили разом, и
			// провайдер отвечал 429 на всю пачку.
			name: "a goroutine per configured wallet, all at once",
			source: `package app

import (
	"context"
	"sync"
)

type Balances struct{ wallets []string }

func (b *Balances) fetch(ctx context.Context, addr string) int { return len(addr) }

func (b *Balances) Refresh(ctx context.Context) []int {
	var wg sync.WaitGroup
	results := make([]int, len(b.wallets))
	for i, wallet := range b.wallets {
		wg.Add(1)
		go func(idx int, addr string) {
			defer wg.Done()
			results[idx] = b.fetch(ctx, addr)
		}(i, wallet)
	}
	wg.Wait()
	return results
}
`,
			expects: []string{"app/app.go:17"},
		},
		{
			name: "semaphore in the loop or in the goroutine bounds the fan-out",
			source: `package app

import (
	"context"
	"sync"
)

func fetch(ctx context.Context, id string) {}

func All(ctx context.Context, ids []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			fetch(ctx, id)
		}(id)
	}
	wg.Wait()
}

func Each(ctx context.Context, ids []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fetch(ctx, id)
		}(id)
	}
	wg.Wait()
}
`,
		},
		{
			name: "fixed small sets and worker pools",
			source: `package app

import (
	"context"
	"sync"
)

func fetch(ctx context.Context, id string) {}

func Fixed(ctx context.Context) {
	var wg sync.WaitGroup
	for _, id := range []string{"a", "b", "c"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			fetch(ctx, id)
		}(id)
	}
	sources := [3]string{"x", "y", "z"}
	for _, id := range sources {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			fetch(ctx, id)
		}(id)
	}
	wg.Wait()
}

func Pool(ctx context.Context, ids []string, workers int) {
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				fetch(ctx, id)
			}
		}()
	}
	for _, id := range ids {
		jobs <- id
	}
	close(jobs)
	wg.Wait()
}
`,
		},
		{
			// Health checkers registered by the code: the list holds functions,
			// and its length is fixed by the program, not by data.
			name: "a goroutine per registered check function",
			source: `package app

import (
	"context"
	"sync"
)

type Checker func(ctx context.Context) error

type Health struct {
	checks []Checker
	named  map[string]Checker
}

func (h *Health) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, check := range h.checks {
		wg.Add(1)
		go func(c Checker) {
			defer wg.Done()
			_ = c(ctx)
		}(check)
	}
	for _, check := range h.named {
		wg.Add(1)
		go func(c Checker) {
			defer wg.Done()
			_ = c(ctx)
		}(check)
	}
	wg.Wait()
}
`,
		},
		{
			name: "goroutines doing only in-memory work",
			source: `package app

import "sync"

func Sum(chunks [][]int) []int {
	var wg sync.WaitGroup
	out := make([]int, len(chunks))
	for i, chunk := range chunks {
		wg.Add(1)
		go func(i int, chunk []int) {
			defer wg.Done()
			for _, v := range chunk {
				out[i] += v
			}
		}(i, chunk)
	}
	wg.Wait()
	return out
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"go.mod":     "module example.com/rulestest\n\ngo 1.24\n",
				"app/app.go": tt.source,
			}
			violations, err := NewUnboundedGoroutineFanoutRule().AnalyzeGoProject(rulestest.Project(t, files))
			require.NoError(t, err)
			assert.Equal(t, tt.expects, foundLines(violations))
		})
	}
}

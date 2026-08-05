package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestSleepWithoutContextRule(t *testing.T) {
	rule := NewSleepWithoutContextRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			// Repro: projectB transaction_service.go before 471e1a1 — 200ms
			// pause between provider APIs with a live ctx parameter.
			name: "sleep in loop of ctx function",
			code: `package main
import (
	"context"
	"time"
)
func (s *Service) SyncWallet(ctx context.Context, wallet string, chains []string) {
	for _, chain := range chains {
		s.syncSingleChain(ctx, wallet, chain)
		time.Sleep(200 * time.Millisecond)
	}
}`,
			expectedCount: 1,
		},
		{
			// Repro: zerion client doGetWithRetry-style retry pause.
			name: "sleep between retries with ctx",
			code: `package main
import (
	"context"
	"time"
)
func (c *Client) doGetWithRetry(ctx context.Context, url string) error {
	for attempt := 0; attempt < 3; attempt++ {
		if err := c.doGet(ctx, url); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return nil
}`,
			expectedCount: 1,
		},
		{
			name: "sleep in closure capturing ctx",
			code: `package main
import (
	"context"
	"time"
)
func run(ctx context.Context) {
	go func() {
		time.Sleep(time.Second)
	}()
}`,
			expectedCount: 1,
		},
		{
			// Post-fix shape: ctx-aware select instead of a raw sleep.
			name: "ctx-aware wait is silent",
			code: `package main
import (
	"context"
	"time"
)
func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}`,
			expectedCount: 0,
		},
		{
			name: "sleep without ctx in scope is silent",
			code: `package main
import "time"
func warmup() {
	time.Sleep(time.Second)
}`,
			expectedCount: 0,
		},
		{
			name: "discarded ctx parameter is silent",
			code: `package main
import (
	"context"
	"time"
)
func tick(_ context.Context) {
	time.Sleep(time.Second)
}`,
			expectedCount: 0,
		},
		{
			name: "closure with own ctx param inside plain function",
			code: `package main
import (
	"context"
	"time"
)
func build() func(context.Context) {
	return func(ctx context.Context) {
		time.Sleep(time.Second)
	}
}`,
			expectedCount: 1,
		},
		{
			name: "suppression comment is honored",
			code: `package main
import (
	"context"
	"time"
)
func run(ctx context.Context) {
	// nolint:sleep-without-context — фикс. пауза по требованию провайдера
	time.Sleep(time.Second)
}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/file.go", "/src", []byte(tt.code), core.DefaultConfig())
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/src/file.go", []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}

func TestSleepWithoutContextRuleSkipsTests(t *testing.T) {
	rule := NewSleepWithoutContextRule()
	code := `package main
import (
	"context"
	"time"
)
func helper(ctx context.Context) {
	time.Sleep(time.Second)
}`
	ctx := core.NewFileContext("/src/file_test.go", "/src", []byte(code), core.DefaultConfig())
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile("/src/file_test.go", []byte(code))
	if err == nil {
		ctx.SetGoAST(fset, astFile)
	}
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

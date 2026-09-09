package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorRebuiltFromTextRule_Metadata(t *testing.T) {
	rule := NewErrorRebuiltFromTextRule()

	assert.Equal(t, "error-rebuilt-from-text", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestErrorRebuiltFromTextRule_Detection(t *testing.T) {
	rule := NewErrorRebuiltFromTextRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			// Repro (projectA, 2026-09): a cancelled browser request reached the
			// HTTP boundary as 500 because the cause was formatted into text with
			// %v and the chain ended there — errors.Is(err, context.Canceled) saw
			// nothing to match.
			name: "cause formatted with %v",
			code: `package service

func fetch() error {
	if err := call(); err != nil {
		return fmt.Errorf("fetch transactions: %v", err)
	}
	return nil
}
`,
			expectMatch: true,
		},
		{
			name: "cause formatted with %s",
			code: `package service

func fetch() error {
	if err := call(); err != nil {
		return fmt.Errorf("fetch transactions: %s", err)
	}
	return nil
}
`,
			expectMatch: true,
		},
		{
			name: "cause wrapped with %w",
			code: `package service

func fetch() error {
	if err := call(); err != nil {
		return fmt.Errorf("fetch transactions: %w", err)
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			name: "new error built from a formatted cause",
			code: `package service

func send() error {
	resp, err := do()
	if err != nil {
		msg := fmt.Sprintf("request failed after %d attempts: %v", attempts, err)
		return errors.New(msg)
	}
	_ = resp
	return nil
}
`,
			expectMatch: true,
		},
		{
			// A result object carries the cause as text only; the boundary then
			// classifies nothing and answers 500 on every failure.
			name: "error rebuilt from a result object message",
			code: `package routing

func today() error {
	result := service.History(ctx)
	if !result.Success {
		return fmt.Errorf("today transaction history: %s", result.Error.Message)
	}
	return nil
}
`,
			expectMatch: true,
		},
		{
			name: "plain values formatted, no error involved",
			code: `package service

func describe(name string, count int) error {
	return fmt.Errorf("unexpected shape %s: %d items", name, count)
}
`,
			expectMatch: false,
		},
		{
			name: "message of an error printed in a log, not rebuilt",
			code: `package service

func fetch() error {
	if err := call(); err != nil {
		logger.Warn(fmt.Sprintf("fetch failed: %v", err))
		return fmt.Errorf("fetch: %w", err)
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			// A pair of errors from one operation: the primary one keeps the
			// chain, the secondary is deliberately reported as text.
			name: "cause wrapped, second failure printed beside it",
			code: `package service

func fetch() error {
	err := call()
	closeErr := closeIt()
	if err != nil {
		return fmt.Errorf("read row: %w; close rows: %v", err, closeErr)
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			// The code of a result object printed next to the object itself:
			// the %w keeps the very same cause, so nothing is lost.
			name: "result code printed beside the wrapped result error",
			code: `package service

func fetch() error {
	result := call()
	if result.Error != nil {
		return fmt.Errorf("%s: %w", result.Error.Code, result.Error)
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			// A sentinel wrapped with %w keeps the category, not the cause:
			// errors.Is(err, ErrSignature) matches, and the transport failure
			// under it still arrives as text.
			name: "sentinel wrapped, real cause printed as text",
			code: `package service

func fetch() error {
	err := call()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrSignature, err.Error())
	}
	return nil
}
`,
			expectMatch: true,
		},
		{
			name: "second cause wrapped, first only printed",
			code: `package service

func fetch() error {
	first, err := call()
	if err != nil {
		return fmt.Errorf("call %v failed: %w", first, err)
	}
	return nil
}
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createDeferContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Contains(t, violations[0].Message, "errors.Is")
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

func TestErrorRebuiltFromTextRule_TestFilesExcluded(t *testing.T) {
	rule := NewErrorRebuiltFromTextRule()

	code := `package service

func TestFetch(t *testing.T) {
	err := call()
	require.EqualError(t, fmt.Errorf("fetch: %v", err), "fetch: boom")
}
`
	ctx := createDeferContext(t, "service_test.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

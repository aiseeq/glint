package patterns

import (
	"fmt"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderCommandRetryRule_Metadata(t *testing.T) {
	rule := NewProviderCommandRetryRule()

	assert.Equal(t, "provider-command-retry", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityCritical, rule.DefaultSeverity())
	assert.True(t, rules.HonorsSuppression(rule))
}

func TestProviderCommandRetryRule_DetectsProPayBoolHelper(t *testing.T) {
	code := `package paywho
func (c *Client) signedPOST(path string, body any, retry bool) (Response, error) {
	panic("not implemented")
}
func (c *Client) CancelTransaction(request Request) (Response, error) {
	return c.signedPOST("/cancel", request, true)
}`
	ctx := createQueryContext(t, "client.go", code)

	violations := NewProviderCommandRetryRule().AnalyzeFile(ctx)

	require.Len(t, violations, 1)
	assert.Equal(t, 6, violations[0].Line)
	assert.Equal(t, "provider_command_retry", violations[0].Context["pattern"])
	assert.Equal(t, "CancelTransaction", violations[0].Context["command"])
	assert.Equal(t, "bool_helper", violations[0].Context["retry_evidence"])
}

func TestProviderCommandRetryRule_DestructiveVocabulary(t *testing.T) {
	for _, method := range []string{
		"SendTransaction",
		"ExecutePayment",
		"SubmitPayment",
		"CreatePayout",
		"SendPayout",
		"TransferFunds",
		"CancelTransaction",
		"CancelPayment",
		"RefundPayment",
		"CreateRefund",
		"SendRefund",
	} {
		t.Run(method, func(t *testing.T) {
			code := fmt.Sprintf(`package service
func execute(s *Service, req Request) error {
	return Retry(func() error {
		return s.provider.%s(req)
	})
}`, method)
			ctx := createQueryContext(t, "service.go", code)

			assert.Len(t, NewProviderCommandRetryRule().AnalyzeFile(ctx), 1)
		})
	}
}

func TestProviderCommandRetryRule_RetryCallbackVocabulary(t *testing.T) {
	for _, retry := range []string{"Retry", "WithRetry", "DoWithRetry"} {
		t.Run(retry, func(t *testing.T) {
			code := fmt.Sprintf(`package service
func cancel(s *Service, ref string) error {
	return s.retry.%s(func() error {
		return s.provider.CancelTransaction(ref)
	})
}`, retry)
			ctx := createQueryContext(t, "service.go", code)

			violations := NewProviderCommandRetryRule().AnalyzeFile(ctx)
			require.Len(t, violations, 1)
			assert.Equal(t, "retry_callback", violations[0].Context["retry_evidence"])
		})
	}
}

func TestProviderCommandRetryRule_DetectsCommandsInLoops(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{
			name: "for",
			body: `for attempt := 0; attempt < 3; attempt++ {
		if err := s.provider.RefundPayment(ref); err == nil { return nil }
	}`,
			want: 1,
		},
		{
			name: "range retries same entity",
			body: `for range retryDelays {
		if err := s.provider.CancelTransaction(ref); err == nil { return nil }
	}`,
			want: 1,
		},
		{
			name: "range processes distinct entities",
			body: `for _, payout := range payouts {
		if err := s.provider.SendPayout(payout); err != nil { return err }
	}`,
			want: 0,
		},
		{
			name: "indexed loop processes distinct entities",
			body: `for i := 0; i < len(payouts); i++ {
		if err := s.provider.SendPayout(payouts[i]); err != nil { return err }
	}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := fmt.Sprintf(`package service
func execute(s *Service, ref string, payouts []Payout) error {
	%s
	return nil
}`, tt.body)
			ctx := createQueryContext(t, "service.go", code)

			violations := NewProviderCommandRetryRule().AnalyzeFile(ctx)
			assert.Len(t, violations, tt.want)
			if tt.want > 0 {
				assert.Equal(t, "loop", violations[0].Context["retry_evidence"])
			}
		})
	}
}

func TestProviderCommandRetryRule_BatchDerivedEntityIsNotRetry(t *testing.T) {
	code := `package service
func execute(s *Service, payouts []Payout) error {
	for _, payout := range payouts {
		req := buildPayoutRequest(payout)
		if err := s.provider.SendPayout(req); err != nil { return err }
	}
	return nil
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Empty(t, NewProviderCommandRetryRule().AnalyzeFile(ctx))
}

func TestProviderCommandRetryRule_DetectsOuterRetryAroundInnerBatch(t *testing.T) {
	code := `package service
func execute(s *Service, payouts []Payout) error {
	for attempt := 0; attempt < 3; attempt++ {
		for _, payout := range payouts {
			if err := s.provider.SendPayout(payout); err != nil { return err }
		}
	}
	return nil
}`
	ctx := createQueryContext(t, "service.go", code)

	violations := NewProviderCommandRetryRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
}

func TestProviderCommandRetryRule_NestedBatchOverOuterGroupIsSafe(t *testing.T) {
	code := `package service
func execute(s *Service, groups [][]Payout) error {
	for _, group := range groups {
		for _, payout := range group {
			if err := s.provider.SendPayout(payout); err != nil { return err }
		}
	}
	return nil
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Empty(t, NewProviderCommandRetryRule().AnalyzeFile(ctx))
}

func TestProviderCommandRetryRule_SkipsAmbiguousSameNameMethodSignatures(t *testing.T) {
	code := `package paywho
func (c *Client) signedPOST(path string, body any, retry bool) error { return nil }
func (a *Auditor) signedPOST(path string, body any, audit bool) error { return nil }
func (c *Client) CancelTransaction(request Request) error {
	return c.signedPOST("/cancel", request, true)
}`
	ctx := createQueryContext(t, "client.go", code)

	assert.Empty(t, NewProviderCommandRetryRule().AnalyzeFile(ctx))
}

func TestProviderCommandRetryRule_DoesNotFlagSafePatterns(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{
			name: "bool helper retry false",
			code: `package paywho
func (c *Client) signedPOST(path string, retry bool) error { return nil }
func (c *Client) CancelTransaction(ref string) error {
	return c.signedPOST(ref, false)
}`,
		},
		{
			name: "true does not correspond to retry parameter",
			code: `package paywho
func (c *Client) signedPOST(retry bool, audit bool) error { return nil }
func (c *Client) CancelTransaction(ref string) error {
	return c.signedPOST(false, true)
}`,
		},
		{
			name: "bool helper parameter is not retry",
			code: `package paywho
func (c *Client) signedPOST(path string, cache bool) error { return nil }
func (c *Client) CancelTransaction(ref string) error {
	return c.signedPOST(ref, true)
}`,
		},
		{
			name: "helper declaration is not in same file",
			code: `package paywho
func (c *Client) CancelTransaction(ref string) error {
	return c.signedPOST(ref, true)
}`,
		},
		{
			name: "single shot direct command",
			code: `package service
func cancel(s *Service, ref string) error {
	return s.provider.CancelTransaction(ref)
}`,
		},
		{
			name: "retry read only status",
			code: `package service
func status(s *Service, ref string) error {
	return Retry(func() error {
		return s.provider.GetTransactionStatus(ref)
	})
}`,
		},
		{
			name: "destructive name on non-provider receiver",
			code: `package service
func cancel(s *Service, ref string) error {
	return Retry(func() error {
		return s.cache.CancelTransaction(ref)
	})
}`,
		},
		{
			name: "loop read only fetch",
			code: `package service
func statuses(s *Service, refs []string) error {
	for _, ref := range refs {
		if _, err := s.provider.FetchPaymentStatus(ref); err != nil { return err }
	}
	return nil
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createQueryContext(t, "service.go", tt.code)
			assert.Empty(t, NewProviderCommandRetryRule().AnalyzeFile(ctx))
		})
	}
}

func TestProviderCommandRetryRule_SuppressionAndTestFiles(t *testing.T) {
	code := `package service
func cancel(s *Service, ref string) error {
	return Retry(func() error {
		//nolint:provider-command-retry // provider guarantees idempotent cancellation
		return s.provider.CancelTransaction(ref)
	})
}`
	rule := NewProviderCommandRetryRule()

	assert.Empty(t, rule.AnalyzeFile(createQueryContext(t, "service.go", code)))
	assert.Empty(t, rule.AnalyzeFile(createQueryContext(t, "service_test.go", code)))
}

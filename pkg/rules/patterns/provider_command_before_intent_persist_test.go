package patterns

import (
	"fmt"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderCommandBeforeIntentPersistRule_Metadata(t *testing.T) {
	rule := NewProviderCommandBeforeIntentPersistRule()

	assert.Equal(t, "provider-command-before-intent-persist", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityCritical, rule.DefaultSeverity())
	assert.True(t, rules.HonorsSuppression(rule))
}

func TestProviderCommandBeforeIntentPersistRule_CommandAndPersistenceVocabulary(t *testing.T) {
	tests := []struct {
		commandReceiver string
		commandMethod   string
		stateReceiver   string
		stateMethod     string
	}{
		{"paywho", "SendTransaction", "txnRepo", "UpdateState"},
		{"provider", "ExecutePayment", "store", "SaveState"},
		{"payment", "SubmitPayment", "db", "PersistState"},
		{"payout", "CreatePayout", "repo", "RecordState"},
		{"bank", "SendPayout", "stateStore", "CreateState"},
		{"remit", "TransferFunds", "ledgerDB", "UpdateState"},
	}

	for _, tt := range tests {
		name := tt.commandReceiver + "." + tt.commandMethod
		t.Run(name, func(t *testing.T) {
			code := fmt.Sprintf(`package service
func send(s *Service, req Request) error {
	resp, err := s.%s.%s(req)
	if err != nil { return err }
	return s.%s.%s(resp.ID)
}`, tt.commandReceiver, tt.commandMethod, tt.stateReceiver, tt.stateMethod)
			ctx := createQueryContext(t, "service.go", code)
			assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
		})
	}
}

func TestProviderCommandBeforeIntentPersistRule_DurableEvidenceVocabulary(t *testing.T) {
	for _, method := range []string{
		"PersistPaywhoRequest",
		"SavePaymentIntent",
		"RecordPayoutAttempt",
		"CreateTransferOutbox",
		"EnqueueProviderCommand",
	} {
		t.Run(method, func(t *testing.T) {
			code := fmt.Sprintf(`package service
func send(s *Service, req Request) error {
	if err := s.repo.%s(req); err != nil { return err }
	resp, err := s.provider.SendTransaction(req)
	if err != nil { return err }
	return s.repo.UpdateState(resp.ID)
}`, method)
			ctx := createQueryContext(t, "service.go", code)
			assert.Empty(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx))
		})
	}
}

func TestProviderCommandBeforeIntentPersistRule_DurableEvidenceRequiresPersistenceReceiver(t *testing.T) {
	for _, receiver := range []string{"metrics", "cache"} {
		t.Run(receiver, func(t *testing.T) {
			code := fmt.Sprintf(`package service
func send(s *Service, req Request) error {
	s.%s.RecordPayoutAttempt(req)
	resp, err := s.provider.SendTransaction(req)
	if err != nil { return err }
	return s.repo.UpdateState(resp.ID)
}`, receiver)
			ctx := createQueryContext(t, "service.go", code)

			assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
		})
	}
}

func TestProviderCommandBeforeIntentPersistRule_EnclosingPersistenceRunsAfterCommandArgument(t *testing.T) {
	code := `package service
func send(s *Service, req Request) error {
	return s.repo.UpdateState(s.provider.SendTransaction(req))
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

func TestProviderCommandBeforeIntentPersistRule_DetectsDirectGoCommand(t *testing.T) {
	code := `package service
func send(s *Service, req Request) error {
	go s.provider.SendTransaction(req)
	return s.repo.UpdateState(req.ID)
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

func TestProviderCommandBeforeIntentPersistRule_AsyncIntentDoesNotProveDurability(t *testing.T) {
	code := `package service
func send(s *Service, req Request) error {
	go s.repo.SavePaymentIntent(req)
	resp, err := s.provider.SendTransaction(req)
	if err != nil { return err }
	return s.repo.UpdateState(resp.ID)
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

func TestProviderCommandBeforeIntentPersistRule_ShortCircuitPersistenceIsNotDurableOnAllPaths(t *testing.T) {
	for _, operator := range []string{"&&", "||"} {
		t.Run(operator, func(t *testing.T) {
			code := fmt.Sprintf(`package service
func send(s *Service, req Request, enabled bool) error {
	saved := enabled %s s.repo.SavePaymentIntent(req) == nil
	_ = saved
	_, err := s.provider.SendTransaction(req)
	return err
}`, operator)
			ctx := createQueryContext(t, "service.go", code)

			assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
		})
	}
}

func TestProviderCommandBeforeIntentPersistRule_DurableIntentMustMatchCommandEntity(t *testing.T) {
	code := `package service
func send(s *Service, reqA, reqB Request) error {
	if err := s.repo.SavePaymentIntent(reqA); err != nil { return err }
	_, err := s.provider.SendTransaction(reqB)
	return err
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

func TestProviderCommandBeforeIntentPersistRule_SkipsContextWhenCorrelatingEntity(t *testing.T) {
	code := `package service
func send(s *Service, requestCtx Context, reqA, reqB Request) error {
	if err := s.repo.SavePaymentIntent(requestCtx, reqA); err != nil { return err }
	_, err := s.provider.SendTransaction(requestCtx, reqB)
	return err
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

func TestProviderCommandBeforeIntentPersistRule_MatchesNormalizedBusinessEntity(t *testing.T) {
	code := `package service
func send(s *Service, ctx Context, req Request) error {
	if err := s.repo.SavePaymentIntent(ctx, (req)); err != nil { return err }
	_, err := s.provider.SendTransaction(ctx, req)
	return err
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Empty(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx))
}

func TestProviderCommandBeforeIntentPersistRule_DoesNotLinkMutuallyExclusiveBranches(t *testing.T) {
	code := `package service
func send(s *Service, req Request, execute bool) error {
	if execute {
		_, err := s.provider.SendTransaction(req)
		return err
	} else {
		return s.repo.UpdateState(req.ID)
	}
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Empty(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx))
}

func TestProviderCommandBeforeIntentPersistRule_AnalyzesFuncLitAsIndependentRoot(t *testing.T) {
	code := `package service
func handler(s *Service) func(Request) error {
	return func(req Request) error {
		resp, err := s.provider.SendTransaction(req)
		if err != nil { return err }
		return s.repo.UpdateState(resp.ID)
	}
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

func TestProviderCommandBeforeIntentPersistRule_Detection(t *testing.T) {
	tests := []struct {
		name string
		path string
		code string
		want int
	}{
		{
			name: "old ProPay command before sent state persistence",
			path: "internal/service/transaction.go",
			code: `package service
func (s *Service) send(req Request) error {
	resp, err := s.paywho.SendTransaction(req)
	if err != nil {
		return err
	}
	return s.txnRepo.UpdateSentToProvider(resp.ID)
}`,
			want: 1,
		},
		{
			name: "durable provider request persisted before command",
			path: "internal/service/transaction.go",
			code: `package service
func (s *Service) send(req Request) error {
	if err := s.txnRepo.PersistPaywhoRequest(req); err != nil {
		return err
	}
	resp, err := s.paywho.SendTransaction(req)
	if err != nil {
		return err
	}
	return s.txnRepo.UpdateSentToProvider(resp.ID)
}`,
			want: 0,
		},
		{
			name: "pure provider adapter without later persistence",
			path: "internal/provider/paywho/client.go",
			code: `package paywho
func (c *Client) send(req Request) (Response, error) {
	return c.paymentProvider.SubmitPayment(req)
}`,
			want: 0,
		},
		{
			name: "unrelated email send",
			path: "internal/notification/email.go",
			code: `package notification
func (s *Service) notify(msg Message) error {
	if err := s.email.Send(msg); err != nil {
		return err
	}
	return s.repo.RecordDelivery(msg.ID)
}`,
			want: 0,
		},
		{
			name: "financial method on non-provider receiver",
			path: "internal/notification/email.go",
			code: `package notification
func (s *Service) notify(req Request) error {
	resp, err := s.email.SendTransaction(req)
	if err != nil {
		return err
	}
	return s.repo.RecordDelivery(resp.ID)
}`,
			want: 0,
		},
		{
			name: "command and persistence in different functions",
			path: "internal/provider/payment.go",
			code: `package provider
func execute(s *Service, req Request) (Response, error) {
	return s.bank.ExecutePayment(req)
}
func record(s *Service, resp Response) error {
	return s.store.SaveProviderResponse(resp)
}`,
			want: 0,
		},
		{
			name: "test file excluded",
			path: "internal/service/transaction_test.go",
			code: `package service
func exercise(s *Service, req Request) error {
	resp, err := s.payoutProvider.CreatePayout(req)
	if err != nil {
		return err
	}
	return s.db.CreatePayoutState(resp.ID)
}`,
			want: 0,
		},
		{
			name: "standard suppression",
			path: "internal/service/transaction.go",
			code: `package service
func (s *Service) send(req Request) error {
	//nolint:provider-command-before-intent-persist // caller persisted an outbox command
	resp, err := s.paywho.SendTransaction(req)
	if err != nil { return err }
	return s.txnRepo.UpdateSentToProvider(resp.ID)
}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createQueryContext(t, tt.path, tt.code)
			violations := NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx)
			assert.Len(t, violations, tt.want)
			if tt.want == 0 {
				return
			}
			require.NotEmpty(t, violations)
			assert.Equal(t, "provider_command_before_intent_persist", violations[0].Context["pattern"])
			assert.Equal(t, "send", violations[0].Context["function"])
			assert.Equal(t, 3, violations[0].Line)
		})
	}
}

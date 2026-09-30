package patterns

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
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
		{"payprov", "SendTransaction", "txnRepo", "UpdateState"},
		{"provider", "ExecutePayment", "store", "SaveState"},
		{"payment", "SubmitPayment", "db", "PersistState"},
		{"payout", "CreatePayout", "repo", "RecordState"},
		{"bank", "SendPayout", "stateStore", "CreateState"},
		{"remit", "TransferFunds", "ledgerDB", "UpdateState"},
		{"provider", "CancelTransaction", "repo", "UpdateState"},
		{"payment", "CancelPayment", "store", "SaveState"},
		{"provider", "RefundPayment", "db", "PersistState"},
		{"payment", "CreateRefund", "repo", "RecordState"},
		{"bank", "SendRefund", "ledgerDB", "UpdateState"},
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
		"PersistPayprovRequest",
		"SavePaymentIntent",
		"RecordPayoutAttempt",
		"CreateTransferOutbox",
		"EnqueueProviderCommand",
		"ClaimPaymentIntent",
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

func TestProviderCommandBeforeIntentPersistRule_AcquireIsNotDurableEvidence(t *testing.T) {
	code := `package service
func send(s *Service, req Request) error {
	if err := s.repo.AcquirePaymentIntent(req); err != nil { return err }
	resp, err := s.provider.SendTransaction(req)
	if err != nil { return err }
	return s.repo.UpdateState(resp.ID)
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

func TestProviderCommandBeforeIntentPersistRule_MatchesCancellationIntentSemantics(t *testing.T) {
	code := `package service
func cancel(s *Service, tx Transaction) error {
	if err := s.repo.ClaimCancellationIntent(tx.ID); err != nil { return err }
	return s.provider.CancelTransaction(tx.Reference)
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Empty(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx))
}

func TestProviderCommandBeforeIntentPersistRule_OperationSemanticsRequireSameEntityRoot(t *testing.T) {
	code := `package service
func cancel(s *Service, txA, txB Transaction) error {
	if err := s.repo.ClaimCancellationIntent(txA.ID); err != nil { return err }
	return s.provider.CancelTransaction(txB.Reference)
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

func TestProviderCommandBeforeIntentPersistRule_DoesNotMatchDifferentIntentOperation(t *testing.T) {
	code := `package service
func refund(s *Service, tx Transaction) error {
	if err := s.repo.ClaimCancellationIntent(tx.ID); err != nil { return err }
	return s.provider.RefundPayment(tx.Reference)
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

func TestProviderCommandBeforeIntentPersistRule_DoesNotCombineOperationAndEntityAcrossIntents(t *testing.T) {
	code := `package service
func cancel(s *Service, txA, txB Transaction) error {
	if err := s.repo.ClaimCancellationIntent(txA.ID); err != nil { return err }
	if err := s.repo.ClaimRefundIntent(txB.ID); err != nil { return err }
	return s.provider.CancelTransaction(txB.Reference)
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

func TestProviderCommandBeforeIntentPersistRule_EntityOwnerPath(t *testing.T) {
	tests := []struct {
		name       string
		persistArg string
		commandArg string
		want       int
	}{
		{name: "same owner", persistArg: "tx.ID", commandArg: "tx.Reference", want: 0},
		{name: "different nested owner", persistArg: "req.A.ID", commandArg: "req.B.Reference", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := fmt.Sprintf(`package service
func cancel(s *Service, tx Transaction, req Request) error {
	if err := s.repo.ClaimCancellationIntent(%s); err != nil { return err }
	return s.provider.CancelTransaction(%s)
}`, tt.persistArg, tt.commandArg)
			ctx := createQueryContext(t, "service.go", code)

			assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), tt.want)
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

func TestProviderCommandBeforeIntentPersistRule_ShortCircuitPersistenceGuardsCommand(t *testing.T) {
	code := `package service
func send(s *Service, req Request, enabled bool) error {
	if enabled && s.repo.SavePaymentIntent(req) == nil {
		_, err := s.provider.SendTransaction(req)
		return err
	}
	return nil
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Empty(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx))
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
import "context"
func send(s *Service, requestCtx context.Context, reqA, reqB Request) error {
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

func TestProviderCommandBeforeIntentPersistRule_MatchesAddressedAndDereferencedEntity(t *testing.T) {
	for _, tt := range []struct {
		name       string
		persistArg string
		commandArg string
	}{
		{name: "persist address", persistArg: "&req", commandArg: "req"},
		{name: "command address", persistArg: "req", commandArg: "&req"},
		{name: "persist dereference", persistArg: "*req", commandArg: "req"},
		{name: "command dereference", persistArg: "req", commandArg: "*req"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code := fmt.Sprintf(`package service
func send(s *Service, ctx Context, req Request) error {
	if err := s.repo.SavePaymentIntent(ctx, %s); err != nil { return err }
	_, err := s.provider.SendTransaction(ctx, %s)
	return err
}`, tt.persistArg, tt.commandArg)
			ctx := createQueryContext(t, "service.go", code)

			assert.Empty(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx))
		})
	}
}

func TestProviderCommandBeforeIntentPersistRule_RealProjectCSerializedRequestPersistence(t *testing.T) {
	code := `package orchestrator
func (s *confirmationService) sendPayprovTransaction(ctx context.Context, tx *domain.Transaction) (*domain.Transaction, error) {
	payprovReq, err := buildPayprovRequest(tx)
	if err != nil {
		s.errors.record(ctx, tx, "build Payprov request", err)
		return tx, fmt.Errorf("build payprov request: %w", err)
	}
	reqJSON, err := payprov.MarshalPOSTBody(payprovReq)
	if err != nil {
		s.errors.record(ctx, tx, "marshal Payprov request", err)
		return tx, fmt.Errorf("marshal payprov request: %w", err)
	}
	if err := payprovrequest.ValidateSendTransactionRequestAgainstPayprovContract(payprovReq, s.payprov); err != nil {
		s.errors.record(ctx, tx, "validate Payprov request contract", err, reqJSON)
		return tx, fmt.Errorf("validate payprov request contract: %w", err)
	}
	if err := s.txnRepo.PersistPayprovRequest(ctx, tx.ID, tx.Version, reqJSON); err != nil {
		return tx, fmt.Errorf("persist Payprov request before send: %w", err)
	}
	tx.Version++

	resp, err := s.payprov.SendTransaction(payprovReq)
	return tx, err
}`
	ctx := createQueryContext(t, "internal/orchestrator/orchestrator.go", code)

	assert.Empty(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx))
}

func TestProviderCommandBeforeIntentPersistRule_ProviderSpecificPersistenceMustMatchReceiver(t *testing.T) {
	code := `package service
func send(s *Service, ctx Context, tx Transaction, req Request) error {
	if err := s.repo.PersistPayprovRequest(ctx, tx.ID, tx.Version, req.JSON); err != nil { return err }
	_, err := s.bank.SendTransaction(req)
	return err
}`
	ctx := createQueryContext(t, "service.go", code)

	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
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

// The context argument is recognised by its type, not by its name: a context
// called "c" is skipped when correlating the entity, and a request envelope
// called "callContext" is the entity.
func TestProviderCommandBeforeIntentPersistRule_ContextByType(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"svc/svc.go": `package svc

import "context"

type Request struct{ ID string }

type Envelope struct{ Request Request }

type Repo struct{}

func (r *Repo) SavePaymentIntent(ctx context.Context, req Request) error { return nil }
func (r *Repo) SaveEnvelopeIntent(env Envelope, req Request) error      { return nil }
func (r *Repo) UpdateState(id string) error                             { return nil }

type Provider struct{}

func (p *Provider) SendTransaction(ctx context.Context, req Request) (Request, error) { return req, nil }
func (p *Provider) SendPayout(env Envelope, req Request) (Request, error)            { return req, nil }

type Service struct {
	repo     *Repo
	provider *Provider
}

func (s *Service) contextNamedC(c context.Context, reqA, reqB Request) error {
	if err := s.repo.SavePaymentIntent(c, reqA); err != nil {
		return err
	}
	_, err := s.provider.SendTransaction(c, reqB)
	return err
}

func (s *Service) envelopeNamedLikeContext(callContext Envelope, reqA, reqB Request) error {
	if err := s.repo.SaveEnvelopeIntent(callContext, reqA); err != nil {
		return err
	}
	_, err := s.provider.SendPayout(callContext, reqB)
	return err
}
`,
	})

	violations, err := NewProviderCommandBeforeIntentPersistRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	var functions []string
	for _, v := range violations {
		functions = append(functions, v.Context["function"].(string))
	}
	assert.Equal(t, []string{"contextNamedC"}, functions)
}

// Without type information a context is what the file declares as one.
func TestProviderCommandBeforeIntentPersistRule_DeclaredContextWithoutTypes(t *testing.T) {
	code := `package service
import "context"
func send(s *Service, c context.Context, reqA, reqB Request) error {
	if err := s.repo.SavePaymentIntent(c, reqA); err != nil { return err }
	_, err := s.provider.SendTransaction(c, reqB)
	return err
}`
	ctx := createQueryContext(t, "service.go", code)
	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

// A repository insert whose name reads like a provider command is still a
// write to the rule's own store: the receiver's name says it is a repository.
func TestProviderCommandBeforeIntentPersistRule_RepositoryIsNotAProvider(t *testing.T) {
	for _, receiver := range []string{"payoutRepo", "paymentStore", "bankDB", "payoutRepository", "remitLedger"} {
		t.Run(receiver, func(t *testing.T) {
			code := fmt.Sprintf(`package service
func (s *Svc) Create(ctx Context, p *Payout) error {
	if err := s.%s.CreatePayout(ctx, p); err != nil {
		return err
	}
	return s.%s.UpdateStatus(ctx, p.ID, "pending")
}`, receiver, receiver)
			ctx := createQueryContext(t, "service.go", code)
			assert.Empty(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx))
		})
	}
}

// A provider whose name merely contains a store word ("sandbox" holds "db")
// is still a provider.
func TestProviderCommandBeforeIntentPersistRule_StoreFragmentInProviderName(t *testing.T) {
	code := `package service
func (s *Svc) Send(req Request) error {
	resp, err := s.sandboxBank.SendPayout(req)
	if err != nil { return err }
	return s.repo.UpdateState(resp.ID)
}`
	ctx := createQueryContext(t, "service.go", code)
	assert.Len(t, NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx), 1)
}

// Short-circuit operators fork the path list; the fork goes through the
// shared path cap, so a long chain of them stays linear.
func TestProviderCommandBeforeIntentPersistRule_ShortCircuitChainIsBounded(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&body, "\tok = ok && s.provider.SendPayout(req%d) == nil\n", i)
	}
	code := "package service\nfunc send(s *Service, ok bool) error {\n" + body.String() + "\treturn s.repo.UpdateState(1)\n}"
	ctx := createQueryContext(t, "service.go", code)

	done := make(chan []*core.Violation, 1)
	go func() { done <- NewProviderCommandBeforeIntentPersistRule().AnalyzeFile(ctx) }()
	select {
	case violations := <-done:
		assert.Len(t, violations, 40)
	case <-time.After(10 * time.Second):
		t.Fatal("short-circuit chain did not finish: path list grows without the cap")
	}
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
			name: "old ProjectC command before sent state persistence",
			path: "internal/service/transaction.go",
			code: `package service
func (s *Service) send(req Request) error {
	resp, err := s.payprov.SendTransaction(req)
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
	if err := s.txnRepo.PersistPayprovRequest(req); err != nil {
		return err
	}
	resp, err := s.payprov.SendTransaction(req)
	if err != nil {
		return err
	}
	return s.txnRepo.UpdateSentToProvider(resp.ID)
}`,
			want: 0,
		},
		{
			name: "pure provider adapter without later persistence",
			path: "internal/provider/payprov/client.go",
			code: `package payprov
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
	resp, err := s.payprov.SendTransaction(req)
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

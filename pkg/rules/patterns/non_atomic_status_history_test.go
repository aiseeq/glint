package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNonAtomicStatusHistoryRule_Metadata(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()

	assert.Equal(t, "non-atomic-status-history", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestNonAtomicStatusHistoryRule_ProPayPattern(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "transaction_service.go", `package service

func (s *Service) markSent(ctx context.Context, txnID string) error {
	if err := s.txnRepo.UpdateStatusWithPaywho(ctx, txnID, "sent", "PW-123"); err != nil {
		return err
	}
	return s.txnRepo.RecordStatusHistory(ctx, txnID, "sent")
}`)

	violations := rule.AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	v := violations[0]
	assert.Equal(t, 4, v.Line)
	assert.Contains(t, v.Message, "UpdateStatusWithPaywho")
	assert.Contains(t, v.Message, "RecordStatusHistory")
	assert.Contains(t, v.Suggestion, "atomic repository method or transaction")
	assert.Equal(t, "non_atomic_status_history", v.Context["pattern"])
	assert.Equal(t, "markSent", v.Context["function"])
	assert.Equal(t, "s.txnRepo", v.Context["receiver"])
	assert.Equal(t, "UpdateStatusWithPaywho", v.Context["mutation_method"])
	assert.Equal(t, "RecordStatusHistory", v.Context["history_method"])
	assert.Contains(t, v.Code, "UpdateStatusWithPaywho")
}

func TestNonAtomicStatusHistoryRule_MutationMethods(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	for _, method := range []string{
		"UpdateStatus",
		"UpdateStatusWithPaywho",
		"UpdateQuote",
		"UpdateSentToProvider",
		"MarkWaitingApproval",
		"Create",
		"CreateOrGet",
	} {
		t.Run(method, func(t *testing.T) {
			code := `package service
func update(repo Repository) {
	repo.` + method + `(ctx, id)
	repo.RecordStatusHistory(ctx, id)
}`
			ctx := createNonAtomicStatusHistoryContext(t, "service.go", code)
			assert.Len(t, rule.AnalyzeFile(ctx), 1)
		})
	}
}

func TestNonAtomicStatusHistoryRule_DetectsQuoteHelperBeforeHistory(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "quote_service.go", `package service
func persist(s *Service) error {
	if err := s.updateQuoteRecord(ctx, tx); err != nil { return err }
	return s.txnRepo.RecordStatusHistory(ctx, tx.ID)
}`)

	violations := rule.AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, "updateQuoteRecord", violations[0].Context["mutation_method"])
}

func TestNonAtomicStatusHistoryRule_DoesNotLinkMutuallyExclusiveBranches(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", `package service
func update(repo Repository, approved bool) {
	if approved {
		repo.UpdateStatus(ctx, id)
	} else {
		repo.RecordStatusHistory(ctx, id)
	}
}`)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestNonAtomicStatusHistoryRule_DoesNotLinkTerminatedBranch(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", `package service
func update(repo Repository, id string, cond bool) {
	if cond {
		repo.UpdateStatus(ctx, id)
		return
	}
	repo.RecordStatusHistory(ctx, id)
}`)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestNonAtomicStatusHistoryRule_DoesNotLinkShadowedIdentifiers(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	tests := []struct {
		name string
		code string
	}{
		{
			name: "shadowed receiver history",
			code: `package service
func update(repo Repository, id string) {
	repo.UpdateStatus(ctx, id)
	{
		repo := auditRepo
		repo.RecordStatusHistory(ctx, id)
	}
}`,
		},
		{
			name: "shadowed receiver mutation",
			code: `package service
func update(repo Repository, id string) {
	{
		repo := auditRepo
		repo.UpdateStatus(ctx, id)
	}
	repo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "shadowed entity history",
			code: `package service
func update(repo Repository, id string) {
	repo.UpdateStatus(ctx, id)
	{
		id := auditID
		repo.RecordStatusHistory(ctx, id)
	}
}`,
		},
		{
			name: "shadowed entity mutation",
			code: `package service
func update(repo Repository, id string) {
	{
		id := auditID
		repo.UpdateStatus(ctx, id)
	}
	repo.RecordStatusHistory(ctx, id)
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createNonAtomicStatusHistoryContext(t, "service.go", tt.code)
			assert.Empty(t, rule.AnalyzeFile(ctx))
		})
	}
}

func TestNonAtomicStatusHistoryRule_DoesNotLinkDifferentEntities(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", `package service
func update(repo Repository) {
	repo.UpdateStatus(ctx, idA)
	repo.RecordStatusHistory(ctx, idB)
}`)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestNonAtomicStatusHistoryRule_DetectsSequenceInsideFuncLit(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", `package service
func update(repo Repository) func() {
	return func() {
		repo.UpdateStatus(ctx, id)
		repo.RecordStatusHistory(ctx, id)
	}
}`)

	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestNonAtomicStatusHistoryRule_DoesNotLinkSiblingReceivers(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", `package service
func update(s *Service) {
	s.UpdateStatus(ctx, id)
	s.auditRepo.RecordStatusHistory(ctx, id)
}`)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestNonAtomicStatusHistoryRule_DoesNotFlagSafeBoundaries(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	tests := []struct {
		name string
		code string
	}{
		{
			name: "atomic Apply method",
			code: `package service
func update(repo Repository) {
	repo.ApplyStatusAndHistory(ctx, id)
	repo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "mutation only",
			code: `package service
func update(repo Repository) {
	repo.UpdateStatus(ctx, id)
}`,
		},
		{
			name: "history only",
			code: `package service
func update(repo Repository) {
	repo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "history is before mutation",
			code: `package service
func update(repo Repository) {
	repo.RecordStatusHistory(ctx, id)
	repo.UpdateStatus(ctx, id)
}`,
		},
		{
			name: "calls are in different functions",
			code: `package service
func update(repo Repository) {
	repo.UpdateStatus(ctx, id)
}
func history(repo Repository) {
	repo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "calls use different repository chains",
			code: `package service
func update(s *Service) {
	s.txnRepo.UpdateStatus(ctx, id)
	s.auditRepo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "history is in nested function",
			code: `package service
func update(repo Repository) {
	repo.UpdateStatus(ctx, id)
	record := func() { repo.RecordStatusHistory(ctx, id) }
	_ = record
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createNonAtomicStatusHistoryContext(t, "service.go", tt.code)
			assert.Empty(t, rule.AnalyzeFile(ctx))
		})
	}
}

func TestNonAtomicStatusHistoryRule_Suppression(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	code := `package service
func update(repo Repository) {
	//nolint:non-atomic-status-history // external transaction wraps both writes
	repo.UpdateStatus(ctx, id)
	repo.RecordStatusHistory(ctx, id)
}`
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", code)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestNonAtomicStatusHistoryRule_SkipsTestFiles(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	code := `package service
func update(repo Repository) {
	repo.UpdateStatus(ctx, id)
	repo.RecordStatusHistory(ctx, id)
}`
	ctx := createNonAtomicStatusHistoryContext(t, "service_test.go", code)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func createNonAtomicStatusHistoryContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Content: []byte(code),
		Lines:   strings.Split(code, "\n"),
	}
	parser := core.NewParser()
	fset, file, err := parser.ParseGoFile(path, []byte(code))
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)
	return ctx
}

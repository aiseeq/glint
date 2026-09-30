package patterns

import (
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNonAtomicStatusHistoryRule_Metadata(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()

	assert.Equal(t, "non-atomic-status-history", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestNonAtomicStatusHistoryRule_ProjectCPattern(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "transaction_service.go", `package service; import "context"

func (ctx context.Context, s *Service) markSent(ctx context.Context, txnID string) error {
	if err := s.txnRepo.UpdateStatusWithPayprov(ctx, txnID, "sent", "PW-123"); err != nil {
		return err
	}
	return s.txnRepo.RecordStatusHistory(ctx, txnID, "sent")
}`)

	violations := rule.AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	v := violations[0]
	assert.Equal(t, 4, v.Line)
	assert.Contains(t, v.Message, "UpdateStatusWithPayprov")
	assert.Contains(t, v.Message, "RecordStatusHistory")
	assert.Contains(t, v.Suggestion, "atomic repository method or transaction")
	assert.Equal(t, "non_atomic_status_history", v.Context["pattern"])
	assert.Equal(t, "markSent", v.Context["function"])
	assert.Equal(t, "s.txnRepo", v.Context["receiver"])
	assert.Equal(t, "UpdateStatusWithPayprov", v.Context["mutation_method"])
	assert.Equal(t, "RecordStatusHistory", v.Context["history_method"])
	assert.Contains(t, v.Code, "UpdateStatusWithPayprov")
}

func TestNonAtomicStatusHistoryRule_MutationMethods(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	for _, method := range []string{
		"UpdateStatus",
		"UpdateStatusWithPayprov",
		"UpdateQuote",
		"UpdateSentToProvider",
		"MarkWaitingApproval",
		"Create",
		"CreateOrGet",
	} {
		t.Run(method, func(t *testing.T) {
			code := `package service; import "context"
func update(ctx context.Context, repo Repository) {
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
	ctx := createNonAtomicStatusHistoryContext(t, "quote_service.go", `package service; import "context"
func persist(ctx context.Context, s *Service) error {
	if err := s.updateQuoteRecord(ctx, tx); err != nil { return err }
	return s.txnRepo.RecordStatusHistory(ctx, tx.ID)
}`)

	violations := rule.AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, "updateQuoteRecord", violations[0].Context["mutation_method"])
}

func TestNonAtomicStatusHistoryRule_DoesNotLinkMutuallyExclusiveBranches(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", `package service; import "context"
func update(ctx context.Context, repo Repository, approved bool) {
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
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", `package service; import "context"
func update(ctx context.Context, repo Repository, id string, cond bool) {
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
			code: `package service; import "context"
func update(ctx context.Context, repo Repository, id string) {
	repo.UpdateStatus(ctx, id)
	{
		repo := auditRepo
		repo.RecordStatusHistory(ctx, id)
	}
}`,
		},
		{
			name: "shadowed receiver mutation",
			code: `package service; import "context"
func update(ctx context.Context, repo Repository, id string) {
	{
		repo := auditRepo
		repo.UpdateStatus(ctx, id)
	}
	repo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "shadowed entity history",
			code: `package service; import "context"
func update(ctx context.Context, repo Repository, id string) {
	repo.UpdateStatus(ctx, id)
	{
		id := auditID
		repo.RecordStatusHistory(ctx, id)
	}
}`,
		},
		{
			name: "shadowed entity mutation",
			code: `package service; import "context"
func update(ctx context.Context, repo Repository, id string) {
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

func TestNonAtomicStatusHistoryRule_DoesNotLinkReassignedIdentifiers(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	tests := []struct {
		name string
		code string
	}{
		{
			name: "reassigned receiver",
			code: `package service; import "context"
func update(ctx context.Context, repo Repository, id string) {
	repo.UpdateStatus(ctx, id)
	repo = auditRepo
	repo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "reassigned entity",
			code: `package service; import "context"
func update(ctx context.Context, repo Repository, id string) {
	repo.UpdateStatus(ctx, id)
	id = auditID
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
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", `package service; import "context"
func update(ctx context.Context, repo Repository) {
	repo.UpdateStatus(ctx, idA)
	repo.RecordStatusHistory(ctx, idB)
}`)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestNonAtomicStatusHistoryRule_DetectsSequenceInsideFuncLit(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", `package service; import "context"
func update(ctx context.Context, repo Repository) func() {
	return func() {
		repo.UpdateStatus(ctx, id)
		repo.RecordStatusHistory(ctx, id)
	}
}`)

	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestNonAtomicStatusHistoryRule_DoesNotLinkSiblingReceivers(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", `package service; import "context"
func update(ctx context.Context, s *Service) {
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
			code: `package service; import "context"
func update(ctx context.Context, repo Repository) {
	repo.ApplyStatusAndHistory(ctx, id)
	repo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "mutation only",
			code: `package service; import "context"
func update(ctx context.Context, repo Repository) {
	repo.UpdateStatus(ctx, id)
}`,
		},
		{
			name: "history only",
			code: `package service; import "context"
func update(ctx context.Context, repo Repository) {
	repo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "history is before mutation",
			code: `package service; import "context"
func update(ctx context.Context, repo Repository) {
	repo.RecordStatusHistory(ctx, id)
	repo.UpdateStatus(ctx, id)
}`,
		},
		{
			name: "calls are in different functions",
			code: `package service; import "context"
func update(ctx context.Context, repo Repository) {
	repo.UpdateStatus(ctx, id)
}
func history(ctx context.Context, repo Repository) {
	repo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "calls use different repository chains",
			code: `package service; import "context"
func update(ctx context.Context, s *Service) {
	s.txnRepo.UpdateStatus(ctx, id)
	s.auditRepo.RecordStatusHistory(ctx, id)
}`,
		},
		{
			name: "history is in nested function",
			code: `package service; import "context"
func update(ctx context.Context, repo Repository) {
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
	code := `package service; import "context"
func update(ctx context.Context, repo Repository) {
	//nolint:non-atomic-status-history // external transaction wraps both writes
	repo.UpdateStatus(ctx, id)
	repo.RecordStatusHistory(ctx, id)
}`
	ctx := createNonAtomicStatusHistoryContext(t, "service.go", code)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestNonAtomicStatusHistoryRule_SkipsTestFiles(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	code := `package service; import "context"
func update(ctx context.Context, repo Repository) {
	repo.UpdateStatus(ctx, id)
	repo.RecordStatusHistory(ctx, id)
}`
	ctx := createNonAtomicStatusHistoryContext(t, "service_test.go", code)

	assert.Empty(t, rule.AnalyzeFile(ctx))
}

// Both writes inside a transaction runner's callback commit or roll back
// together.
func TestNonAtomicStatusHistoryRule_InsideTransactionRunner(t *testing.T) {
	code := `package service; import "context"
func (s *Service) Transition(ctx context.Context, id string) error {
	return s.db.RunInTx(ctx, func(ctx context.Context) error {
		if err := s.repo.UpdateStatus(ctx, id, "done"); err != nil {
			return err
		}
		return s.repo.RecordStatusHistory(ctx, id, "done")
	})
}

func (s *Service) Outside(ctx context.Context, id string) error {
	return s.retry.Do(ctx, func(ctx context.Context) error {
		if err := s.repo.UpdateStatus(ctx, id, "done"); err != nil {
			return err
		}
		return s.repo.RecordStatusHistory(ctx, id, "done")
	})
}`
	violations := NewNonAtomicStatusHistoryRule().AnalyzeFile(createNonAtomicStatusHistoryContext(t, "service.go", code))
	require.Len(t, violations, 1)
	assert.Equal(t, 13, violations[0].Line)
}

// The runner list is shared with multi-write-no-transaction's setting name.
func TestNonAtomicStatusHistoryRule_ConfiguredTransactionRunner(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	require.NoError(t, rule.Configure(map[string]any{"transaction_functions": []any{"WithinUnitOfWork"}}))
	code := `package service; import "context"
func (s *Service) Transition(ctx context.Context, id string) error {
	return s.uow.WithinUnitOfWork(ctx, func(ctx context.Context) error {
		if err := s.repo.UpdateStatus(ctx, id); err != nil {
			return err
		}
		return s.repo.RecordStatusHistory(ctx, id)
	})
}`
	assert.Empty(t, rule.AnalyzeFile(createNonAtomicStatusHistoryContext(t, "service.go", code)))

	require.Error(t, rule.Configure(map[string]any{"transaction_functions": "WithinUnitOfWork"}))
}

func TestNonAtomicStatusHistoryRule_ConfiguredMethodNames(t *testing.T) {
	rule := NewNonAtomicStatusHistoryRule()
	require.NoError(t, rule.Configure(map[string]any{
		"mutation_methods": []any{"SetState"},
		"history_methods":  []any{"AppendStateLog"},
	}))
	code := `package service; import "context"
func configured(ctx context.Context, repo Repository, id string) {
	repo.SetState(ctx, id)
	repo.AppendStateLog(ctx, id)
}
func defaults(ctx context.Context, repo Repository, id string) {
	repo.UpdateStatus(ctx, id)
	repo.RecordStatusHistory(ctx, id)
}`
	violations := rule.AnalyzeFile(createNonAtomicStatusHistoryContext(t, "service.go", code))
	require.Len(t, violations, 1)
	assert.Equal(t, "configured", violations[0].Context["function"])
	assert.Contains(t, violations[0].Message, "SetState followed by separate AppendStateLog")

	for _, bad := range []map[string]any{
		{"mutation_methods": "SetState"},
		{"history_methods": []any{""}},
		{"history_methods": []any{42}},
	} {
		assert.Error(t, NewNonAtomicStatusHistoryRule().Configure(bad), "%v", bad)
	}
}

// Without type information a first argument the file does not declare may
// or may not be the context, so the entity is unknown and the rule is quiet.
func TestNonAtomicStatusHistoryRule_UndeclaredFirstArgumentIsUnknown(t *testing.T) {
	code := `package service
func update(repo Repository) {
	repo.UpdateStatus(ctx, idA)
	repo.RecordStatusHistory(ctx, idB)
}`
	assert.Empty(t, NewNonAtomicStatusHistoryRule().AnalyzeFile(createNonAtomicStatusHistoryContext(t, "service.go", code)))
}

// With type information identities are the type checker's objects and a
// context is recognised by its type.
func TestNonAtomicStatusHistoryRule_Typed(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"svc/svc.go": `package svc

import "context"

type Repo struct{}

func (r *Repo) UpdateStatus(ctx context.Context, id string) error        { return nil }
func (r *Repo) RecordStatusHistory(ctx context.Context, id string) error { return nil }

type Other struct{}

func (o *Other) RecordStatusHistory(ctx context.Context, id string) error { return nil }

func contextNamedC(c context.Context, repo *Repo, idA, idB string) {
	_ = repo.UpdateStatus(c, idA)
	_ = repo.RecordStatusHistory(c, idB)
}

func sameEntity(c context.Context, repo *Repo, id string) {
	_ = repo.UpdateStatus(c, id)
	_ = repo.RecordStatusHistory(c, id)
}

func typeSwitchShadow(ctx context.Context, repo *Repo, r any, id string) {
	_ = repo.UpdateStatus(ctx, id)
	switch repo := r.(type) {
	case *Other:
		_ = repo.RecordStatusHistory(ctx, id)
	}
}
`,
	})

	violations, err := NewNonAtomicStatusHistoryRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	var functions []string
	for _, v := range violations {
		functions = append(functions, v.Context["function"].(string))
	}
	assert.Equal(t, []string{"sameEntity"}, functions)
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

// Paths used to double at every branch: a real 20+ branch function made the
// rule allocate ~15 GB and the process died.
func TestNonAtomicStatusHistoryRule_BranchExplosion(t *testing.T) {
	var body strings.Builder
	body.WriteString("package service; import \"context\"\n\nfunc step(ctx context.Context, repo Repository, n int) {\n")
	for i := 0; i < 24; i++ {
		body.WriteString("\tif n > ")
		body.WriteString(strconv.Itoa(i))
		body.WriteString(" {\n\t\tn++\n\t} else {\n\t\tn--\n\t}\n")
	}
	body.WriteString("\trepo.UpdateStatus(ctx, id)\n\trepo.RecordStatusHistory(ctx, id)\n}\n")

	rule := NewNonAtomicStatusHistoryRule()
	ctx := createNonAtomicStatusHistoryContext(t, "branch_explosion.go", body.String())

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	violations := rule.AnalyzeFile(ctx)
	runtime.ReadMemStats(&after)

	require.Len(t, violations, 1)
	allocatedMB := float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20)
	assert.Less(t, allocatedMB, 64.0, "24 branches must not cost %0.f MB", allocatedMB)
}

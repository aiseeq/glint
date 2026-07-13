package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdempotencyCheckThenCreateRule_Metadata(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()

	assert.Equal(t, "idempotency-check-then-create", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
	assert.Contains(t, rule.Description(), "TOCTOU")
}

func TestIdempotencyCheckThenCreateRule_DetectsProPayStyleRace(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments

func (s *quoteService) CreateQuote(ctx context.Context, tx *Transaction) error {
	existing, err := s.txnRepo.GetByIdempotencyKey(ctx, tx.IdempotencyKey)
	if err == nil {
		*tx = *existing
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	return s.txnRepo.Create(ctx, tx)
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "quote_service.go", code)
	violations := rule.AnalyzeFile(ctx)

	require.Len(t, violations, 1)
	v := violations[0]
	assert.Equal(t, 12, v.Line)
	assert.Contains(t, v.Message, "GetByIdempotencyKey")
	assert.Contains(t, v.Message, "Create")
	assert.Contains(t, v.Message, "TOCTOU")
	assert.Contains(t, v.Code, "s.txnRepo.Create")
	assert.Contains(t, v.Suggestion, "atomic")
	assert.Equal(t, "idempotency_check_then_create", v.Context["pattern"])
	assert.Equal(t, "CreateQuote", v.Context["function"])
	assert.Equal(t, "s.txnRepo", v.Context["receiver"])
	assert.Equal(t, "GetByIdempotencyKey", v.Context["lookup_method"])
	assert.Equal(t, "Create", v.Context["create_method"])
	assert.Equal(t, 4, v.Context["lookup_line"])
}

func TestIdempotencyCheckThenCreateRule_DetectsCompleteSequenceInFuncLit(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func saveLater(repo PaymentRepository, payment *Payment) func() error {
	return func() error {
		_, _ = repo.GetByIdempotencyKey(payment.IdempotencyKey)
		return repo.Create(payment)
	}
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	violations := rule.AnalyzeFile(ctx)

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
}

func TestIdempotencyCheckThenCreateRule_DetectsTypedShortReceiver(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func save(r PaymentRepository, key string, payment *Payment) error {
	_, _ = r.GetByIdempotencyKey(key)
	return r.Create(payment)
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestIdempotencyCheckThenCreateRule_DetectsTypedLocalReceiver(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func save(repo PaymentRepository, key string, payment *Payment) error {
	var r PaymentRepository = repo
	_, _ = r.GetByIdempotencyKey(key)
	return r.Create(payment)
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestIdempotencyCheckThenCreateRule_DoesNotLinkMutuallyExclusiveBranches(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func save(repo PaymentRepository, checkOnly bool, key string, payment *Payment) error {
	if checkOnly {
		_, _ = repo.GetByIdempotencyKey(key)
	} else {
		return repo.Create(payment)
	}
	return nil
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestIdempotencyCheckThenCreateRule_DoesNotLinkNegatedShortCircuitPath(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func save(repo PaymentRepository, enabled bool, key string, payment *Payment) error {
	if enabled && repo.ExistsByIdempotencyKey(key) {
		return nil
	}
	if !enabled && repo.Create(payment) == nil {
		return nil
	}
	return nil
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestIdempotencyCheckThenCreateRule_DoesNotLinkNegatedGuardPath(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func save(repo PaymentRepository, enabled bool, key string, payment *Payment) error {
	if enabled {
		_, _ = repo.GetByIdempotencyKey(key)
	}
	if enabled {
		return nil
	}
	return repo.Create(payment)
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestIdempotencyCheckThenCreateRule_DoesNotLinkShadowedReceiver(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func save(repo, otherRepo PaymentRepository, key string, payment *Payment) error {
	_, _ = repo.GetByIdempotencyKey(key)
	{
		repo := otherRepo
		return repo.Create(payment)
	}
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestIdempotencyCheckThenCreateRule_DoesNotLinkReassignedReceiver(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func save(repo, otherRepo PaymentRepository, key string, payment *Payment) error {
	_, _ = repo.GetByIdempotencyKey(key)
	repo = otherRepo
	return repo.Create(payment)
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestIdempotencyCheckThenCreateRule_DoesNotLinkDistinctDirectEntities(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func save(repo PaymentRepository, firstPayment, secondPayment *Payment) error {
	_, _ = repo.GetByIdempotencyKey(firstPayment.IdempotencyKey)
	return repo.Create(secondPayment)
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestIdempotencyCheckThenCreateRule_DoesNotLinkReassignedEntity(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func save(repo PaymentRepository, payment, otherPayment *Payment) error {
	_, _ = repo.GetByIdempotencyKey(payment.IdempotencyKey)
	payment = otherPayment
	return repo.Create(payment)
}`

	ctx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestIdempotencyCheckThenCreateRule_PositiveMethods(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	tests := []struct {
		name string
		code string
	}{
		{
			name: "find idempotency then insert",
			code: `package payments
func save(store PaymentStore, key string, payment *Payment) error {
	_, _ = store.FindByIdempotencyKey(key)
	return store.Insert(payment)
}`,
		},
		{
			name: "exists idempotency then create",
			code: `package payments
func save(db DB, key string, payment *Payment) error {
	if db.ExistsByIdempotencyKey(key) { return nil }
	return db.Create(payment)
}`,
		},
		{
			name: "lookup by reference then create",
			code: `package payments
func save(repo PaymentRepository, ref string, payment *Payment) error {
	_, _ = repo.GetByReference(ref)
	return repo.Create(payment)
}`,
		},
		{
			name: "analogous idempotency lookup name",
			code: `package payments
func save(repo PaymentRepository, key string, payment *Payment) error {
	_, _ = repo.LookupPaymentIdempotencyRecord(key)
	return repo.CreatePayment(payment)
}`,
		},
		{
			name: "short receiver on repository method",
			code: `package payments
func (r *TransactionRepo) save(key string, payment *Payment) error {
	_, _ = r.CheckIdempotencyKey(key)
	return r.Insert(payment)
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createIdempotencyCheckThenCreateContext(t, "service.go", tt.code)
			assert.Len(t, rule.AnalyzeFile(ctx), 1)
		})
	}
}

func TestIdempotencyCheckThenCreateRule_Negatives(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	tests := []struct {
		name string
		code string
	}{
		{
			name: "atomic create or get",
			code: `package payments
func save(repo PaymentRepository, key string, payment *Payment) error {
	_, _ = repo.GetByIdempotencyKey(key)
	_, err := repo.CreateOrGet(payment)
	return err
}`,
		},
		{
			name: "atomic upsert",
			code: `package payments
func save(store PaymentStore, key string, payment *Payment) error {
	_, _ = store.FindByIdempotencyKey(key)
	return store.Upsert(payment)
}`,
		},
		{
			name: "atomic insert on conflict",
			code: `package payments
func save(db DB, key string, payment *Payment) error {
	_, _ = db.GetByIdempotencyKey(key)
	return db.InsertOnConflict(payment)
}`,
		},
		{
			name: "lookup without create",
			code: `package payments
func get(repo PaymentRepository, key string) (*Payment, error) {
	return repo.GetByIdempotencyKey(key)
}`,
		},
		{
			name: "create without lookup",
			code: `package payments
func save(repo PaymentRepository, payment *Payment) error {
	return repo.Create(payment)
}`,
		},
		{
			name: "different functions",
			code: `package payments
func get(repo PaymentRepository, key string) { _, _ = repo.GetByIdempotencyKey(key) }
func save(repo PaymentRepository, payment *Payment) { _ = repo.Create(payment) }`,
		},
		{
			name: "different receivers",
			code: `package payments
func save(sourceRepo, targetRepo PaymentRepository, key string, payment *Payment) error {
	_, _ = sourceRepo.GetByIdempotencyKey(key)
	return targetRepo.Create(payment)
}`,
		},
		{
			name: "non data access receiver",
			code: `package payments
func save(client APIClient, key string, payment *Payment) error {
	_, _ = client.GetByIdempotencyKey(key)
	return client.Create(payment)
}`,
		},
		{
			name: "create before lookup",
			code: `package payments
func save(repo PaymentRepository, key string, payment *Payment) error {
	if err := repo.Create(payment); err != nil { return err }
	_, err := repo.GetByIdempotencyKey(key)
	return err
}`,
		},
		{
			name: "ordinary lookup",
			code: `package payments
func save(repo PaymentRepository, id string, payment *Payment) error {
	_, _ = repo.GetByID(id)
	return repo.Create(payment)
}`,
		},
		{
			name: "method returns a reference but does not look up by it",
			code: `package payments
func save(repo PaymentRepository, id string, payment *Payment) error {
	_, _ = repo.GetPersistedProviderReference(id)
	return repo.Create(payment)
}`,
		},
		{
			name: "lookup in nested function",
			code: `package payments
func save(repo PaymentRepository, key string, payment *Payment) error {
	check := func() { _, _ = repo.GetByIdempotencyKey(key) }
	_ = check
	return repo.Create(payment)
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createIdempotencyCheckThenCreateContext(t, "service.go", tt.code)
			assert.Empty(t, rule.AnalyzeFile(ctx))
		})
	}
}

func TestIdempotencyCheckThenCreateRule_ExcludesTestsAndHonorsSuppression(t *testing.T) {
	rule := NewIdempotencyCheckThenCreateRule()
	code := `package payments
func save(repo PaymentRepository, key string, payment *Payment) error {
	_, _ = repo.GetByIdempotencyKey(key)
	//nolint:idempotency-check-then-create // protected by a serializable transaction
	return repo.Create(payment)
}`

	testCtx := createIdempotencyCheckThenCreateContext(t, "service_test.go", code)
	assert.Empty(t, rule.AnalyzeFile(testCtx))

	productionCtx := createIdempotencyCheckThenCreateContext(t, "service.go", code)
	assert.Empty(t, rule.AnalyzeFile(productionCtx))
}

func createIdempotencyCheckThenCreateContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   strings.Split(code, "\n"),
		Content: []byte(code),
	}
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile(path, []byte(code))
	require.NoError(t, err)
	ctx.SetGoAST(fset, astFile)
	return ctx
}

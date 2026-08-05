package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestMaskedErrorOrConditionRule(t *testing.T) {
	rule := NewMaskedErrorOrConditionRule()

	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name: "db error conflated with no-data returns zero and nil",
			code: `package svc

func GetEffectiveAPY(ctx context.Context, strategy string) (SafeDecimal, error) {
	latest, err := repo.GetLatestSnapshot(ctx, strategy)
	if err != nil || latest == nil {
		logger.Warn("no latest snapshot", "error", err)
		return SafeDecimal{Decimal: decimal.Zero}, nil
	}
	return compute(latest), nil
}
`,
			wantCount: 1,
		},
		{
			name: "or of two error checks masks both",
			code: `package svc

func Load() (*Data, error) {
	a, err := loadA()
	b, err2 := loadB()
	if err != nil || err2 != nil {
		return nil, nil
	}
	return merge(a, b), nil
}
`,
			wantCount: 1,
		},
		{
			name: "proper split of error and no-data branches",
			code: `package svc

func GetEffectiveAPY(ctx context.Context, strategy string) (SafeDecimal, error) {
	latest, err := repo.GetLatestSnapshot(ctx, strategy)
	if err != nil {
		return SafeDecimal{}, fmt.Errorf("get snapshot: %w", err)
	}
	if latest == nil {
		return SafeDecimal{Decimal: decimal.Zero}, nil
	}
	return compute(latest), nil
}
`,
			wantCount: 0,
		},
		{
			name: "branch propagates the error",
			code: `package svc

func Get() (*Data, error) {
	d, err := load()
	if err != nil || d == nil {
		return nil, err
	}
	return d, nil
}
`,
			wantCount: 0,
		},
		{
			name: "err equals nil in or-condition is fine",
			code: `package svc

func Get() (*Data, error) {
	d, err := load()
	if err == nil || d.Cached {
		return d, nil
	}
	return nil, err
}
`,
			wantCount: 0,
		},
		{
			name: "and-condition narrowing is not flagged",
			code: `package svc

func Get() (*Data, error) {
	d, err := load()
	if err != nil && errors.Is(err, ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}
`,
			wantCount: 0,
		},
		{
			// Раньше здесь ожидался 0: случай считался зоной log-and-return-zero.
			// Но то правило требует Error/Warn-лог в ветке, а без лога ошибка
			// исчезала вовсе и не ловилась никем (ревью saga SI-487).
			name: "function without error result masks the failure entirely",
			code: `package svc

func Count() int {
	n, err := load()
	if err != nil || n == nil {
		return 0
	}
	return n.Value
}
`,
			wantCount: 1,
		},
		{
			name: "nested handling of err inside branch is not masking",
			code: `package svc

func Get() (*Data, error) {
	d, err := load()
	if err != nil || d == nil {
		if err != nil {
			return nil, fmt.Errorf("load: %w", err)
		}
		return nil, nil
	}
	return d, nil
}
`,
			wantCount: 0,
		},
		{
			name: "named error variable with Err suffix",
			code: `package svc

func Get() (*Data, error) {
	d, dbErr := load()
	if dbErr != nil || d == nil {
		return nil, nil
	}
	return d, nil
}
`,
			wantCount: 1,
		},
		{
			name: "closure with error result is analyzed",
			code: `package svc

func Wrap() {
	fn := func() (int, error) {
		v, err := load()
		if err != nil || v == 0 {
			return 0, nil
		}
		return v, nil
	}
	_ = fn
}
`,
			wantCount: 1,
		},
		{
			// Возврат принадлежит замыканию, а не внешней функции: внешняя
			// корректно отдаёт err. Само замыкание при этом глотает ошибку и
			// теперь считается находкой — но ровно одной, за счёт closure.
			name: "return inside nested closure is attributed to the closure",
			code: `package svc

func Get() (*Data, error) {
	d, err := load()
	cb := func() int {
		if err != nil || d == nil {
			return 0
		}
		return 1
	}
	_ = cb
	return d, err
}
`,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("service.go", ".", []byte(tt.code), nil)
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("service.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d; violations: %+v",
					len(violations), tt.wantCount, violations)
			}
		})
	}
}

// Дыра между правилами, вскрытая ревью saga (SI-487): функция БЕЗ error в
// сигнатуре схлопывает err с «нет данных» через || и молча возвращает значение.
// masked-error-in-or-condition требовал error в результатах, log-and-return-zero —
// наличия лога; случай «без error и без лога» не ловил никто, хотя он опаснее
// обоих: ошибку невозможно ни вернуть, ни увидеть в логе.
func TestMaskedErrorOrCondition_FunctionWithoutErrorResult(t *testing.T) {
	rule := NewMaskedErrorOrConditionRule()

	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name: "no error result: err swallowed via || and value returned",
			code: `package svc

func (s *S) calculateDayYield(userID string, cumulative Decimal) Decimal {
	userShare, err := s.calculateUserShare(userID)
	if err != nil || userShare.LessThanOrEqual(zero) {
		return cumulative
	}
	return cumulative.Add(userShare)
}
`,
			wantCount: 1,
		},
		{
			// Единственный bool-результат — зона error-masked-as-false-bool,
			// которое само отличает предикат от маскировки. Репро: собственный
			// self-check glint на isSecretQuerySet, где false означает
			// «литерал не разобрался, значит это не тот вызов».
			name: "bool predicate is out of scope: false means not-matched",
			code: `package svc

func (r *Rule) isSecretQuerySet(call *CallExpr) bool {
	name, err := strconv.Unquote(lit.Value)
	if err != nil || !r.secretParam.MatchString(name) {
		return false
	}
	return true
}
`,
			wantCount: 0,
		},
		{
			name: "no error result: panic on error is explicit, not masking",
			code: `package svc

func mustLoad(name string) Config {
	cfg, err := load(name)
	if err != nil || cfg == nil {
		panic("config unavailable: " + name)
	}
	return *cfg
}
`,
			wantCount: 0,
		},
		{
			name: "no error result: nested check on err distinguishes the failure",
			code: `package svc

func (s *S) value() Decimal {
	v, err := s.load()
	if err != nil || v.IsZero() {
		if err != nil {
			s.report(err)
		}
		return zero
	}
	return v
}
`,
			wantCount: 0,
		},
		{
			// Голый return из void-функции — ранний выход после обработки
			// (401 отправлен, запрос отклонён и залогирован), а не подмена
			// значения. Репро: middleware saga (auth, loopback, analytics).
			name: "bare return from a void function is an early exit, not masking",
			code: `package svc

func handler(w http.ResponseWriter, r *http.Request) {
	token, err := extract(r)
	if err != nil || token == "" {
		sendUnauthorized(w, err)
		return
	}
	serve(w, token)
}
`,
			wantCount: 0,
		},
		{
			name: "no error result and no return in branch: nothing masked",
			code: `package svc

func (s *S) refresh() {
	v, err := s.load()
	if err != nil || v.IsZero() {
		s.cache = zero
	}
}
`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("service.go", ".", []byte(tt.code), nil)
			fset, astFile, err := core.NewParser().ParseGoFile("service.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d; violations: %+v",
					len(violations), tt.wantCount, violations)
			}
		})
	}
}

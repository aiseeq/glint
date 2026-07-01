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
			name: "function without error result is out of scope",
			code: `package svc

func Count() int {
	n, err := load()
	if err != nil || n == nil {
		return 0
	}
	return n.Value
}
`,
			wantCount: 0,
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
			name: "return inside nested closure belongs to closure without error result",
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
			wantCount: 0,
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

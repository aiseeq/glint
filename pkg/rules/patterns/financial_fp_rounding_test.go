package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestFinancialFPRoundingRule(t *testing.T) {
	rule := NewFinancialFPRoundingRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name:      "floor balance * 100 / 100 is unsafe",
			code:      `const flooredBalance = Math.floor(availableBalance * 100) / 100`,
			filename:  "frontend/src/components/Withdrawal.tsx",
			wantCount: 1,
		},
		{
			name:      "ceil amount * 100 / 100 is unsafe",
			code:      `const v = Math.ceil(amount * 100) / 100`,
			filename:  "frontend/src/components/Foo.tsx",
			wantCount: 1,
		},
		{
			name:      "floor maxReceive * pct / 100 is unsafe (cent loss bug)",
			code:      `setWithdrawalAmount((Math.floor(maxReceive * pct) / 100).toFixed(2))`,
			filename:  "frontend/src/components/Withdrawal.tsx",
			wantCount: 1,
		},
		{
			name:      "explicit epsilon is safe",
			code:      `const safe = Math.floor(balance * 100 + 1e-9) / 100`,
			filename:  "frontend/src/components/Withdrawal.tsx",
			wantCount: 0,
		},
		{
			name:      "Math.round is safe (half-to-even on cent grid)",
			code:      `const v = Math.round(balance * 100) / 100`,
			filename:  "frontend/src/components/Foo.tsx",
			wantCount: 0,
		},
		{
			name:      "non-money pagination Math.ceil is ignored",
			code:      `const totalPages = Math.ceil(items / itemsPerPage)`,
			filename:  "frontend/src/components/Foo.tsx",
			wantCount: 0,
		},
		{
			name:      "chart axis floor is ignored (no money context)",
			code:      `const minTick = Math.floor(adjustedMin / magnitude) * magnitude`,
			filename:  "frontend/src/components/Chart.tsx",
			wantCount: 0,
		},
		{
			name:      "test files are skipped",
			code:      `const flooredBalance = Math.floor(availableBalance * 100) / 100`,
			filename:  "frontend/src/components/Withdrawal.test.tsx",
			wantCount: 0,
		},
		{
			name:      "math.Floor on float money in Go is unsafe",
			code:      `cents := math.Floor(balanceFloat * 100) / 100`,
			filename:  "backend/services/balance.go",
			wantCount: 1,
		},
		{
			name:      "decimal arithmetic in Go is fine (no math.Floor)",
			code:      `cents := balance.Mul(decimal.NewFromInt(100)).Floor()`,
			filename:  "backend/services/balance.go",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), nil)
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantCount)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d (%q)", v.Message, v.Line, v.Code)
				}
			}
		})
	}
}

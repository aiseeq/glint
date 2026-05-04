package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestFinancialRoundedDeltaRule(t *testing.T) {
	rule := NewFinancialRoundedDeltaRule()

	tests := []struct {
		name      string
		code      string
		filename  string
		wantCount int
	}{
		{
			name: "parsed cumulative profit subtraction is forbidden",
			code: `const currentProfit = parseFloat(entry.profit)
const prevProfit = parseFloat(previous.profit)
const dailyDelta = currentProfit - prevProfit`,
			filename:  "frontend/src/hooks/useOperations.ts",
			wantCount: 1,
		},
		{
			name:      "direct parsed amount subtraction is forbidden",
			code:      `const delta = parseFloat(today.balance) - parseFloat(yesterday.balance)`,
			filename:  "frontend/src/lib/balance.ts",
			wantCount: 1,
		},
		{
			name: "backend delta field is valid",
			code: `const dailyDelta = parseFloat(entry.dailyYield)
if (Math.abs(dailyDelta) < 0.001) return`,
			filename:  "frontend/src/hooks/useOperations.ts",
			wantCount: 0,
		},
		{
			name:      "non financial numeric subtraction is valid",
			code:      `const duration = parseFloat(endMs) - parseFloat(startMs)`,
			filename:  "frontend/src/lib/timing.ts",
			wantCount: 0,
		},
		{
			name:      "test files are skipped",
			code:      `const dailyDelta = parseFloat(entry.profit) - parseFloat(prev.profit)`,
			filename:  "frontend/src/hooks/useOperations.test.ts",
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

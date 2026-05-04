package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
)

func TestContextFirstRulePureAccessors(t *testing.T) {
	rule := NewContextFirstRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "detect helper",
			code: `package service
func DetectWalletType(address string) string { return address }
`,
			expectedCount: 0,
		},
		{
			name: "count accessor",
			code: `package service
type Service struct{ wallets []string }
func (s *Service) WalletCount() int { return len(s.wallets) }
`,
			expectedCount: 0,
		},
		{
			name: "service operation still requires context",
			code: `package service
type Service struct{}
func (s *Service) SyncWallet(address string) error { return nil }
`,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/service.go", "/src", []byte(tt.code), core.DefaultConfig())
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile("/src/service.go", []byte(tt.code))
			assert.NoError(t, err)
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount)
		})
	}
}

package typesafety

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestAnyInPublicContractRule(t *testing.T) {
	rule := NewAnyInPublicContractRule()

	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name: "exported method returns bare any with error",
			code: `package svc

func (s *DBAdminService) BulkApproveInvestments(ctx context.Context, ids []string) (any, error) {
	return nil, nil
}
`,
			wantCount: 1,
		},
		{
			name: "exported function returns map string any",
			code: `package svc

func GetStrategyPerformance(name string) (map[string]any, error) {
	return nil, nil
}
`,
			wantCount: 1,
		},
		{
			name: "typed response is fine",
			code: `package svc

func (s *DBAdminService) BulkApproveInvestments(ctx context.Context, ids []string) (*BulkApproveResponse, error) {
	return nil, nil
}
`,
			wantCount: 0,
		},
		{
			name: "unexported function is out of scope",
			code: `package svc

func decodePayload(raw []byte) (any, error) {
	return nil, nil
}
`,
			wantCount: 0,
		},
		{
			name: "comma-ok lookup contract is allowed",
			code: `package svc

func (r *Registry) GetSetting(key string) (any, bool) {
	return nil, false
}
`,
			wantCount: 0,
		},
		{
			name: "well-known stdlib contracts are excluded",
			code: `package svc

func (d *Decimal) Value() (driver.Value, error) {
	return nil, nil
}

func (d *Decimal) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (d *Decimal) Scan(value any) error {
	return nil
}
`,
			wantCount: 0,
		},
		{
			name: "exported struct field map string any",
			code: `package models

type CreateUserRequest struct {
	Email    string         ` + "`json:\"email\"`" + `
	Metadata map[string]any ` + "`json:\"metadata\"`" + `
}
`,
			wantCount: 1,
		},
		{
			name: "unexported struct is out of scope",
			code: `package models

type internalState struct {
	cache map[string]any
}
`,
			wantCount: 0,
		},
		{
			name: "interface method returning any",
			code: `package svc

type AdminService interface {
	BulkApprove(ctx context.Context, ids []string) (any, error)
}
`,
			wantCount: 1,
		},
		{
			name: "interface{} spelling is also caught",
			code: `package svc

func (s *Service) Export() (interface{}, error) {
	return nil, nil
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

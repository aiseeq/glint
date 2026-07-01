package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestConstructorNilReturnRule(t *testing.T) {
	rule := NewConstructorNilReturnRule()

	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name: "constructor returns nil on failed type assertion",
			code: `package repo

func NewCanonicalWalletRepository(userRepo interface{}) WalletRepository {
	repo, ok := userRepo.(*CanonicalUserRepository)
	if !ok {
		return nil
	}
	return &walletRepo{users: repo}
}
`,
			wantCount: 1,
		},
		{
			name: "constructor with error result is explicit",
			code: `package repo

func NewCanonicalWalletRepository(userRepo interface{}) (WalletRepository, error) {
	repo, ok := userRepo.(*CanonicalUserRepository)
	if !ok {
		return nil, fmt.Errorf("invalid user repository type: %T", userRepo)
	}
	return &walletRepo{users: repo}, nil
}
`,
			wantCount: 0,
		},
		{
			name: "constructor that never returns nil",
			code: `package svc

func NewService(cfg *Config) *Service {
	return &Service{cfg: cfg}
}
`,
			wantCount: 0,
		},
		{
			name: "comma-ok style constructor result is an explicit contract",
			code: `package svc

func NewParser(kind string) (Parser, bool) {
	if kind == "" {
		return nil, false
	}
	return &parser{}, true
}
`,
			wantCount: 0,
		},
		{
			name: "nil inside closure does not belong to constructor",
			code: `package svc

func NewService(cfg *Config) *Service {
	s := &Service{}
	s.resolve = func() *Item {
		return nil
	}
	return s
}
`,
			wantCount: 0,
		},
		{
			name: "method constructor on factory is out of scope",
			code: `package svc

func (f *Factory) NewIterator() *Iterator {
	if f.done {
		return nil
	}
	return &Iterator{}
}
`,
			wantCount: 0,
		},
		{
			name: "non-constructor function is out of scope",
			code: `package svc

func findUser(id string) *User {
	if id == "" {
		return nil
	}
	return lookup(id)
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

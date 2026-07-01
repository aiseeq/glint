package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestConstructorSwallowsNilDepRule(t *testing.T) {
	rule := NewConstructorSwallowsNilDepRule()

	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name: "constructor logs nil dependency and continues",
			code: `package auth

func NewPermissionManager(repo Repository) *PermissionManager {
	pm := &PermissionManager{repo: repo}
	if repo == nil {
		pm.logger.Error("Critical error: repository is nil, permission checks will fail")
	}
	return pm
}
`,
			wantCount: 1,
		},
		{
			name: "constructor returns error on nil dependency",
			code: `package auth

func NewPermissionManager(repo Repository) (*PermissionManager, error) {
	if repo == nil {
		return nil, fmt.Errorf("repository is required")
	}
	return &PermissionManager{repo: repo}, nil
}
`,
			wantCount: 0,
		},
		{
			name: "constructor panics on nil dependency",
			code: `package auth

func NewPermissionManager(repo Repository) *PermissionManager {
	if repo == nil {
		panic("repository is required")
	}
	return &PermissionManager{repo: repo}
}
`,
			wantCount: 0,
		},
		{
			name: "defaulting nil options is not a swallowed dependency",
			code: `package svc

func NewClient(opts *Options) *Client {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Client{opts: opts}
}
`,
			wantCount: 0,
		},
		{
			name: "debug-level logging of nil is not flagged",
			code: `package svc

func NewClient(cache Cache) *Client {
	if cache == nil {
		logger.Debug("cache disabled")
	}
	return &Client{cache: cache}
}
`,
			wantCount: 0,
		},
		{
			name: "log then return nil is constructor-nil-return territory",
			code: `package svc

func NewClient(db DB) *Client {
	if db == nil {
		logger.Error("db is nil")
		return nil
	}
	return &Client{db: db}
}
`,
			wantCount: 0,
		},
		{
			name: "or-chained nil checks with warn log",
			code: `package svc

func NewService(db DB, repo Repo) *Service {
	if db == nil || repo == nil {
		logger.Warn("NewService called with nil dependencies, running degraded")
	}
	return &Service{db: db, repo: repo}
}
`,
			wantCount: 1,
		},
		{
			name: "nil check of local variable is out of scope",
			code: `package svc

func NewService(cfg *Config) *Service {
	conn := dial(cfg)
	if conn == nil {
		logger.Error("dial failed")
	}
	return &Service{conn: conn}
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

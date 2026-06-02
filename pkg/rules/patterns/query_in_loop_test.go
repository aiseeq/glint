package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryInLoopRule_Metadata(t *testing.T) {
	rule := NewQueryInLoopRule()
	assert.Equal(t, "query-in-loop", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestQueryInLoopRule_Detection(t *testing.T) {
	rule := NewQueryInLoopRule()
	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "repo field call in range loop (N+1)",
			code: `package main
func ex(s *S, ids []string) {
	for _, id := range ids {
		s.repo.GetByID(id)
	}
}`,
			expectMatch: true,
		},
		{
			name: "db field call in for loop",
			code: `package main
func ex(r *R) {
	for i := 0; i < 10; i++ {
		r.db.QueryRowContext(nil, "x")
	}
}`,
			expectMatch: true,
		},
		{
			name: "bare repo var call in loop",
			code: `package main
func ex(groupRepo G, ids []string) {
	for _, id := range ids {
		groupRepo.GetUserGroupAssignment(id)
	}
}`,
			expectMatch: true,
		},
		{
			name: "non-data receiver (logger) not flagged",
			code: `package main
func ex(s *S, ids []string) {
	for _, id := range ids {
		s.logger.Info(id)
	}
}`,
			expectMatch: false,
		},
		{
			name: "data call outside loop not flagged",
			code: `package main
func ex(s *S, id string) {
	s.repo.GetByID(id)
	for i := 0; i < 3; i++ {
		_ = i
	}
}`,
			expectMatch: false,
		},
		{
			name: "repo call inside nested func literal not flagged",
			code: `package main
func ex(s *S, ids []string) {
	for _, id := range ids {
		go func() { s.repo.GetByID(id) }()
	}
}`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createQueryContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)
			if tt.expectMatch {
				require.NotEmpty(t, violations, "expected violation: %s", tt.name)
				assert.Equal(t, "query_in_loop", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "expected no violations: %s", tt.name)
			}
		})
	}
}

func TestQueryInLoopRule_TestFilesExcluded(t *testing.T) {
	rule := NewQueryInLoopRule()
	code := `package main
func ex(s *S, ids []string) {
	for _, id := range ids {
		s.repo.GetByID(id)
	}
}`
	ctx := createQueryContext(t, "service_test.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func createQueryContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   strings.Split(code, "\n"),
		Content: []byte(code),
	}
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile(path, []byte(code))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx.SetGoAST(fset, astFile)
	return ctx
}

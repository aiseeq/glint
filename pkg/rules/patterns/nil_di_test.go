package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNilDIRule_Metadata(t *testing.T) {
	rule := NewNilDIRule()

	assert.Equal(t, "nil-di", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestNilDIRule_Detection(t *testing.T) {
	rule := NewNilDIRule()

	tests := []struct {
		name       string
		code       string
		expectHits int
	}{
		{
			name: "nil logger to service - should detect",
			code: `package main

func main() {
	svc := NewMetricsService(cfg, nil)
}
`,
			expectHits: 1,
		},
		{
			name: "nil repo to handler - should detect",
			code: `package main

func main() {
	h := NewDepositHandler(db, logger, nil, cfg)
}
`,
			expectHits: 0, // nil is not in high-risk position for handler
		},
		{
			name: "nil logger to middleware - should detect",
			code: `package main

func main() {
	mw := NewSecurityMiddleware(nil, cfg)
}
`,
			expectHits: 1,
		},
		{
			name: "nil db to repository - should detect",
			code: `package main

func main() {
	repo := NewUserRepository(nil, logger)
}
`,
			expectHits: 1,
		},
		{
			name: "non-high-risk nil - should NOT detect",
			code: `package main

func main() {
	// nil for non-service/repo/logger parameter
	obj := NewSomething(cfg, nil, data)
}
`,
			expectHits: 0,
		},
		{
			name: "suppressed with comment - should NOT detect",
			code: `package main

func main() {
	// nil-di: safe - validator not needed for admin tokens
	svc := NewJWTService(cfg, nil)
}
`,
			expectHits: 0,
		},
		{
			name: "suppressed inline - should NOT detect",
			code: `package main

func main() {
	svc := NewService(cfg, nil) // nil-di: safe
}
`,
			expectHits: 0,
		},
		{
			name: "real world bug pattern - metrics service nil logger",
			code: `package main

func main() {
	canonicalService := canonical.NewCanonicalMetricsService(cfg, nil)
}
`,
			expectHits: 1,
		},
		{
			name: "multiple nil to service - detect high-risk only",
			code: `package main

func createServices() {
	svc := NewInvestmentService(cfg, repo, nil, userSvc, nil)
}
`,
			expectHits: 1, // only last nil (logger position)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createNilDIContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectHits > 0 {
				require.Len(t, violations, tt.expectHits, "Expected %d violations for: %s", tt.expectHits, tt.name)
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

func TestNilDIRule_SkipsTestFiles(t *testing.T) {
	rule := NewNilDIRule()

	code := `package main

func main() {
	svc := NewService(cfg, nil)
}
`
	// Test _test.go files
	ctx := createNilDIContext(t, "service_test.go", code)
	violations := rule.AnalyzeFile(ctx)
	assert.Empty(t, violations, "Test files should be excluded")

	// Test test.go files (benchmarks)
	ctx = createNilDIContext(t, "test.go", code)
	violations = rule.AnalyzeFile(ctx)
	assert.Empty(t, violations, "test.go files should be excluded")
}

func TestNilDIRule_HighRiskParams(t *testing.T) {
	rule := NewNilDIRule()

	tests := []struct {
		paramHint string
		isHighRisk bool
	}{
		{"logger", true},
		{"log", true},
		{"service", true},
		{"svc", true},
		{"repo", true},
		{"repository", true},
		{"storage", true},
		{"store", true},
		{"handler", true},
		{"client", true},
		{"db", true},
		{"database", true},
		{"cache", true},
		{"metrics", true},
		{"validator", true},
		{"config", false},
		{"options", false},
		{"settings", false},
		{"dependency", false},
		{"data", false},
	}

	for _, tt := range tests {
		t.Run(tt.paramHint, func(t *testing.T) {
			result := rule.isHighRiskParam(tt.paramHint)
			assert.Equal(t, tt.isHighRisk, result, "Expected isHighRisk=%v for %s", tt.isHighRisk, tt.paramHint)
		})
	}
}

// Helper function
func createNilDIContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitNilDILines(code),
		Content: []byte(code),
	}

	if len(path) > 3 && path[len(path)-3:] == ".go" {
		parser := core.NewParser()
		fset, ast, err := parser.ParseGoFile(path, []byte(code))
		if err != nil {
			t.Fatalf("Failed to parse Go code: %v", err)
		}
		ctx.SetGoAST(fset, ast)
	}

	return ctx
}

func splitNilDILines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

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
			name: "constructor with nil arg - should detect",
			code: `package main

func main() {
	svc := NewService(db, nil)
}
`,
			expectHits: 1,
		},
		{
			name: "constructor with multiple nil args - should detect all",
			code: `package main

func main() {
	svc := NewService(nil, nil, nil)
}
`,
			expectHits: 3,
		},
		{
			name: "constructor with no nil args - should not detect",
			code: `package main

func main() {
	svc := NewService(db, logger)
}
`,
			expectHits: 0,
		},
		{
			name: "non-constructor with nil - should not detect",
			code: `package main

func main() {
	ProcessData(nil)
}
`,
			expectHits: 0,
		},
		{
			name: "package-qualified constructor with nil",
			code: `package main

func main() {
	svc := mypackage.NewService(nil)
}
`,
			expectHits: 1,
		},
		{
			name: "real world example - crypto2b bug pattern",
			code: `package main

func createServices() {
	handler := depositService.NewIntegrationOnlyDepositHandler(db, logger, nil, cfg, nil, nil, nil)
}
`,
			expectHits: 4,
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

func TestNilDIRule_TestFilesExcluded(t *testing.T) {
	rule := NewNilDIRule()

	code := `package main

func main() {
	svc := NewService(nil) // This should be allowed in test files
}
`
	ctx := createNilDIContext(t, "service_test.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
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

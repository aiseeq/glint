package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTechDebtRule_Metadata(t *testing.T) {
	rule := NewTechDebtRule()

	assert.Equal(t, "tech-debt", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestTechDebtRule_LegacyMarkers(t *testing.T) {
	rule := NewTechDebtRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name:        "legacy code marker",
			code:        "// legacy code - needs migration",
			expectMatch: true,
		},
		{
			name:        "deprecated code",
			code:        "// deprecated code, will be removed",
			expectMatch: true,
		},
		{
			name:        "old code marker",
			code:        "// old code from v1",
			expectMatch: true,
		},
		{
			name:        "remove legacy",
			code:        "// TODO: remove legacy implementation",
			expectMatch: true,
		},
		{
			name:        "normal comment",
			code:        "// This function handles user login",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createTechDebtContext(t, "backend/service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
				assert.Equal(t, "legacy_marker", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}

func TestTechDebtRule_FakeRefactoring(t *testing.T) {
	rule := NewTechDebtRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name:        "wrapper instead of removal",
			code:        "// wrapper delegates instead of removal",
			expectMatch: true,
		},
		{
			name:        "russian fake refactoring",
			code:        "// делегирует вместо удаления",
			expectMatch: true,
		},
		{
			name:        "normal delegation comment",
			code:        "// delegates to the service layer",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createTechDebtContext(t, "backend/service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
				assert.Equal(t, "fake_refactoring", violations[0].Context["pattern"])
				assert.Equal(t, core.SeverityHigh, violations[0].Severity)
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}

func TestTechDebtRule_TemporarySolutions(t *testing.T) {
	rule := NewTechDebtRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name:        "temporary fix",
			code:        "// temporary fix for issue #123",
			expectMatch: true,
		},
		{
			name:        "temp fix",
			code:        "// temp fix until next release",
			expectMatch: true,
		},
		{
			name:        "quick fix",
			code:        "// quick fix for production",
			expectMatch: true,
		},
		{
			name:        "workaround",
			code:        "// workaround for library bug",
			expectMatch: true,
		},
		{
			name:        "hotfix",
			code:        "// hotfix for critical issue",
			expectMatch: true,
		},
		{
			name:        "russian temporary",
			code:        "// временное решение",
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createTechDebtContext(t, "backend/service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
				assert.Equal(t, "temporary_solution", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}

func TestTechDebtRule_BrokenFeature(t *testing.T) {
	rule := NewTechDebtRule()

	code := "// broken - doesn't work with new API"
	ctx := createTechDebtContext(t, "backend/service.go", code)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations)
	assert.Equal(t, "broken_feature", violations[0].Context["pattern"])
	assert.Equal(t, core.SeverityHigh, violations[0].Severity)
}

func TestTechDebtRule_NeedsRefactoring(t *testing.T) {
	rule := NewTechDebtRule()

	tests := []struct {
		code        string
		expectMatch bool
	}{
		{"// needs refactoring", true},
		{"// should be refactored", true},
		{"// refactor this later", true},
		{"// the code is clean", false},
	}

	for _, tt := range tests {
		ctx := createTechDebtContext(t, "backend/service.go", tt.code)
		violations := rule.AnalyzeFile(ctx)

		if tt.expectMatch {
			require.NotEmpty(t, violations, "Expected violation for: %s", tt.code)
		} else {
			assert.Empty(t, violations)
		}
	}
}

func TestTechDebtRule_DeadCode(t *testing.T) {
	rule := NewTechDebtRule()

	code := "// dead code - not used anymore"
	ctx := createTechDebtContext(t, "backend/service.go", code)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations)
	assert.Equal(t, "dead_code_marker", violations[0].Context["pattern"])
}

func TestTechDebtRule_TestFilesExcluded(t *testing.T) {
	rule := NewTechDebtRule()

	code := "// legacy code that needs migration"
	ctx := createTechDebtContext(t, "backend/service_test.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

func TestTechDebtRule_VendorExcluded(t *testing.T) {
	rule := NewTechDebtRule()

	code := "// legacy code"
	ctx := createTechDebtContext(t, "vendor/lib/file.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Vendor files should be excluded")
}

func TestTechDebtRule_NonCommentLinesSkipped(t *testing.T) {
	rule := NewTechDebtRule()

	code := `package main

func legacy() {
	// This is fine
	x := "legacy code"
}
`
	ctx := &core.FileContext{
		Path:    "/backend/service.go",
		RelPath: "backend/service.go",
		Lines:   splitLines(code),
		Content: []byte(code),
	}
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Non-comment lines should not trigger violations")
}

// Helper functions
func createTechDebtContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	return &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   []string{code},
		Content: []byte(code),
	}
}

func splitLines(s string) []string {
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

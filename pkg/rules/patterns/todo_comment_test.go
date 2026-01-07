package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestTodoCommentRule(t *testing.T) {
	rule := NewTodoCommentRule()

	tests := []struct {
		name           string
		code           string
		expectedCount  int
		expectedKeyword string
	}{
		{
			name:           "TODO with colon",
			code:           "// TODO: implement this feature",
			expectedCount:  1,
			expectedKeyword: "TODO",
		},
		{
			name:           "FIXME with colon",
			code:           "// FIXME: broken logic here",
			expectedCount:  1,
			expectedKeyword: "FIXME",
		},
		{
			name:           "HACK comment",
			code:           "// HACK: workaround for bug",
			expectedCount:  1,
			expectedKeyword: "HACK",
		},
		{
			name:           "TODO with author",
			code:           "// TODO(john): review this",
			expectedCount:  1,
			expectedKeyword: "TODO",
		},
		{
			name:           "TODO with dash",
			code:           "// TODO - fix later",
			expectedCount:  1,
			expectedKeyword: "TODO",
		},
		{
			name:           "Not actionable - description",
			code:           "// This function detects TODO comments",
			expectedCount:  0,
		},
		{
			name:           "Not actionable - in middle",
			code:           "// The TODO pattern is matched here",
			expectedCount:  0,
		},
		{
			name:           "Not a comment",
			code:           "var TODO = \"something\"",
			expectedCount:  0,
		},
		{
			name:           "Block comment TODO",
			code:           "/* TODO: implement */",
			expectedCount:  1,
			expectedKeyword: "TODO",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/test/file.go", "/test", []byte(tt.code), core.DefaultConfig())
			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.expectedCount)
			if tt.expectedCount > 0 && len(violations) > 0 {
				assert.Contains(t, violations[0].Message, tt.expectedKeyword)
			}
		})
	}
}

func TestTodoCommentSeverity(t *testing.T) {
	rule := NewTodoCommentRule()

	tests := []struct {
		code     string
		severity core.Severity
	}{
		{"// TODO: low priority", core.SeverityLow},
		{"// FIXME: medium priority", core.SeverityMedium},
		{"// HACK: medium priority", core.SeverityMedium},
		{"// XXX: low priority", core.SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			ctx := core.NewFileContext("/test/file.go", "/test", []byte(tt.code), core.DefaultConfig())
			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, 1)
			assert.Equal(t, tt.severity, violations[0].Severity)
		})
	}
}

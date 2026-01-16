package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
)

func TestErrorLengthCheckRule(t *testing.T) {
	rule := NewErrorLengthCheckRule()

	tests := []struct {
		name      string
		code      string
		wantCount int
		wantMsg   string
	}{
		{
			name: "len(errMsg) range check - critical violation",
			code: `package test
func isDuplicateKeyError(err error) bool {
	errMsg := err.Error()
	return len(errMsg) >= 30 && len(errMsg) <= 300
}`,
			wantCount: 1,
			wantMsg:   "error message length",
		},
		{
			name: "len(err.Error()) comparison",
			code: `package test
func checkError(err error) bool {
	if len(err.Error()) > 100 {
		return true
	}
	return false
}`,
			wantCount: 1,
			wantMsg:   "message length",
		},
		{
			name: "complex if with length range",
			code: `package test
func isForeignKeyError(err error) bool {
	errMsg := err.Error()
	if len(errMsg) >= 40 && len(errMsg) <= 400 {
		return true
	}
	return false
}`,
			wantCount: 1,
			wantMsg:   "length range",
		},
		{
			name: "valid - no error length check",
			code: `package test
import "errors"
func isDuplicateKeyError(err error) bool {
	return errors.Is(err, ErrDuplicateKey)
}`,
			wantCount: 0,
		},
		{
			name: "valid - non-error length check",
			code: `package test
func checkString(s string) bool {
	return len(s) >= 10
}`,
			wantCount: 0,
		},
		{
			name: "valid - using pq.Error",
			code: `package test
import "github.com/lib/pq"
func isDuplicateKeyError(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := core.NewParser()
			ctx := core.NewFileContext("/src/test.go", "/src", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := parser.ParseGoFile("/src/test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantCount, "Code:\n%s", tt.code)
		})
	}
}

package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// Репро с projectD (models.NewArticleWithRequestDate): значение под success-only
// guard'ом, но сразу после guard'а нулевое состояние проверяется и получает
// документированный фолбек — провал парсинга отличим от «данных не было»,
// его судьба решена в коде рядом. Это не потеря ошибки.
func TestErrorMaskingRule_ZeroStateHandledAfterGuard(t *testing.T) {
	rule := NewErrorMaskingRule()

	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "IsZero fallback after guard - not flagged",
			code: `package main

import "time"

func seenDate(raw string, requestDate time.Time) time.Time {
	var seen time.Time
	if raw != "" {
		parsed, err := time.Parse("20060102150405", raw)
		if err == nil {
			seen = parsed
		}
	}
	if seen.IsZero() {
		seen = requestDate
	}
	return seen
}`,
			wantViolations: 0,
		},
		{
			name: "empty-string fallback after guard - not flagged",
			code: `package main

import "os"

func hostname() string {
	var name string
	value, err := os.Hostname()
	if err == nil {
		name = value
	}
	if name == "" {
		name = "localhost"
	}
	return name
}`,
			wantViolations: 0,
		},
		{
			name: "no fallback after guard - still flagged",
			code: `package main

import "time"

func seenDate(raw string) time.Time {
	var seen time.Time
	parsed, err := time.Parse("20060102150405", raw)
	if err == nil {
		seen = parsed
	}
	return seen
}`,
			wantViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := rulestest.GoFile(t, "dates.go", tt.code)
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantViolations {
				t.Errorf("got %d violations, want %d", len(violations), tt.wantViolations)
				for _, v := range violations {
					t.Logf("  violation: %s at line %d", v.Message, v.Line)
				}
			}
		})
	}
}

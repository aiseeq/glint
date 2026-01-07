package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewViolation(t *testing.T) {
	v := NewViolation("test-rule", "test-category", "test.go", 10, SeverityHigh, "test message")

	assert.Equal(t, "test-rule", v.Rule)
	assert.Equal(t, "test-category", v.Category)
	assert.Equal(t, "test.go", v.File)
	assert.Equal(t, 10, v.Line)
	assert.Equal(t, SeverityHigh, v.Severity)
	assert.Equal(t, "test message", v.Message)
}

func TestViolationWithSuggestion(t *testing.T) {
	v := NewViolation("test-rule", "test-category", "test.go", 10, SeverityHigh, "test message")
	result := v.WithSuggestion("fix it")

	assert.Equal(t, "fix it", result.Suggestion)
	assert.Same(t, v, result) // Should return same pointer
}

func TestViolationWithCode(t *testing.T) {
	v := NewViolation("test-rule", "test-category", "test.go", 10, SeverityHigh, "test message")
	result := v.WithCode("var x = 1")

	assert.Equal(t, "var x = 1", result.Code)
	assert.Same(t, v, result)
}

func TestViolationWithContext(t *testing.T) {
	v := NewViolation("test-rule", "test-category", "test.go", 10, SeverityHigh, "test message")
	result := v.WithContext("key", "value")

	assert.Equal(t, "value", result.Context["key"])
	assert.Same(t, v, result)
}

func TestViolationListBySeverity(t *testing.T) {
	list := ViolationList{
		NewViolation("r1", "c1", "f1.go", 1, SeverityLow, "low"),
		NewViolation("r2", "c1", "f2.go", 2, SeverityMedium, "medium"),
		NewViolation("r3", "c1", "f3.go", 3, SeverityHigh, "high"),
		NewViolation("r4", "c1", "f4.go", 4, SeverityCritical, "critical"),
	}

	// Filter by medium or higher
	filtered := list.BySeverity(SeverityMedium)
	assert.Len(t, filtered, 3)

	// Filter by high or higher
	filtered = list.BySeverity(SeverityHigh)
	assert.Len(t, filtered, 2)

	// Filter by critical only
	filtered = list.BySeverity(SeverityCritical)
	assert.Len(t, filtered, 1)
}

func TestViolationListHasCritical(t *testing.T) {
	listWithCritical := ViolationList{
		NewViolation("r1", "c1", "f1.go", 1, SeverityLow, "low"),
		NewViolation("r2", "c1", "f2.go", 2, SeverityCritical, "critical"),
	}
	assert.True(t, listWithCritical.HasCritical())

	listWithoutCritical := ViolationList{
		NewViolation("r1", "c1", "f1.go", 1, SeverityLow, "low"),
		NewViolation("r2", "c1", "f2.go", 2, SeverityHigh, "high"),
	}
	assert.False(t, listWithoutCritical.HasCritical())
}

func TestViolationListCountBySeverity(t *testing.T) {
	list := ViolationList{
		NewViolation("r1", "c1", "f1.go", 1, SeverityLow, "low"),
		NewViolation("r2", "c1", "f2.go", 2, SeverityLow, "low"),
		NewViolation("r3", "c1", "f3.go", 3, SeverityMedium, "medium"),
		NewViolation("r4", "c1", "f4.go", 4, SeverityHigh, "high"),
	}

	counts := list.CountBySeverity()
	assert.Equal(t, 2, counts[SeverityLow])
	assert.Equal(t, 1, counts[SeverityMedium])
	assert.Equal(t, 1, counts[SeverityHigh])
	assert.Equal(t, 0, counts[SeverityCritical])
}

func TestViolationListCountByRule(t *testing.T) {
	list := ViolationList{
		NewViolation("rule-a", "c1", "f1.go", 1, SeverityLow, "msg"),
		NewViolation("rule-a", "c1", "f2.go", 2, SeverityLow, "msg"),
		NewViolation("rule-b", "c1", "f3.go", 3, SeverityMedium, "msg"),
	}

	counts := list.CountByRule()
	assert.Equal(t, 2, counts["rule-a"])
	assert.Equal(t, 1, counts["rule-b"])
}

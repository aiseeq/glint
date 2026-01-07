package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestNewBaseRule(t *testing.T) {
	rule := NewBaseRule("test-rule", "test-category", "Test description", core.SeverityHigh)

	assert.Equal(t, "test-rule", rule.Name())
	assert.Equal(t, "test-category", rule.Category())
	assert.Equal(t, "Test description", rule.Description())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestBaseRuleConfigure(t *testing.T) {
	rule := NewBaseRule("test", "cat", "desc", core.SeverityMedium)

	settings := map[string]interface{}{
		"threshold": 10,
		"enabled":   true,
	}

	err := rule.Configure(settings)
	assert.NoError(t, err)

	val, ok := rule.GetSetting("threshold")
	assert.True(t, ok)
	assert.Equal(t, 10, val)
}

func TestBaseRuleGetStringSetting(t *testing.T) {
	rule := NewBaseRule("test", "cat", "desc", core.SeverityMedium)
	rule.Configure(map[string]interface{}{
		"name": "value",
	})

	assert.Equal(t, "value", rule.GetStringSetting("name", "default"))
	assert.Equal(t, "default", rule.GetStringSetting("missing", "default"))
}

func TestBaseRuleGetIntSetting(t *testing.T) {
	rule := NewBaseRule("test", "cat", "desc", core.SeverityMedium)
	rule.Configure(map[string]interface{}{
		"count":   42,
		"float":   3.14,
		"invalid": "not a number",
	})

	assert.Equal(t, 42, rule.GetIntSetting("count", 0))
	assert.Equal(t, 3, rule.GetIntSetting("float", 0)) // float64 converted to int
	assert.Equal(t, 0, rule.GetIntSetting("invalid", 0))
	assert.Equal(t, 99, rule.GetIntSetting("missing", 99))
}

func TestBaseRuleGetBoolSetting(t *testing.T) {
	rule := NewBaseRule("test", "cat", "desc", core.SeverityMedium)
	rule.Configure(map[string]interface{}{
		"enabled":  true,
		"disabled": false,
		"invalid":  "yes",
	})

	assert.True(t, rule.GetBoolSetting("enabled", false))
	assert.False(t, rule.GetBoolSetting("disabled", true))
	assert.True(t, rule.GetBoolSetting("invalid", true)) // defaults because not bool
	assert.False(t, rule.GetBoolSetting("missing", false))
}

func TestBaseRuleGetFloat64Setting(t *testing.T) {
	rule := NewBaseRule("test", "cat", "desc", core.SeverityMedium)
	rule.Configure(map[string]interface{}{
		"ratio":   0.75,
		"integer": 10,
	})

	assert.Equal(t, 0.75, rule.GetFloat64Setting("ratio", 0.0))
	assert.Equal(t, 10.0, rule.GetFloat64Setting("integer", 0.0))
	assert.Equal(t, 1.5, rule.GetFloat64Setting("missing", 1.5))
}

func TestBaseRuleCreateViolation(t *testing.T) {
	rule := NewBaseRule("my-rule", "my-category", "desc", core.SeverityHigh)

	v := rule.CreateViolation("test.go", 42, "Something is wrong")

	assert.Equal(t, "my-rule", v.Rule)
	assert.Equal(t, "my-category", v.Category)
	assert.Equal(t, "test.go", v.File)
	assert.Equal(t, 42, v.Line)
	assert.Equal(t, core.SeverityHigh, v.Severity)
	assert.Equal(t, "Something is wrong", v.Message)
}

// MockRule for testing that implements Rule interface
type MockRule struct {
	*BaseRule
	violations []*core.Violation
}

func NewMockRule(name string) *MockRule {
	return &MockRule{
		BaseRule:   NewBaseRule(name, "mock", "Mock rule", core.SeverityMedium),
		violations: nil,
	}
}

func (r *MockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.violations
}

func (r *MockRule) SetViolations(v []*core.Violation) {
	r.violations = v
}

func TestGetRuleInfo(t *testing.T) {
	rule := NewMockRule("info-rule")
	rule.BaseRule = NewBaseRule("info-rule", "info-category", "Info description", core.SeverityCritical)

	info := GetRuleInfo(rule)

	assert.Equal(t, "info-rule", info.Name)
	assert.Equal(t, "info-category", info.Category)
	assert.Equal(t, "Info description", info.Description)
	assert.Equal(t, core.SeverityCritical, info.Severity)
	assert.False(t, info.HasAutoFix)
}

// MockFixerRule implements both Rule and Fixer
type MockFixerRule struct {
	*BaseRule
}

func NewMockFixerRule(name string) *MockFixerRule {
	return &MockFixerRule{
		BaseRule: NewBaseRule(name, "mock", "Mock fixer rule", core.SeverityMedium),
	}
}

func (r *MockFixerRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return nil
}

func (r *MockFixerRule) Fix(ctx *core.FileContext, violation *core.Violation) (*Fix, error) {
	return &Fix{
		File:    violation.File,
		OldText: "old",
		NewText: "new",
	}, nil
}

func TestGetRuleInfoWithFixer(t *testing.T) {
	rule := NewMockFixerRule("fixer-rule")
	info := GetRuleInfo(rule)

	assert.True(t, info.HasAutoFix)
}

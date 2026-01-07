package rules

import (
	"github.com/aiseeq/glint/pkg/core"
)

// Rule is the interface that all rules must implement
type Rule interface {
	// Metadata
	Name() string
	Category() string
	Description() string
	DefaultSeverity() core.Severity

	// Configuration
	Configure(settings map[string]interface{}) error

	// Analysis - rules implement the ones they need
	AnalyzeFile(ctx *core.FileContext) []*core.Violation
}

// BaseRule provides common functionality for rules
type BaseRule struct {
	name            string
	category        string
	description     string
	defaultSeverity core.Severity
	settings        map[string]interface{}
}

// NewBaseRule creates a new base rule
func NewBaseRule(name, category, description string, severity core.Severity) *BaseRule {
	return &BaseRule{
		name:            name,
		category:        category,
		description:     description,
		defaultSeverity: severity,
		settings:        make(map[string]interface{}),
	}
}

// Name returns the rule name
func (r *BaseRule) Name() string {
	return r.name
}

// Category returns the rule category
func (r *BaseRule) Category() string {
	return r.category
}

// Description returns the rule description
func (r *BaseRule) Description() string {
	return r.description
}

// DefaultSeverity returns the default severity
func (r *BaseRule) DefaultSeverity() core.Severity {
	return r.defaultSeverity
}

// Configure sets rule settings
func (r *BaseRule) Configure(settings map[string]interface{}) error {
	r.settings = settings
	return nil
}

// GetSetting retrieves a setting value
func (r *BaseRule) GetSetting(key string) (interface{}, bool) {
	val, ok := r.settings[key]
	return val, ok
}

// GetStringSetting retrieves a string setting
func (r *BaseRule) GetStringSetting(key, defaultVal string) string {
	if val, ok := r.settings[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return defaultVal
}

// GetIntSetting retrieves an int setting
func (r *BaseRule) GetIntSetting(key string, defaultVal int) int {
	if val, ok := r.settings[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultVal
}

// GetBoolSetting retrieves a bool setting
func (r *BaseRule) GetBoolSetting(key string, defaultVal bool) bool {
	if val, ok := r.settings[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultVal
}

// GetFloat64Setting retrieves a float64 setting
func (r *BaseRule) GetFloat64Setting(key string, defaultVal float64) float64 {
	if val, ok := r.settings[key]; ok {
		switch v := val.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		}
	}
	return defaultVal
}

// CreateViolation creates a new violation for this rule
func (r *BaseRule) CreateViolation(file string, line int, message string) *core.Violation {
	return core.NewViolation(r.name, r.category, file, line, r.defaultSeverity, message)
}

// RuleInfo contains metadata about a rule for display purposes
type RuleInfo struct {
	Name        string
	Category    string
	Description string
	Severity    core.Severity
	HasAutoFix  bool
}

// GetRuleInfo extracts info from a rule
func GetRuleInfo(r Rule) RuleInfo {
	info := RuleInfo{
		Name:        r.Name(),
		Category:    r.Category(),
		Description: r.Description(),
		Severity:    r.DefaultSeverity(),
	}

	// Check if rule supports auto-fix
	if _, ok := r.(Fixer); ok {
		info.HasAutoFix = true
	}

	return info
}

// Fixer is an optional interface for rules that can auto-fix issues
type Fixer interface {
	Rule
	Fix(ctx *core.FileContext, violation *core.Violation) (*Fix, error)
}

// Fix represents an auto-fix for a violation
type Fix struct {
	File        string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	OldText     string
	NewText     string
}

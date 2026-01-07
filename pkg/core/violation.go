package core

import (
	"fmt"
	"path/filepath"
)

// Violation represents a single issue found by a rule
type Violation struct {
	// Rule identification
	Rule     string // Rule name (e.g., "error_masking")
	Category string // Category name (e.g., "patterns")

	// Location
	File    string // Absolute or relative file path
	Line    int    // Line number (1-based)
	Column  int    // Column number (1-based, 0 = unknown)
	EndLine int    // End line for multi-line issues (0 = single line)

	// Severity
	Severity Severity

	// Description
	Message    string // What's wrong
	Suggestion string // How to fix it

	// Context
	Code    string                 // The offending code snippet
	Context map[string]any // Additional metadata
}

// NewViolation creates a new violation with required fields
func NewViolation(rule, category, file string, line int, severity Severity, message string) *Violation {
	return &Violation{
		Rule:     rule,
		Category: category,
		File:     file,
		Line:     line,
		Severity: severity,
		Message:  message,
		Context:  make(map[string]any),
	}
}

// WithSuggestion adds a suggestion to the violation
func (v *Violation) WithSuggestion(suggestion string) *Violation {
	v.Suggestion = suggestion
	return v
}

// WithCode adds the code snippet to the violation
func (v *Violation) WithCode(code string) *Violation {
	v.Code = code
	return v
}

// WithColumn adds column information
func (v *Violation) WithColumn(col int) *Violation {
	v.Column = col
	return v
}

// WithEndLine marks this as a multi-line violation
func (v *Violation) WithEndLine(endLine int) *Violation {
	v.EndLine = endLine
	return v
}

// WithContext adds context metadata
func (v *Violation) WithContext(key string, value any) *Violation {
	if v.Context == nil {
		v.Context = make(map[string]any)
	}
	v.Context[key] = value
	return v
}

// Location returns a formatted location string (file:line or file:line:col)
func (v *Violation) Location() string {
	if v.Column > 0 {
		return fmt.Sprintf("%s:%d:%d", v.File, v.Line, v.Column)
	}
	return fmt.Sprintf("%s:%d", v.File, v.Line)
}

// RelativeFile returns the file path relative to the given root
func (v *Violation) RelativeFile(root string) string {
	rel, err := filepath.Rel(root, v.File)
	if err != nil {
		return v.File
	}
	return rel
}

// String returns a human-readable representation
func (v *Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s (%s)", v.Severity.Label(), v.Location(), v.Message, v.Rule)
}

// ViolationList is a slice of violations with helper methods
type ViolationList []*Violation

// BySeverity returns violations filtered by minimum severity
func (vl ViolationList) BySeverity(minSeverity Severity) ViolationList {
	result := make(ViolationList, 0, len(vl))
	for _, v := range vl {
		if v.Severity.IsAtLeast(minSeverity) {
			result = append(result, v)
		}
	}
	return result
}

// ByCategory returns violations filtered by category
func (vl ViolationList) ByCategory(category string) ViolationList {
	result := make(ViolationList, 0)
	for _, v := range vl {
		if v.Category == category {
			result = append(result, v)
		}
	}
	return result
}

// ByRule returns violations filtered by rule name
func (vl ViolationList) ByRule(rule string) ViolationList {
	result := make(ViolationList, 0)
	for _, v := range vl {
		if v.Rule == rule {
			result = append(result, v)
		}
	}
	return result
}

// CountBySeverity returns a map of severity to count
func (vl ViolationList) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int)
	for _, v := range vl {
		counts[v.Severity]++
	}
	return counts
}

// CountByCategory returns a map of category to count
func (vl ViolationList) CountByCategory() map[string]int {
	counts := make(map[string]int)
	for _, v := range vl {
		counts[v.Category]++
	}
	return counts
}

// CountByRule returns a map of rule to count
func (vl ViolationList) CountByRule() map[string]int {
	counts := make(map[string]int)
	for _, v := range vl {
		counts[v.Rule]++
	}
	return counts
}

// HasCritical returns true if there's at least one critical violation
func (vl ViolationList) HasCritical() bool {
	for _, v := range vl {
		if v.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

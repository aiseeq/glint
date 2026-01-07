package patterns

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDeprecatedIoutilRule())
}

// DeprecatedIoutilRule detects usage of deprecated io/ioutil package
type DeprecatedIoutilRule struct {
	*rules.BaseRule
}

// NewDeprecatedIoutilRule creates the rule
func NewDeprecatedIoutilRule() *DeprecatedIoutilRule {
	return &DeprecatedIoutilRule{
		BaseRule: rules.NewBaseRule(
			"deprecated-ioutil",
			"patterns",
			"Detects deprecated io/ioutil package usage (use io and os packages instead)",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for io/ioutil usage
func (r *DeprecatedIoutilRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() {
		return nil
	}

	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		// Check for import of io/ioutil
		if strings.Contains(line, `"io/ioutil"`) {
			v := r.CreateViolation(ctx.RelPath, lineNum+1, "io/ioutil is deprecated since Go 1.16")
			v.WithCode(strings.TrimSpace(line))
			v.WithSuggestion("Use io.ReadAll, os.ReadFile, os.WriteFile instead")
			violations = append(violations, v)
			continue
		}

		// Check for ioutil.* function calls
		if strings.Contains(line, "ioutil.") {
			// Skip if inside string literal
			if isInsideString(line, "ioutil.") {
				continue
			}

			// Determine specific replacement
			suggestion := r.getSuggestion(line)
			v := r.CreateViolation(ctx.RelPath, lineNum+1, "ioutil functions are deprecated")
			v.WithCode(strings.TrimSpace(line))
			v.WithSuggestion(suggestion)
			violations = append(violations, v)
		}
	}

	return violations
}

// isInsideString checks if a substring appears inside a string literal
func isInsideString(line, substr string) bool {
	idx := strings.Index(line, substr)
	if idx < 0 {
		return false
	}

	// Count quotes before the substring
	beforeSubstr := line[:idx]
	quoteCount := strings.Count(beforeSubstr, `"`)

	// If odd number of quotes, we're inside a string
	return quoteCount%2 == 1
}

func (r *DeprecatedIoutilRule) getSuggestion(line string) string {
	switch {
	case strings.Contains(line, "ioutil.ReadAll"):
		return "Replace with io.ReadAll"
	case strings.Contains(line, "ioutil.ReadFile"):
		return "Replace with os.ReadFile"
	case strings.Contains(line, "ioutil.WriteFile"):
		return "Replace with os.WriteFile"
	case strings.Contains(line, "ioutil.ReadDir"):
		return "Replace with os.ReadDir"
	case strings.Contains(line, "ioutil.TempDir"):
		return "Replace with os.MkdirTemp"
	case strings.Contains(line, "ioutil.TempFile"):
		return "Replace with os.CreateTemp"
	case strings.Contains(line, "ioutil.NopCloser"):
		return "Replace with io.NopCloser"
	case strings.Contains(line, "ioutil.Discard"):
		return "Replace with io.Discard"
	default:
		return "Replace with equivalent functions from io or os packages"
	}
}

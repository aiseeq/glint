package typesafety

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewInterfaceAnyRule())
}

// InterfaceAnyRule detects interface{} usage that should be replaced with 'any'
type InterfaceAnyRule struct {
	*rules.BaseRule
	patterns map[string]*regexp.Regexp
}

// NewInterfaceAnyRule creates the rule
func NewInterfaceAnyRule() *InterfaceAnyRule {
	return &InterfaceAnyRule{
		BaseRule: rules.NewBaseRule(
			"interface-any",
			"typesafety",
			"Detects interface{} that should be replaced with 'any' (Go 1.18+)",
			core.SeverityMedium,
		),
		patterns: map[string]*regexp.Regexp{
			"interface{}":            regexp.MustCompile(`interface\{\}`),
			"map[string]interface{}": regexp.MustCompile(`map\[string\]interface\{\}`),
			"[]interface{}":          regexp.MustCompile(`\[\]interface\{\}`),
		},
	}
}

// AnalyzeFile checks for interface{} usage
func (r *InterfaceAnyRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() {
		return nil
	}

	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Skip regex patterns
		if strings.Contains(line, "regexp.") && strings.Contains(line, `interface\{\}`) {
			continue
		}

		// Check each pattern
		for patternName, pattern := range r.patterns {
			if pattern.MatchString(line) {
				// Skip if inside string literal
				if strings.Contains(line, `"`) {
					matchStr := getMatchString(patternName)
					if isInsideString(line, matchStr) {
						continue
					}
				}

				// Check for allowed exceptions
				if r.isAllowedException(line, ctx) {
					continue
				}

				v := r.CreateViolation(ctx.RelPath, lineNum+1, r.getMessage(patternName))
				v.WithCode(trimmed)
				v.WithSuggestion(r.getSuggestion(patternName))
				violations = append(violations, v)
				break // One violation per line
			}
		}
	}

	return violations
}

func (r *InterfaceAnyRule) isAllowedException(line string, ctx *core.FileContext) bool {
	// Test files: allow map[string]interface{} for flexible test data
	if ctx.IsTestFile() && strings.Contains(line, "map[string]interface{}") {
		return true
	}

	// JWT library callback signature
	if strings.Contains(line, "func(token *jwt.Token) (interface{}, error)") {
		return true
	}

	// JSON unmarshaling may require interface{}
	if strings.Contains(line, "json.Unmarshal") && strings.Contains(line, "interface{}") {
		return true
	}

	// Check if 'any' is already used (Go 1.18+ replacement)
	// This catches cases like: var x any = interface{}(val)
	if isUsingAny(line) {
		return true
	}

	return false
}

func isUsingAny(line string) bool {
	// Check for 'any' keyword usage patterns
	anyPatterns := []string{
		" any ", " any,", " any)", " any}",
		"]any ", "]any,", "]any)", "]any}",
		" any`", "]any`", "\tany ",
	}

	for _, p := range anyPatterns {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

func getMatchString(patternName string) string {
	switch patternName {
	case "map[string]interface{}":
		return "map[string]interface{}"
	case "[]interface{}":
		return "[]interface{}"
	default:
		return "interface{}"
	}
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
	// (Simplified check - doesn't handle escaped quotes perfectly)
	return quoteCount%2 == 1
}

func (r *InterfaceAnyRule) getMessage(patternName string) string {
	switch patternName {
	case "interface{}":
		return "Use 'any' instead of 'interface{}' (Go 1.18+)"
	case "map[string]interface{}":
		return "Use 'map[string]any' instead of 'map[string]interface{}' (Go 1.18+)"
	case "[]interface{}":
		return "Use '[]any' instead of '[]interface{}' (Go 1.18+)"
	default:
		return "Use 'any' instead of 'interface{}' (Go 1.18+)"
	}
}

func (r *InterfaceAnyRule) getSuggestion(patternName string) string {
	switch patternName {
	case "interface{}":
		return "Replace with 'any' type alias"
	case "map[string]interface{}":
		return "Replace with 'map[string]any' or define a typed struct"
	case "[]interface{}":
		return "Replace with '[]any' or use generics for type safety"
	default:
		return "Replace with 'any' type alias"
	}
}

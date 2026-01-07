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
		if v := r.checkLine(ctx, lineNum, line); v != nil {
			violations = append(violations, v)
		}
	}

	return violations
}

func (r *InterfaceAnyRule) checkLine(ctx *core.FileContext, lineNum int, line string) *core.Violation {
	trimmed := strings.TrimSpace(line)

	// Skip comments
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
		return nil
	}

	// Skip regex patterns
	if strings.Contains(line, "regexp.") && strings.Contains(line, `interface\{\}`) {
		return nil
	}

	// Check each pattern
	for patternName, pattern := range r.patterns {
		if !pattern.MatchString(line) {
			continue
		}

		if r.shouldSkipMatch(line, patternName, ctx) {
			continue
		}

		v := r.CreateViolation(ctx.RelPath, lineNum+1, r.getMessage(patternName))
		v.WithCode(trimmed)
		v.WithSuggestion(r.getSuggestion(patternName))
		return v // One violation per line
	}

	return nil
}

func (r *InterfaceAnyRule) shouldSkipMatch(line, patternName string, ctx *core.FileContext) bool {
	// Skip if inside string literal
	if strings.Contains(line, `"`) {
		matchStr := getMatchString(patternName)
		if isInsideString(line, matchStr) {
			return true
		}
	}

	return r.isAllowedException(line, ctx)
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
	return isUsingAny(line)
}

func isUsingAny(line string) bool {
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

	beforeSubstr := line[:idx]
	quoteCount := strings.Count(beforeSubstr, `"`)
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

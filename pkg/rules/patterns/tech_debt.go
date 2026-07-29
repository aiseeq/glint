package patterns

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTechDebtRule())
}

// TechDebtRule detects technical debt patterns beyond simple TODO comments
type TechDebtRule struct {
	*rules.BaseRule
	patterns map[string]*debtPattern
}

type debtPattern struct {
	regex       *regexp.Regexp
	severity    core.Severity
	description string
	suggestion  string
}

// NewTechDebtRule creates the rule
func NewTechDebtRule() *TechDebtRule {
	r := &TechDebtRule{
		BaseRule: rules.NewBaseRule(
			"tech-debt",
			"patterns",
			"Detects technical debt patterns: legacy markers, fake refactoring, compliance spam",
			core.SeverityMedium,
		),
	}
	r.initPatterns()
	return r
}

func (r *TechDebtRule) initPatterns() {
	r.patterns = map[string]*debtPattern{
		"legacy_marker": {
			regex:       regexp.MustCompile(`(?i)//.*\b(legacy\s+code|deprecated\s+code|old\s+code|remove\s+legacy|migrate\s+from\s+legacy)`),
			severity:    core.SeverityMedium,
			description: "Legacy/deprecated code marker",
			suggestion:  "Remove legacy code or create migration task",
		},
		"fake_refactoring": {
			regex:       regexp.MustCompile(`(?i)//.*(?:wrapper|делегирует|delegates?).*(?:вместо|instead\s+of).*(?:удаления|removal|eliminating)`),
			severity:    core.SeverityHigh,
			description: "Fake refactoring - wrapper instead of removal",
			suggestion:  "Remove wrapper and use canonical implementation directly",
		},
		"temporary_solution": {
			regex:       regexp.MustCompile(`(?i)//\s*(temporary|временн|temp\s+fix|quick\s+fix|hotfix|workaround)`),
			severity:    core.SeverityMedium,
			description: "Temporary solution marker",
			suggestion:  "Replace with proper implementation",
		},
		"needs_refactoring": {
			regex:       regexp.MustCompile(`(?i)//\s*(needs?\s+refactor|should\s+be\s+refactored|refactor\s+this|требует\s+рефакторинг)`),
			severity:    core.SeverityMedium,
			description: "Code marked for refactoring",
			suggestion:  "Refactor the code or create a task",
		},
		"dead_code_marker": {
			// "unused" must be followed by a non-letter to avoid matching "UnusedParamRule",
			// and not by a hyphen: "unused-field" is a rule name being referenced, not an
			// admission of dead code (repro: glint self-check on never_assigned_field.go).
			regex:       regexp.MustCompile(`(?i)//\s*(dead\s+code|unused(?:[^a-zA-Z-]|$)|not\s+used|никогда\s+не\s+использ)`),
			severity:    core.SeverityMedium,
			description: "Dead code marker",
			suggestion:  "Remove dead code - git remembers history",
		},
		"broken_feature": {
			regex:       regexp.MustCompile(`(?i)//\s*(broken|не\s+работает|doesn.?t\s+work|сломан)`),
			severity:    core.SeverityHigh,
			description: "Broken feature marker",
			suggestion:  "Fix the broken feature or remove it",
		},
		"ignore_errors": {
			// Only an explicit "ignore error" with no explanation counts.
			// Phrases like "non-critical" or "safe to ignore" usually justify
			// why ignoring is fine, so they are not lazy markers.
			regex:       regexp.MustCompile(`(?i)//.*\b(ignore\s+errors?\s*$|игнорир\w*\s+ошибк\w*\s*$)`),
			severity:    core.SeverityCritical,
			description: "Ignoring errors without explanation - document why it's safe",
			suggestion:  "Add explanation why ignoring is safe (e.g. 'Non-critical: uses defaults if fails')",
		},
		"unfinished_work": {
			regex:       regexp.MustCompile(`(?i)//\s*(\bWIP\b|work\s+in\s+progress|not\s+finished|incomplete|незаверш|в\s+работе)`),
			severity:    core.SeverityMedium,
			description: "Unfinished work marker",
			suggestion:  "Complete the implementation or create a task",
		},
	}
}

// AnalyzeFile checks for tech debt patterns
func (r *TechDebtRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.IsTestFile() || r.shouldSkipFile(ctx.RelPath) {
		return nil
	}

	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		// Skip non-comment lines for efficiency
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "//") {
			continue
		}

		for _, patternName := range slices.Sorted(maps.Keys(r.patterns)) {
			pattern := r.patterns[patternName]
			if pattern.regex.MatchString(line) {
				v := r.CreateViolation(ctx.RelPath, lineNum+1, pattern.description)
				v.Severity = pattern.severity
				v.WithCode(trimmed)
				v.WithSuggestion(pattern.suggestion)
				v.WithContext("pattern", patternName)

				violations = append(violations, v)
				break // Only report first matching pattern per line
			}
		}
	}

	return violations
}

func (r *TechDebtRule) shouldSkipFile(path string) bool {
	if strings.HasSuffix(path, "legacy_comment_marker.go") || strings.HasSuffix(path, "legacy_identifier.go") {
		return true
	}
	skipPatterns := []string{
		"vendor/",
		"node_modules/",
		"/generated/",
		".generated.",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range skipPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	return false
}

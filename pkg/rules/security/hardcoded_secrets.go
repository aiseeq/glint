package security

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewHardcodedSecretsRule())
}

// HardcodedSecretsRule detects hardcoded passwords, API keys, and tokens
type HardcodedSecretsRule struct {
	*rules.BaseRule
	patterns []*secretPattern
}

type secretPattern struct {
	name    string
	regex   *regexp.Regexp
	message string
}

// NewHardcodedSecretsRule creates the rule
func NewHardcodedSecretsRule() *HardcodedSecretsRule {
	return &HardcodedSecretsRule{
		BaseRule: rules.NewBaseRule(
			"hardcoded-secret",
			"security",
			"Detects hardcoded passwords, API keys, tokens, and other secrets",
			core.SeverityCritical,
		),
		patterns: []*secretPattern{
			{
				name:    "password",
				regex:   regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["'\x60][^"'\x60]{4,}["'\x60]`),
				message: "Hardcoded password detected",
			},
			{
				name:    "api_key",
				regex:   regexp.MustCompile(`(?i)\b(api[_-]?key|apikey)\s*[:=]\s*["'\x60][A-Za-z0-9_\-]{16,}["'\x60]`),
				message: "Hardcoded API key detected",
			},
			{
				name:    "secret",
				regex:   regexp.MustCompile(`(?i)(secret|private[_-]?key)\s*[:=]\s*["'\x60][^"'\x60]{8,}["'\x60]`),
				message: "Hardcoded secret detected",
			},
			{
				name:    "token",
				regex:   regexp.MustCompile(`(?i)(auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*["'\x60][A-Za-z0-9_\-\.]{20,}["'\x60]`),
				message: "Hardcoded token detected",
			},
			{
				name:    "aws_key",
				regex:   regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
				message: "AWS access key detected",
			},
			{
				name:    "private_key",
				regex:   regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
				message: "Private key detected in source code",
			},
			{
				name:    "jwt",
				regex:   regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`),
				message: "JWT token detected in source code",
			},
		},
	}
}

// AnalyzeFile checks for hardcoded secrets
func (r *HardcodedSecretsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	// Skip test files - they may contain test credentials
	if ctx.IsTestFile() {
		return nil
	}

	// Skip config module files - they contain development defaults
	// that are overridden by environment variables in production
	if strings.Contains(ctx.RelPath, "/config/") || strings.HasPrefix(ctx.RelPath, "config/") {
		return nil
	}

	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		// Skip comments
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Skip lines that are clearly example/placeholder values
		if r.isPlaceholder(line) {
			continue
		}

		for _, pattern := range r.patterns {
			if pattern.regex.MatchString(line) {
				v := r.CreateViolation(ctx.RelPath, lineNum+1, pattern.message)
				v.WithCode(r.maskSecret(line))
				v.WithSuggestion("Use environment variables or a secrets manager")
				v.WithContext("pattern", pattern.name)
				violations = append(violations, v)
				break // Only report one match per line
			}
		}
	}

	return violations
}

func (r *HardcodedSecretsRule) isPlaceholder(line string) bool {
	lower := strings.ToLower(line)
	placeholders := []string{
		"xxx", "your_", "example", "placeholder", "<your",
		"todo", "fixme", "change_me", "replace_with",
		"test_", "dummy", "sample", "demo",
	}

	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
	}

	// Skip explicit testing configuration (Testing.Security.*, etc.)
	if strings.Contains(lower, "testing.security") ||
		strings.Contains(lower, "testsecurity") ||
		strings.Contains(lower, "testconfig") {
		return true
	}

	return false
}

func (r *HardcodedSecretsRule) maskSecret(line string) string {
	// Mask the actual secret value in the output
	// Find quoted strings and mask their middle part
	masked := line
	for _, quote := range []string{`"`, `'`, "`"} {
		parts := strings.Split(masked, quote)
		for i := 1; i < len(parts); i += 2 {
			if len(parts[i]) > 4 {
				visible := 2
				if len(parts[i]) > 8 {
					visible = 3
				}
				parts[i] = parts[i][:visible] + "***" + parts[i][len(parts[i])-visible:]
			}
		}
		masked = strings.Join(parts, quote)
	}
	return masked
}

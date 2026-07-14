package security

import (
	"path/filepath"
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
	name           string
	regex          *regexp.Regexp
	message        string
	highConfidence bool
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
				name:           "resend_key",
				regex:          regexp.MustCompile(`\bre_[A-Za-z0-9_-]{20,}\b`),
				message:        "Resend API key detected",
				highConfidence: true,
			},
			{
				name:           "google_oauth_secret",
				regex:          regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_-]{20,}\b`),
				message:        "Google OAuth client secret detected",
				highConfidence: true,
			},
			{
				name:           "stripe_key",
				regex:          regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{20,}\b`),
				message:        "Stripe live secret key detected",
				highConfidence: true,
			},
			{
				name:           "pgpassword",
				regex:          regexp.MustCompile(`\bPGPASSWORD=\S{20,}`),
				message:        "Hardcoded PostgreSQL password detected",
				highConfidence: true,
			},
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
				name:           "aws_key",
				regex:          regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
				message:        "AWS access key detected",
				highConfidence: true,
			},
			{
				name:           "private_key",
				regex:          regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
				message:        "Private key detected in source code",
				highConfidence: true,
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
	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		// Skip comments
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		for _, pattern := range r.patterns {
			if (ctx.IsTestFile() || isTestConfigPath(ctx.RelPath)) && !pattern.highConfidence {
				continue
			}
			if !pattern.highConfidence && r.isPlaceholder(line) {
				continue
			}
			if pattern.regex.MatchString(line) {
				if ctx.IsSuppressed(lineNum+1, r.Name()) {
					break
				}
				v := r.CreateViolation(ctx.RelPath, lineNum+1, pattern.message)
				v.WithCode(r.maskSecretMatches(line))
				v.WithSuggestion("Use environment variables or a secrets manager")
				v.WithContext("pattern", pattern.name)
				violations = append(violations, v)
				break // Only report one match per line
			}
		}
	}

	return violations
}

func isTestConfigPath(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	return strings.Contains(lower, "test-config") ||
		strings.Contains(lower, "test_config") ||
		strings.Contains(lower, "/testing/")
}

func (r *HardcodedSecretsRule) isPlaceholder(line string) bool {
	lower := strings.ToLower(line)
	placeholders := []string{
		"xxx", "your_", "example", "placeholder", "<your",
		"todo", "fixme", "change_me", "replace_with",
		"test_", "dummy", "sample", "demo", "${",
		"process.env", "os.getenv", "os.lookupenv",
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

func (r *HardcodedSecretsRule) maskSecretMatches(line string) string {
	for _, pattern := range r.patterns {
		line = pattern.regex.ReplaceAllString(line, "[REDACTED]")
	}
	return line
}

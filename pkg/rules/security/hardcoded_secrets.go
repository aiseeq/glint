package security

import (
	"go/ast"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
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
	name  string
	regex *regexp.Regexp
	// needles are lower-case texts one of which every match contains: a line
	// holding none of them is skipped without running the regexp, whose
	// leading \b or (?i) alternation rules out a fast literal-prefix scan.
	needles        []string
	message        string
	highConfidence bool
}

// mayMatch reports whether the lower-cased line holds one of the needles.
func (p *secretPattern) mayMatch(lowerLine string) bool {
	return helpers.ContainsAny(lowerLine, p.needles)
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
				needles:        []string{"re_"},
				message:        "Resend API key detected",
				highConfidence: true,
			},
			{
				name:           "google_oauth_secret",
				regex:          regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_-]{20,}\b`),
				needles:        []string{"gocspx-"},
				message:        "Google OAuth client secret detected",
				highConfidence: true,
			},
			{
				name:           "stripe_key",
				regex:          regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{20,}\b`),
				needles:        []string{"sk_live_"},
				message:        "Stripe live secret key detected",
				highConfidence: true,
			},
			{
				name:           "pgpassword",
				regex:          regexp.MustCompile(`\bPGPASSWORD=\S{20,}`),
				needles:        []string{"pgpassword="},
				message:        "Hardcoded PostgreSQL password detected",
				highConfidence: true,
			},
			{
				name:    "password",
				needles: []string{"pass", "pwd"},
				regex:   regexp.MustCompile(`(?i)` + nameAlternation(passwordNames) + `\s*(?::=|[:=])\s*["'\x60][^"'\x60]{4,}["'\x60]`),
				message: "Hardcoded password detected",
			},
			{
				name:    "api_key",
				needles: []string{"api"},
				regex:   regexp.MustCompile(`(?i)\b` + nameAlternation(apiKeyNames) + `\s*(?::=|[:=])\s*["'\x60][A-Za-z0-9_\-]{16,}["'\x60]`),
				message: "Hardcoded API key detected",
			},
			{
				name:    "secret",
				needles: []string{"secret", "private"},
				regex:   regexp.MustCompile(`(?i)` + nameAlternation(secretNames) + `\s*(?::=|[:=])\s*["'\x60][^"'\x60]{8,}["'\x60]`),
				message: "Hardcoded secret detected",
			},
			{
				name:    "token",
				needles: []string{"token", "bearer"},
				regex:   regexp.MustCompile(`(?i)` + nameAlternation(tokenNames, []string{`bearer`}) + `\s*(?::=|[:=])\s*["'\x60][A-Za-z0-9_\-\.]{20,}["'\x60]`),
				message: "Hardcoded token detected",
			},
			{
				name:           "aws_key",
				regex:          regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
				needles:        []string{"akia"},
				message:        "AWS access key detected",
				highConfidence: true,
			},
			{
				name:           "private_key",
				regex:          regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
				needles:        []string{"-----begin "},
				message:        "Private key detected in source code",
				highConfidence: true,
			},
			{
				name:    "jwt",
				regex:   regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`),
				needles: []string{"eyj"},
				message: "JWT token detected in source code",
			},
		},
	}
}

// truncatedPEMBlock is a whole PEM block on one line with a body too short to be
// a key: test fixtures write them to exercise the parsing.
var truncatedPEMBlock = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\n|\s)*[A-Za-z0-9+/=\\n]{0,120}-----END [A-Z ]*PRIVATE KEY-----`)

// AnalyzeFile checks for hardcoded secrets
func (r *HardcodedSecretsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	patternLiterals := regexpPatternLiterals(ctx)
	contentAt := stringContents(ctx)
	testData := ctx.IsTestFile() || isTestConfigPath(ctx.RelPath)
	envTemplate := ctx.IsEnvTemplate()

	for lineNum, line := range ctx.Lines {
		// Skip comments
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || (envTemplate && strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if credential := credentialInLine(line, envTemplate); credential != "" {
			if !ctx.IsSuppressed(lineNum+1, r.Name()) {
				v := r.CreateViolation(ctx.RelPath, lineNum+1, "Hardcoded credential: a real-looking password in a URL's userinfo or a secret value in an env template")
				v.WithCode(strings.ReplaceAll(line, credential, "[REDACTED]"))
				v.WithSuggestion("Read the credential from the environment or a secrets manager; leave a placeholder (user:password@) in templates")
				v.WithContext("pattern", "url_userinfo")
				violations = append(violations, v)
			}
			continue
		}
		lower := strings.ToLower(line)

		for _, pattern := range r.patterns {
			if testData && !pattern.highConfidence {
				continue
			}
			if !pattern.mayMatch(lower) {
				continue
			}
			if testData && pattern.name == "private_key" && truncatedPEMBlock.MatchString(line) {
				continue // a test's truncated PEM: a real key body is far longer
			}
			var notSecret func(key, value string) bool
			if !pattern.highConfidence {
				notSecret = isNotSecretValue
			}
			if hasLiteralSecret(pattern.regex, line, lineNum+1, secretContext{patternLiterals, contentAt, !ctx.IsGoFile()}, notSecret) {
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
	if !testData {
		violations = append(violations, r.defaultTagSecrets(ctx)...)
	}

	return violations
}

// defaultTagSecrets reports a credential written as the default of a struct
// field (Password string `env:"DB_PASSWORD" default:"..."`): whenever the
// environment sets nothing, the binary's own copy is the password.
func (r *HardcodedSecretsRule) defaultTagSecrets(ctx *core.FileContext) []*core.Violation {
	if ctx.GoAST == nil {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		field, ok := n.(*ast.Field)
		if !ok || field.Tag == nil || len(field.Names) != 1 || !secretFieldName.MatchString(field.Names[0].Name) {
			return true
		}
		value, ok := fieldTag(field).Lookup("default")
		if !ok || value == "" || isNotSecretValue(field.Names[0].Name, value) {
			return true
		}
		line := ctx.LineFor(field)
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, line, "Hardcoded secret as the default value of a configuration field")
		v.WithCode(r.maskSecretMatches(strings.Replace(ctx.GetLine(line), value, "***", 1)))
		v.WithSuggestion("Leave the default empty and fail at startup when the environment does not set it")
		v.WithContext("pattern", "default_tag")
		violations = append(violations, v)
		return true
	})
	return violations
}

// secretContext is what the file tells about the strings of a line.
type secretContext struct {
	patternLiterals []regexpPatternLiteral
	contentAt       stringContentAt
	// regexpShapes is set for a file whose regexp patterns are not known
	// (regexpPatternLiterals reads Go only): there a value written as a
	// regular expression is the shape a scanner searches for, no secret.
	regexpShapes bool
}

// hasLiteralSecret reports whether a line carries a literal value of the
// secret pattern. A match inside a regexp pattern counts only when the pattern's
// fixed text holds the secret by itself: the rest describes a shape. A match
// whose "quoted value" is code between two literals holds no value at all.
// notSecret, when set, judges the matched value and the text before it (the
// key): a placeholder, an environment variable name or a sentence is no secret.
func hasLiteralSecret(secret *regexp.Regexp, line string, lineNum int, file secretContext, notSecret func(key, value string) bool) bool {
	for _, loc := range secret.FindAllStringIndex(line, -1) {
		match := line[loc[0]:loc[1]]
		if isDynamicSecretMatch(match) || quotedValueIsCode(match, loc[0], lineNum, file.contentAt) {
			continue
		}
		if file.regexpShapes && helpers.LooksLikeRegexpShape(match) {
			continue
		}
		if notSecret != nil {
			valueStart, value := matchedValue(match)
			if notSecret(line[:loc[0]+valueStart], value) {
				continue
			}
		}
		if literal, ok := regexpPatternAt(file.patternLiterals, lineNum, loc[0]+1); ok && literal.exempts(secret) {
			continue
		}
		return true
	}
	return false
}

func isDynamicSecretMatch(match string) bool {
	separator := strings.IndexByte(match, '=')
	if separator < 0 {
		return false
	}
	value := strings.TrimSpace(match[separator+1:])
	// Кавычка перед $ не делает значение литералом: PGPASSWORD="$DB_PASSWORD"
	// — та же подстановка переменной, что и без кавычек.
	value = strings.TrimLeft(value, "\"'`")
	return strings.HasPrefix(value, "$")
}

func isTestConfigPath(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	return strings.Contains(lower, "test-config") ||
		strings.Contains(lower, "test_config") ||
		strings.Contains(lower, "/testing/")
}

// matchedValue returns the value of a key = "value" match and its offset in
// the match: the text between the first quote after the separator and the
// closing quote that ends the match. A match without a quoted value (a bare
// token) is its own value.
func matchedValue(match string) (int, string) {
	separator := strings.IndexAny(match, ":=")
	if separator < 0 {
		return 0, match
	}
	open := strings.IndexAny(match[separator:], "\"'`")
	if open < 0 {
		return 0, match
	}
	start := separator + open + 1
	end := len(match)
	if end > start && strings.ContainsRune("\"'`", rune(match[end-1])) {
		end--
	}
	return start, match[start:end]
}

// placeholderMarkers are the fragments of a value that is written to be
// replaced: your_password_here, example_api_key, ${DB_PASSWORD}.
var placeholderMarkers = []string{
	"xxx", "your_", "example", "placeholder", "<your",
	"todo", "fixme", "change_me", "replace_with",
	"test_", "dummy", "sample", "demo", "${",
	"process.env", "os.getenv", "os.lookupenv",
}

// testConfigMarkers are key fragments of explicit testing configuration
// (Testing.Security.*, testConfig.*).
var testConfigMarkers = []string{"testing.security", "testsecurity", "testconfig"}

// envVarName is the shape of an environment variable name: DB_PASSWORD.
var envVarName = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)

// urlPath is the shape of a route: /auth/reset-password.
var urlPath = regexp.MustCompile(`^/[A-Za-z0-9._~:{}/-]*$`)

// isNotSecretValue reports whether a matched value holds no secret: a
// placeholder, the name of an environment variable, a URL path, a phrase with
// spaces, or a value under an explicit testing-configuration key. Markers
// count only in the value (and the key for test configuration), never in a
// trailing comment.
func isNotSecretValue(key, value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	lowerKey := strings.ToLower(key)
	for _, marker := range testConfigMarkers {
		if strings.Contains(lowerKey, marker) {
			return true
		}
	}
	return envVarName.MatchString(value) || urlPath.MatchString(value) || strings.ContainsAny(strings.TrimSpace(value), " \t")
}

func (r *HardcodedSecretsRule) maskSecretMatches(line string) string {
	for _, pattern := range r.patterns {
		line = pattern.regex.ReplaceAllString(line, "[REDACTED]")
	}
	return line
}

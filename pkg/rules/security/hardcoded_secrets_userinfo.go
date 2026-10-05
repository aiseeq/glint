package security

import (
	"regexp"
	"strings"
	"unicode"
)

// urlUserinfoPassword finds the password of scheme://user:password@host.
var urlUserinfoPassword = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@"'\x60]*:([^\s@/"'\x60]+)@[^\s"'\x60]`)

// envTemplateSecret is a KEY=value line of an env template whose key names a
// secret.
var envTemplateSecret = regexp.MustCompile(`^(?:export\s+)?([A-Za-z0-9_]*(?i:password|passwd|secret|token|api_?key|private_key)[A-Za-z0-9_]*)=(.*)$`)

// envTemplateNotSecretKey names a key about a secret rather than the secret
// itself: where it lives, what it is called.
var envTemplateNotSecretKey = regexp.MustCompile(`(?i)_(?:file|path|dir|name|url|id|ttl|length|len)$`)

// credentialInLine returns the value of a credential written into the line:
// a real-looking password in the userinfo of a URL (a DSN constant named
// adminDSN is a password whatever its variable is called), and in an env
// template the value of a secret key. "" when there is none.
func credentialInLine(line string, envTemplate bool) string {
	for _, m := range urlUserinfoPassword.FindAllStringSubmatch(line, -1) {
		if realLookingSecret(m[1], 8) {
			return m[1]
		}
	}
	if !envTemplate {
		return ""
	}
	m := envTemplateSecret.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil || envTemplateNotSecretKey.MatchString(m[1]) {
		return ""
	}
	value := strings.Trim(strings.TrimSpace(m[2]), `"'`)
	if realLookingSecret(value, 12) {
		return value
	}
	return ""
}

// realLookingSecret reports a value shaped like a real secret: long enough,
// letters and digits mixed, no template or format syntax, no placeholder
// word. postgres:postgres and user:password stay local defaults.
func realLookingSecret(value string, minLen int) bool {
	if len(value) < minLen || strings.ContainsAny(value, "${}%<> \t") {
		return false
	}
	var letter, digit bool
	for _, c := range value {
		letter = letter || unicode.IsLetter(c)
		digit = digit || unicode.IsDigit(c)
	}
	if !letter || !digit {
		return false
	}
	lower := strings.ToLower(value)
	for _, word := range []string{"password", "changeme", "change_me", "change-me", "secret", "replace"} {
		if strings.Contains(lower, word) {
			return false
		}
	}
	return !isNotSecretValue("", value)
}

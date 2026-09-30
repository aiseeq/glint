package security

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The samples are split so that the file itself holds no secret-shaped text.
// Every pattern names the texts its matches contain; a needle that misses a
// real match would silently hide the secret.
func TestHardcodedSecretNeedlesAdmitEveryMatch(t *testing.T) {
	samples := map[string]string{
		"resend_key":          `key := "re` + `_AbCdEfGhIjKlMnOpQrStUv"`,
		"google_oauth_secret": `v := "GOCSPX` + `-AbCdEfGhIjKlMnOpQrStUv"`,
		"stripe_key":          `v := "sk_live` + `_AbCdEfGhIjKlMnOpQrStUv"`,
		"pgpassword":          `PGPASSWORD` + `=AbCdEfGhIjKlMnOpQrStUv psql`,
		"password":            `DBPassWord := "hunter22"`,
		"api_key":             `API-KEY: "AbCdEfGhIjKlMnOp1234"`,
		"secret":              `PRIVATE_KEY = "AbCdEfGh1234"`,
		"token":               `Bearer = "AbCdEfGhIjKlMnOpQrStUv"`,
		"aws_key":             `id := "AKIA` + `ABCDEFGHIJKLMNOP"`,
		"private_key":         `-----BEGIN ` + `RSA PRIVATE KEY-----`,
		"jwt":                 `t := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"`,
	}
	rule := NewHardcodedSecretsRule()
	for _, pattern := range rule.patterns {
		sample, ok := samples[pattern.name]
		require.True(t, ok, "no sample for pattern %s", pattern.name)
		require.NotEmpty(t, pattern.needles, pattern.name)
		for _, needle := range pattern.needles {
			assert.Equal(t, strings.ToLower(needle), needle, "needles are lower-case: %s", pattern.name)
		}
		require.True(t, pattern.regex.MatchString(sample), "sample must match %s", pattern.name)
		assert.True(t, pattern.mayMatch(strings.ToLower(sample)), "needles of %s reject a match", pattern.name)
	}
}

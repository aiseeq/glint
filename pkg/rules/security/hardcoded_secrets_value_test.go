package security

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A value that names a secret without holding it - the name of an environment
// variable, a URL path, a sentence shown to the user - is not a secret, even
// when the identifier it is assigned to says password or secret.
func TestHardcodedSecretsIgnoresValuesThatAreNotSecrets(t *testing.T) {
	code := `package app

const routeResetPassword = "/auth/reset-password"

const envJWTSecret = "APP_JWT_SECRET"

const envDBPassword = "DB_PASSWORD"

type Msgs struct{ Password string }

var labels = Msgs{Password: "Enter your password"}
`
	ctx := rulestest.GoFile(t, "app/app.go", code)
	assert.Empty(t, NewHardcodedSecretsRule().AnalyzeFile(ctx))
}

// A placeholder marker counts only inside the value: a real secret stays a
// secret when a trailing comment or the identifier mentions test_ or example.
func TestHardcodedSecretsPlaceholderOnlyInValue(t *testing.T) {
	value := strings.Join([]string{"Sup3r", "S3cret", "Value"}, "")
	tests := []struct {
		name string
		code string
	}{
		{
			name: "trailing comment",
			code: "package app\n\nvar dbPassword = \"" + value + "\" // rotated after test_run\n",
		},
		{
			name: "identifier",
			code: "package app\n\nvar exampleServicePassword = \"" + value + "\"\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := rulestest.GoFile(t, "app/app.go", tt.code)
			violations := NewHardcodedSecretsRule().AnalyzeFile(ctx)
			if assert.Len(t, violations, 1, "Code:\n%s", tt.code) {
				assert.Equal(t, "password", violations[0].Context["pattern"])
			}
		})
	}
}

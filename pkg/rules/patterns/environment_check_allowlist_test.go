package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// An access predicate answers yes when its allowlist is empty: a deploy
// without the setting lets everybody in.
func TestEnvironmentCheckFailsOpenEmptyAllowlist(t *testing.T) {
	file := rulestest.GoFile(t, "auth/admins.go", `package auth

import (
	"os"
	"strings"
)

func operatorEmails() []string {
	env := os.Getenv("OPERATOR_EMAILS")
	if env == "" {
		return nil
	}
	return strings.Split(env, ",")
}

func isOperatorEmail(email string) bool {
	allowed := operatorEmails()
	if allowed == nil {
		return true
	}
	for _, e := range allowed {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	return false
}

type Guard struct{ AllowedOrigins []string }

func (g Guard) canCall(origin string) bool {
	if len(g.AllowedOrigins) == 0 {
		return true
	}
	for _, o := range g.AllowedOrigins {
		if o == origin {
			return true
		}
	}
	return false
}

func hasTags(tags []string) bool {
	if len(tags) == 0 {
		return true
	}
	return false
}

func isDenied(email string) bool {
	blocked := strings.Split(os.Getenv("BLOCKED_EMAILS"), ",")
	if len(blocked) == 0 {
		return false
	}
	for _, b := range blocked {
		if b == email {
			return true
		}
	}
	return false
}
`)
	assert.Equal(t, []string{"auth/admins.go:18", "auth/admins.go:32"},
		foundLines(NewEnvironmentCheckFailsOpenRule().AnalyzeFile(file)))
}

package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// Context keys are package-level declarations; two functions that each name a
// local variable key define no keys at all.
func TestRedundantCompatibility_LocalKeyVariablesAreNotKeyDefinitions(t *testing.T) {
	const source = `package keys

import "fmt"

type ctxKey string

const UserIDKey ctxKey = "user_id"

const UserIDKeyAlt ctxKey = "userID"

func CacheA(id int) string {
	var key = fmt.Sprintf("a:%d", id)
	return key
}

func CacheB(id int) string {
	var key = fmt.Sprintf("b:%d", id)
	return key
}
`
	ctx := rulestest.GoFile(t, "keys/k.go", source)
	var codes []string
	for _, v := range NewRedundantCompatibilityRule().AnalyzeFile(ctx) {
		codes = append(codes, v.Code)
	}
	assert.Equal(t, []string{"Keys: UserIDKey, UserIDKeyAlt (base: UserIDKey)"}, codes)
}

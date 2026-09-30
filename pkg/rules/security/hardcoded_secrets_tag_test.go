package security

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A secret written as the default of a configuration field ships in the
// binary: it is the value whenever the environment does not set one.
func TestHardcodedSecretsDefaultInStructTag(t *testing.T) {
	code := "package config\n\n" +
		"type Database struct {\n" +
		"\tHost     string `yaml:\"host\" env:\"DB_HOST\" default:\"localhost\"`\n" +
		"\tPassword string `yaml:\"password\" env:\"DB_PASSWORD\" json:\"-\" default:\"hunter2\"`\n" +
		"\tAPIKey   string `yaml:\"api_key\" env:\"API_KEY\" default:\"\"`\n" +
		"\tToken    string `yaml:\"token\" env:\"TOKEN\" default:\"${TOKEN}\"`\n" +
		"}\n\n" +
		"type Security struct {\n" +
		"\tJWTSecret string `yaml:\"jwt_secret\" env:\"JWT_SECRET\" json:\"-\" default:\"s3cr3t-signing-key\"`\n" +
		"}\n"
	ctx := rulestest.GoFile(t, "config/config.go", code)
	var lines []int
	for _, v := range NewHardcodedSecretsRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{5, 11}, lines)
}

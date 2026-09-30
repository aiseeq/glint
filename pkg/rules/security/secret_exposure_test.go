package security

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func secretExposureLines(t *testing.T, path, code string) []int {
	t.Helper()
	var lines []int
	for _, v := range NewSecretExposureRule().AnalyzeFile(rulestest.GoFile(t, path, code)) {
		lines = append(lines, v.Line)
	}
	return lines
}

// A secret or a connection string handed to a log line or an error message
// is written wherever logs and errors go.
func TestSecretExposureInLogsAndErrors(t *testing.T) {
	code := "package svc\n\n" +
		"import (\n\t\"fmt\"\n\t\"log/slog\"\n)\n\n" +
		"type Config struct{ Password string; Host string }\n\n" +
		"type Flags struct{ dbURL string }\n\n" +
		"var ErrNoAPIKey = fmt.Errorf(\"no key\")\n\n" +
		"func check(c Config, known []string, logger *slog.Logger, flags Flags) error {\n" +
		"\tlogger.Info(\"migration config\", \"db_url\", flags.dbURL, \"host\", c.Host)\n" +
		"\tfor _, k := range known {\n" +
		"\t\tif k == c.Password {\n" +
		"\t\t\treturn fmt.Errorf(\"known development password '%s'\", c.Password)\n" +
		"\t\t}\n" +
		"\t}\n" +
		"\tlogger.Error(fmt.Sprintf(\"login failed for %s\", c.Host))\n" +
		"\t_ = fmt.Errorf(\"%w: %s\", ErrNoAPIKey, c.Host)\n" +
		"\tlogger.Info(\"password length\", \"len\", len(c.Password))\n" +
		"\tdsn := fmt.Sprintf(\"postgres://u:%s@%s\", c.Password, c.Host)\n" +
		"\t_ = dsn\n" +
		"\treturn nil\n" +
		"}\n"
	assert.Equal(t, []int{15, 18}, secretExposureLines(t, "svc/svc.go", code))
}

// A failed comparison of a credential that prints the expected value hands
// the stored credential to whoever sent the wrong one.
func TestSecretExposureExpectedCredentialInError(t *testing.T) {
	code := "package svc\n\n" +
		"import \"fmt\"\n\n" +
		"type headers struct{ publicKey string }\n\n" +
		"type Handler struct{ publicKey string }\n\n" +
		"func (h *Handler) verify(got headers) error {\n" +
		"\tif got.publicKey != h.publicKey {\n" +
		"\t\treturn fmt.Errorf(\"invalid public key: expected %s, got %s\", h.publicKey, got.publicKey)\n" +
		"\t}\n" +
		"\treturn nil\n" +
		"}\n"
	assert.Equal(t, []int{11}, secretExposureLines(t, "svc/svc.go", code))
}

// A secret field of a configuration read from the environment, without
// json:"-", goes out whenever the configuration is encoded.
func TestSecretExposureSerializableConfigSecret(t *testing.T) {
	code := "package config\n\n" +
		"type OAuth struct {\n" +
		"\tClientID     string `yaml:\"client_id\" env:\"OAUTH_CLIENT_ID\" json:\"clientId\"`\n" +
		"\tClientSecret string `yaml:\"client_secret\" env:\"OAUTH_CLIENT_SECRET\" json:\"clientSecret\"`\n" +
		"\tPrivateKey   string `env:\"PRIVATE_KEY\" json:\"-\"`\n" +
		"}\n\n" +
		"type criticalVars struct {\n" +
		"\tJWTSecret string `env:\"JWT_SECRET\"`\n" +
		"}\n\n" +
		"type LoginRequest struct {\n" +
		"\tPassword string `json:\"password\"`\n" +
		"}\n"
	assert.Equal(t, []int{5}, secretExposureLines(t, "config/config.go", code))
}

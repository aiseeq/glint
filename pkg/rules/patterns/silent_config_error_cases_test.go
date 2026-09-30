package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A config-load name fragment matches whole camelCase words: parseEnv and
// parseEnvironment load the environment, parseEnvelope decodes a message.
func TestSilentConfigError_FragmentMatchesWholeWords(t *testing.T) {
	const source = `package env

import "encoding/json"

type Envelope struct{ Body string }

type Settings struct{ Port int }

func parseEnvelope(b []byte) (Envelope, error) {
	var e Envelope
	err := json.Unmarshal(b, &e)
	return e, err
}

func parseEnv() (Settings, error) { return Settings{}, nil }

func parseEnvironment() (Settings, error) { return Settings{}, nil }

func Bodies(raw [][]byte) []string {
	var out []string
	for _, b := range raw {
		if e, err := parseEnvelope(b); err == nil {
			out = append(out, e.Body)
		}
	}
	return out
}

func Port() int {
	port := 0
	if s, err := parseEnv(); err == nil {
		port = s.Port
	}
	if s, err := parseEnvironment(); err == nil {
		port = s.Port
	}
	return port
}
`
	ctx := rulestest.GoFile(t, "env/e.go", source)
	assert.Equal(t, []int{31, 34}, violationLines(NewSilentConfigErrorRule().AnalyzeFile(ctx)))
}

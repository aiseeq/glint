package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A missing network in the configuration gives the zero entry, and taking
// its first endpoint panics with "index out of range".
func TestIndexIntoMapLookup(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"chain/client.go": `package chain

type Network struct {
	Endpoints []string
	Ports     [2]int
}

type Config struct {
	Networks map[string]Network
	ByName   map[string]*Network
	Aliases  map[string][]string
	Nested   map[string]map[string]string
}

func Endpoint(cfg *Config) string {
	return cfg.Networks["local"].Endpoints[0]
}

func Alias(cfg *Config, name string) string {
	return cfg.Aliases[name][0]
}

func Pointer(cfg *Config) string {
	return cfg.ByName["local"].Endpoints[1]
}

func Checked(cfg *Config, name string) string {
	if len(cfg.Aliases[name]) == 0 {
		return ""
	}
	return cfg.Aliases[name][0]
}

func CheckedEntry(cfg *Config) string {
	network, ok := cfg.Networks["local"]
	if !ok || len(network.Endpoints) == 0 {
		return ""
	}
	return network.Endpoints[0]
}

func Array(cfg *Config) int {
	return cfg.Networks["local"].Ports[0]
}

func MapOfMaps(cfg *Config) string {
	return cfg.Nested["a"]["b"]
}

func Variable(cfg *Config, i int) string {
	return cfg.Aliases["x"][i]
}

func Sliced(list []string) string {
	return list[0]
}
`,
	}
	violations, err := NewIndexIntoMapLookupRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"chain/client.go:16", "chain/client.go:20", "chain/client.go:24"}, foundLines(violations))
}

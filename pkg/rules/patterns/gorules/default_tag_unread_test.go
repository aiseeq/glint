package gorules

import (
	"maps"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultTagConfig declares its defaults in tags: default is read only by a
// loader that knows the key, env-default only by its own library.
const defaultTagConfig = `package config

type Config struct {
	Port       int    ` + "`env:\"PORT\" default:\"8080\"`" + `
	RetryAfter int    ` + "`yaml:\"retry_after\" default:\"60\"`" + `
	Name       string ` + "`env:\"NAME\" env-default:\"app\"`" + `
	Plain      string ` + "`json:\"plain\"`" + `
}
`

// A default tag nobody reads leaves the field zero: the default is only
// written down. A loader of the project (reflect on the tag) or a library
// that reads the key makes it real.
func TestDefaultTagUnread(t *testing.T) {
	project := rulestest.Project(t, map[string]string{"config/config.go": defaultTagConfig})
	violations, err := NewDefaultTagUnreadRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []string{"config/config.go:4", "config/config.go:5"}, patterntest.FoundLines(violations))
	require.NotEmpty(t, violations)
	assert.Contains(t, violations[0].Message, `default:"8080"`)
}

func TestDefaultTagReadByOwnLoader(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"config/config.go": defaultTagConfig,
		"config/load.go": `package config

import "reflect"

func defaults(v any) {
	t := reflect.TypeOf(v).Elem()
	for i := range t.NumField() {
		if def, ok := t.Field(i).Tag.Lookup("default"); ok {
			_ = def
		}
	}
}
`,
	})
	violations, err := NewDefaultTagUnreadRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// defaultTagLibraryProject loads the config with a loader package that
// imports the library at path, a stub of it.
func defaultTagLibraryProject(t *testing.T, path string) map[string]string {
	t.Helper()
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n\n" +
			"require " + path + " v0.0.0\n\n" +
			"replace " + path + " => ./third_party/lib\n",
		"third_party/lib/go.mod": "module " + path + "\n\ngo 1.24\n",
		"third_party/lib/lib.go": "package lib\n\nfunc Set(v any) error { return nil }\n",
		"config/load.go": `package config

import lib "` + path + `"

func Load(c *Config) error { return lib.Set(c) }
`,
	}
	maps.Copy(files, map[string]string{"config/config.go": defaultTagConfig})
	return files
}

func TestDefaultTagReadByLibrary(t *testing.T) {
	project := rulestest.Project(t, defaultTagLibraryProject(t, "github.com/creasty/defaults"))
	violations, err := NewDefaultTagUnreadRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// A library that reads another key (cleanenv reads env-default) does not
// read default; one outside the known list is named in readers.
func TestDefaultTagReaders(t *testing.T) {
	files := defaultTagLibraryProject(t, "github.com/ilyakaznacheev/cleanenv")
	violations, err := NewDefaultTagUnreadRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"config/config.go:4", "config/config.go:5"}, patterntest.FoundLines(violations))

	files = defaultTagLibraryProject(t, "example.org/acme/conf")
	rule := NewDefaultTagUnreadRule()
	require.NoError(t, rule.Configure(map[string]any{"readers": []any{"example.org/acme/conf"}}))
	violations, err = rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

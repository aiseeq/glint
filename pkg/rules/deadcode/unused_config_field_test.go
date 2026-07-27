package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// loader.go decodes a config, which is what makes the config types of a test
// case "filled from the outside".
const configLoader = `package config

func decode(data []byte, out any) error { return nil }

func Load(data []byte) (*Root, error) {
	root := &Root{}
	err := Unmarshal(data, root)
	return root, err
}

func Unmarshal(data []byte, out any) error { return decode(data, out) }
`

func analyzeConfigFields(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := NewUnusedConfigFieldRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

// Repro from glint itself: a rule severity could be written in .glint.yaml and
// was parsed into the struct, but nothing ever read the field — the setting
// silently did nothing.
func TestUnusedConfigFieldReportsParsedButUnreadField(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"loader.go": configLoader,
		"config.go": `package config

type Root struct {
	Enabled  bool   ` + "`yaml:\"enabled\"`" + `
	Severity string ` + "`yaml:\"severity\"`" + `
}

func IsEnabled(c Root) bool {
	return c.Enabled
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, 5, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Severity")
	assert.Contains(t, violations[0].Message, "severity")
}

// Sections nested inside the decoded config are decoded too.
func TestUnusedConfigFieldReportsNestedSectionField(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"loader.go": configLoader,
		"config.go": `package config

type Root struct {
	Settings Settings ` + "`yaml:\"settings\"`" + `
}

type Settings struct {
	Output  string ` + "`yaml:\"output\"`" + `
	Verbose bool   ` + "`yaml:\"verbose\"`" + `
}

func Output(r Root) string {
	return r.Settings.Output
}
`,
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Settings.Verbose")
}

// A field read anywhere in the project is alive, even in another file.
func TestUnusedConfigFieldAcceptsFieldReadInAnotherFile(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"loader.go": configLoader,
		"config.go": `package config

type Root struct {
	Output string ` + "`yaml:\"output\"`" + `
}
`,
		"report.go": `package config

func Format(r Root) string {
	return r.Output
}
`,
	})

	assert.Empty(t, violations)
}

// A field filled in a composite literal is used: the value comes from the
// program itself, not only from the config file.
func TestUnusedConfigFieldAcceptsFieldWrittenInLiteral(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"loader.go": configLoader,
		"config.go": `package config

type Root struct {
	Code int ` + "`yaml:\"code\"`" + `
}

func Default() Root {
	return Root{Code: 200}
}
`,
	})

	assert.Empty(t, violations)
}

// Repro from glint itself: the stats of a JSON report are built by converting
// another struct and then handed to an encoder, so nothing reads the fields by
// name — but the encoder does.
func TestUnusedConfigFieldAcceptsEncodedPayload(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"report.go": `package config

type Stats struct {
	FilesAnalyzed int ` + "`yaml:\"filesAnalyzed\"`" + `
	FilesSkipped  int ` + "`yaml:\"filesSkipped\"`" + `
}

func Marshal(v any) ([]byte, error) { return nil, nil }
func Unmarshal(data []byte, out any) error { return nil }

func Report(s Stats) ([]byte, error) {
	restored := Stats{}
	if err := Unmarshal(nil, &restored); err != nil {
		return nil, err
	}
	return Marshal(s)
}
`,
	})

	assert.Empty(t, violations)
}

// A struct that nothing decodes is not a config: an unused field there is
// ordinary dead code, which is a different question.
func TestUnusedConfigFieldIgnoresTypeThatIsNeverDecoded(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"config.go": `package config

type Root struct {
	Output string ` + "`yaml:\"output\"`" + `
}

func New() Root {
	return Root{}
}
`,
	})

	assert.Empty(t, violations)
}

// Fields without a serialization tag are never filled from the outside.
func TestUnusedConfigFieldIgnoresUntaggedField(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"loader.go": configLoader,
		"config.go": `package config

type Root struct {
	Enabled bool ` + "`yaml:\"enabled\"`" + `
	cache   map[string]string
}

func IsEnabled(r Root) bool { return r.Enabled }
`,
	})

	assert.Empty(t, violations)
}

// A tag of "-" means the field is deliberately kept out of serialization.
func TestUnusedConfigFieldIgnoresSkippedTag(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"loader.go": configLoader,
		"config.go": `package config

type Root struct {
	Enabled  bool   ` + "`yaml:\"enabled\"`" + `
	internal string ` + "`yaml:\"-\"`" + `
}

func IsEnabled(r Root) bool { return r.Enabled }
`,
	})

	assert.Empty(t, violations)
}

// A field reached through an embedded struct is used by its promoted name.
func TestUnusedConfigFieldAcceptsPromotedFieldRead(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"loader.go": configLoader,
		"config.go": `package config

type Base struct {
	Version int ` + "`yaml:\"version\"`" + `
}

type Root struct {
	Base
}

func Version(r Root) int {
	return r.Version
}
`,
	})

	assert.Empty(t, violations)
}

func TestUnusedConfigFieldReportsEveryUnreadField(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"loader.go": configLoader,
		"config.go": `package config

type Root struct {
	Host string ` + "`yaml:\"host\"`" + `
	Port int    ` + "`yaml:\"port\"`" + `
}
`,
	})

	require.Len(t, violations, 2)
	assert.Equal(t, 4, violations[0].Line)
	assert.Equal(t, 5, violations[1].Line)
}

func TestUnusedConfigFieldMetadata(t *testing.T) {
	rule := NewUnusedConfigFieldRule()
	assert.Equal(t, "unused-config-field", rule.Name())
	assert.Equal(t, "deadcode", rule.Category())
	assert.False(t, rule.RequiresSSA())
	assert.Nil(t, rule.AnalyzeFile(nil))
}

func TestUnusedConfigFieldRejectsNilProject(t *testing.T) {
	_, err := NewUnusedConfigFieldRule().AnalyzeGoProject(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil Go project context")
}

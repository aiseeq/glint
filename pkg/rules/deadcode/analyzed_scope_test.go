package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// deadEverywhere is a package full of what every deadcode project rule
// reports: an unused internal export, an unused unexported symbol, an unread
// field, a nil field read but never assigned, a decoded setting nobody reads
// and a parameter nobody uses.
const deadEverywhere = `package store

type Logger interface{ Info(string) }

type unmarshalTarget struct {
	Level string ` + "`yaml:\"level\"`" + `
}

func Unmarshal(data []byte, out any) error { return nil }

func Load(data []byte) error { return Unmarshal(data, &unmarshalTarget{}) }

// Dead is exported from an internal package and used by nobody.
const Dead = 1

func unusedHelper() {}

type holder struct {
	hits   int
	logger Logger
}

func (h *holder) Touch() { h.hits++; h.logger.Info("touch") }

func Ignore(unused int) {}
`

// loadSubset loads the module but hands the loader only the files named in
// analyzed — the shape of "glint check ./cmd" or of an exclude pattern: the
// other packages are type-checked, but they have no file context.
func loadSubset(t *testing.T, files map[string]string, analyzed ...string) *core.GoProjectContext {
	t.Helper()
	root, contexts := rulestest.Module(t, files)
	keep := make(map[string]bool, len(analyzed))
	for _, rel := range analyzed {
		keep[rel] = true
	}
	var subset []*core.FileContext
	for _, fileCtx := range contexts {
		if keep[fileCtx.RelPath] {
			subset = append(subset, fileCtx)
		}
	}
	require.Len(t, subset, len(analyzed))
	project, err := core.LoadGoProject(root, subset, core.GoProjectOptions{})
	require.NoError(t, err)
	return project
}

// Repro: "glint check ./cmd" or an exclude pattern left a package out of the
// analyzed files while it stayed in the typed load; a project rule that took
// its candidates from the whole load reported into a file with no context,
// and cmd/glint aborted the run on the unmappable finding.
func TestDeadcodeProjectRulesReportOnlyAnalyzedFiles(t *testing.T) {
	project := loadSubset(t, map[string]string{
		"go.mod":                   "module example.com/projecta\n\ngo 1.24\n",
		"internal/store/store.go":  deadEverywhere,
		"cmd/app/main.go":          "package main\n\nimport \"example.com/projecta/internal/store\"\n\nfunc main() { _ = store.Load(nil) }\n",
		"internal/other/unused.go": "package other\n\nconst Gone = 2\n",
	}, "cmd/app/main.go")

	projectRules := []rules.GoProjectRule{
		NewUnusedInternalExportRule(),
		NewUnusedFieldRule(),
		NewNeverAssignedFieldRule(),
		NewUnusedConfigFieldRule(),
		NewUnusedSymbolsRule(),
		NewUnusedParamRule(),
	}
	for _, rule := range projectRules {
		violations, err := rule.AnalyzeGoProject(project)
		require.NoError(t, err, rule.Name())
		for _, v := range violations {
			_, err := project.File(v.File)
			assert.NoError(t, err, "%s reported into a file outside the analysis: %s", rule.Name(), v.Message)
		}
	}
}

// The same package, analyzed, is what each rule reports on — the subset test
// above stays meaningful only while the fixture really is dead code.
func TestDeadcodeProjectRulesSeeTheFixtureWhenAnalyzed(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"go.mod":                  "module example.com/projecta\n\ngo 1.24\n",
		"internal/store/store.go": deadEverywhere,
		"cmd/app/main.go":         "package main\n\nimport \"example.com/projecta/internal/store\"\n\nfunc main() { _ = store.Load(nil) }\n",
	})

	projectRules := []rules.GoProjectRule{
		NewUnusedInternalExportRule(),
		NewUnusedFieldRule(),
		NewNeverAssignedFieldRule(),
		NewUnusedConfigFieldRule(),
		NewUnusedSymbolsRule(),
		NewUnusedParamRule(),
	}
	for _, rule := range projectRules {
		violations, err := rule.AnalyzeGoProject(project)
		require.NoError(t, err, rule.Name())
		assert.NotEmpty(t, violations, "%s finds nothing in the dead fixture", rule.Name())
	}
}

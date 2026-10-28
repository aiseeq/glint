package gorules

import (
	"fmt"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	_ "github.com/aiseeq/glint/pkg/rules/patterns/concurrencyrules"
	_ "github.com/aiseeq/glint/pkg/rules/patterns/dbrules"
	_ "github.com/aiseeq/glint/pkg/rules/patterns/errrules"
	_ "github.com/aiseeq/glint/pkg/rules/patterns/frontendrules"
	_ "github.com/aiseeq/glint/pkg/rules/patterns/httprules"
	_ "github.com/aiseeq/glint/pkg/rules/patterns/moneyrules"
	_ "github.com/aiseeq/glint/pkg/rules/patterns/shellrules"
	_ "github.com/aiseeq/glint/pkg/rules/patterns/testrules"
	_ "github.com/aiseeq/glint/pkg/rules/patterns/timerules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every project rule meets packages that fail to type-check (an old tree, a
// broken build) with nil type information. A rule that needs types skips
// them; none may fail the whole run.
func TestProjectRulesSurvivePackageWithoutTypes(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"store/store.go": `package store

import "errors"

var ErrNotFound = errors.New("not found")

var broken int = "not an int"

type Repo struct{ rows map[string]string }

func (r *Repo) Configure(text string) {
	ErrNotFound = errors.New(text)
}

func (r *Repo) Get(id string) (string, error) {
	row, ok := r.rows[id]
	if !ok {
		return "", ErrNotFound
	}
	return row, nil
}
`,
	}
	root, contexts := rulestest.Module(t, files)
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{TolerateBrokenPackages: true, ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	require.NotEmpty(t, project.SkippedPackages)

	var failed []string
	for _, rule := range rules.All() {
		projectRule, ok := rule.(rules.GoProjectRule)
		if !ok {
			continue
		}
		func() {
			defer func() {
				if p := recover(); p != nil {
					failed = append(failed, fmt.Sprintf("%s: %v", rule.Name(), p))
				}
			}()
			if _, err := projectRule.AnalyzeGoProject(project); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", rule.Name(), err))
			}
		}()
	}
	assert.Empty(t, failed)
}

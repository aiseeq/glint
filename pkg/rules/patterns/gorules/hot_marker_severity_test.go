package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hotMarkerSource silences, with a marker, a finding of each rule in a
// function marked //glint:hot, where it is medium, and in an ordinary one,
// where it stays low.
const hotMarkerSource = `package ledger

import (
	"errors"
	"fmt"
)

//glint:hot
func Charge(a, t int, dmg int) error {
	// nolint:format-before-branch
	msg := fmt.Sprintf("charge %d on %d", a, t)
	if dmg < 0 {
		return errors.New(msg)
	}
	return nil
}

func Refund(a, t int, dmg int) error {
	// nolint:format-before-branch
	msg := fmt.Sprintf("refund %d on %d", a, t)
	if dmg < 0 {
		return errors.New(msg)
	}
	return nil
}

//glint:hot
func Count(seen map[string]int, kind string, n int) {
	// nolint:map-key-built-by-format
	seen[fmt.Sprintf("%s/%d", kind, n)]++
}

func Tally(seen map[string]int, kind string, n int) {
	// nolint:map-key-built-by-format
	seen[fmt.Sprintf("%s/%d", kind, n)]++
}
`

// A marker that silences a finding of a typed function rule keeps the
// severity the finding would have been reported with: medium in a hot
// function, low elsewhere — not the rule's default alone.
func TestHotFunctionMarkerKeepsTheRaisedSeverity(t *testing.T) {
	for name, tt := range map[string]struct {
		rule rules.GoProjectRule
		want []core.SuppressionHit
	}{
		"format-before-branch": {NewFormatBeforeBranchRule(), []core.SuppressionHit{
			{Line: 10, Severity: core.SeverityMedium, Rated: true},
			{Line: 19, Severity: core.SeverityLow, Rated: true},
		}},
		"map-key-built-by-format": {NewMapKeyBuiltByFormatRule(), []core.SuppressionHit{
			{Line: 29, Severity: core.SeverityMedium, Rated: true},
			{Line: 34, Severity: core.SeverityLow, Rated: true},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			project := rulestest.Project(t, map[string]string{"ledger/ledger.go": hotMarkerSource})
			violations, err := tt.rule.AnalyzeGoProject(project)
			require.NoError(t, err)
			assert.Empty(t, violations, "every finding is silenced")
			file, err := project.File("ledger/ledger.go")
			require.NoError(t, err)
			assert.Equal(t, tt.want, file.TakeSuppressions(tt.rule.Name()))
		})
	}
}

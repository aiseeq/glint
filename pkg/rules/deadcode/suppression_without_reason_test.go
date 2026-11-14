package deadcode

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

// The finding about a marker without a reason names the rules the marker
// leaves unexplained, not every rule of its line: what it is as severe as.
// Two bare markers of one line are one finding with the rules of both.
func TestSuppressionWithoutReasonNamesTheRulesOfItsMarker(t *testing.T) {
	root := t.TempDir()
	source := "package p\n\n" +
		"var (); var A = 1 /* stale-suppression: safe — fixture of the generator */ // nolint:empty-decl-group\n" +
		"var (); var B = 1 /* nolint:stale-suppression */ // nolint:empty-decl-group,broad-exclusion\n" +
		"var (); var C = 1 // nolint:not-a-rule,empty-decl-group\n" +
		"var (); var D = 1 // nolint:empty-decl-group the generator writes it\n"
	ctx := core.NewFileContext(filepath.Join(root, "a.go"), root, []byte(source), core.DefaultConfig())

	type finding struct {
		line  int
		rules []string
	}
	var got []finding
	for _, v := range NewSuppressionWithoutReasonRule().AnalyzeFile(ctx) {
		got = append(got, finding{v.Line, v.MarkerRules})
	}
	assert.Equal(t, []finding{
		{3, []string{"empty-decl-group"}},
		{4, []string{"stale-suppression", "empty-decl-group", "broad-exclusion"}},
		{5, []string{"empty-decl-group"}},
	}, got)
}

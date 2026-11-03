package patterntest

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// AssertFindingFiles checks each finding against the file kinds declared by
// its rule.
func AssertFindingFiles(t *testing.T, rule rules.Rule, contexts []*core.FileContext, findings []*core.Violation) {
	t.Helper()
	rulestest.AssertFindingFiles(t, rule, contexts, findings)
}

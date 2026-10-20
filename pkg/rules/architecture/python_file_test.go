package architecture

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A Python source is reported once, at its first line; any other file is
// not, nor is a file whose name only mentions py.
func TestPythonFileRule(t *testing.T) {
	rule := NewPythonFileRule()
	found := rule.AnalyzeFile(rulestest.TextFile(t, "tools/scripts/token.py", "import sys\nprint(sys.argv)\n"))
	require.Len(t, found, 1)
	assert.Equal(t, 1, found[0].Line)
	assert.Equal(t, "tools/scripts/token.py", found[0].File)

	for _, path := range []string{"tools/scripts/token.sh", "docs/py.md", "tools/pyproject.go"} {
		assert.Empty(t, rule.AnalyzeFile(rulestest.TextFile(t, path, "x\n")), path)
	}
}

// The rule ships switched off: a project turns it on in its configuration.
func TestPythonFileRuleIsOptIn(t *testing.T) {
	assert.False(t, core.DefaultConfig().IsRuleEnabled("architecture", "python-file"))
}

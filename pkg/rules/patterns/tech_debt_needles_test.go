package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every alternative of every pattern must contain one of the needles: a needle
// that misses a real match would silently hide the marker.
func TestTechDebtNeedlesAdmitEveryMatch(t *testing.T) {
	samples := map[string][]string{
		"obsolete_code_marker": {"// Deprecated code below", "// OLD CODE"},
		"fake_refactoring": {
			"// Wrapper instead of removal",
			"// делегирует вместо удаления",
		},
		"temporary_solution": {
			"// Temporary fix for the race", "// TEMPORARY:", "// временное решение",
			"// temp fix", "// Quick fix", "// HOTFIX", "// Workaround for the driver",
		},
		"needs_refactoring": {
			"// Needs refactor", "// should be refactored", "// refactor this", "// требует рефакторинга",
		},
		"dead_code_marker": {"// Dead code", "// UNUSED.", "// not used", "// никогда не используется"},
		"broken_feature": {
			"// BROKEN:", "// broken logic", "// не работает", "// doesn't work", "// Сломано",
		},
		"ignore_errors":   {"// ignore errors", "// Ignore error", "// игнорируем ошибки", "//Игнорирую ошибку"},
		"unfinished_work": {"// WIP", "// work in progress", "// not finished", "// Incomplete", "// незавершено", "// в работе"},
	}
	for _, needle := range techDebtNeedles {
		assert.Equal(t, strings.ToLower(needle), needle, "needles are lower-case")
	}
	rule := NewTechDebtRule()
	for name, pattern := range rule.patterns {
		lines, ok := samples[name]
		require.True(t, ok, "no samples for pattern %s", name)
		for _, line := range lines {
			require.True(t, pattern.regex.MatchString(line), "sample %q must match %s", line, name)
			assert.True(t, helpers.ContainsAny(strings.ToLower(line), techDebtNeedles), "needles reject %q of %s", line, name)
		}
	}
}

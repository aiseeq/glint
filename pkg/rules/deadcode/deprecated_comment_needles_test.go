package deadcode

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every deprecated pattern must hold a needle: a needle that misses a real
// match would silently hide the comment.
func TestDeprecationNeedlesAdmitEveryMatch(t *testing.T) {
	samples := []string{
		"// Deprecated: use New", "// DEPRECATED", "// Legacy: old path", "// legacy handler",
		"// Obsolete: gone", "// OBSOLETE", "// it will be removed", "// Scheduled for removal",
		"// Do not use", "// REMOVED: moved",
	}
	for _, needle := range deprecationNeedles {
		assert.Equal(t, strings.ToLower(needle), needle, "needles are lower-case")
	}
	rule := NewDeprecatedCommentRule()
	for _, pattern := range rule.deprecatedPatterns {
		matched := false
		for _, sample := range samples {
			if pattern.MatchString(sample) {
				matched = true
				assert.True(t, helpers.ContainsAny(strings.ToLower(sample), deprecationNeedles), "needles reject %q", sample)
			}
		}
		require.True(t, matched, "no sample matches %s", pattern)
	}
}

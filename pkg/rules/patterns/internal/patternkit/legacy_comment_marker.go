package patternkit

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// SuppressionDirectiveRE matches, in a lowercased comment, what names a rule
// rather than admits anything: a nolint rule list, a "<rule>: safe" marker, and
// the rule names legacy-identifier and legacy-comment-marker in prose.
var SuppressionDirectiveRE = regexp.MustCompile(`nolint:[a-z0-9_-]+(?:,\s*[a-z0-9_-]+)*|[a-z0-9_-]+:\s*safe\b|\blegacy-(?:identifier|comment-marker)\b`)

// ExplanationComment returns the lowercased comment of a line up to its first
// suppression directive. A directive and the reason after it belong to the
// suppression: a rule that took them as an explanation of the code would fall
// silent and leave the suppression stale, with no line left to put it on.
func ExplanationComment(line string) string {
	comment := strings.ToLower(core.CommentPart(line))
	if loc := SuppressionDirectiveRE.FindStringIndex(comment); loc != nil {
		comment = comment[:loc[0]]
	}
	return comment
}

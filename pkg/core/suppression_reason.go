package core

import (
	"strings"
	"unicode"
)

// SuppressionReasonRule names the rule that requires a reason after inline
// suppression markers. Its own marker suppresses only when it has a reason:
// a bare one would hide its own finding and the bare marker it stands over.
const SuppressionReasonRule = "suppression-without-reason"

// SuppressionHasReason reports whether the suppression comment gives a reason
// for the named rule: text after the rule list of "nolint:" or after "safe"
// with a letter or a digit in it. Punctuation alone (".", "//", "–") is no
// reason.
func SuppressionHasReason(comment, name string) bool {
	text := SuppressionCommentText(comment)
	if after, ok := strings.CutPrefix(text, "nolint:"); ok {
		for segment := range strings.SplitSeq(after, ",") {
			fields := strings.Fields(segment)
			if len(fields) == 0 {
				return false
			}
			if len(fields) > 1 {
				return isSuppressionReason(strings.TrimPrefix(strings.TrimSpace(segment), fields[0]))
			}
		}
		return false
	}
	for _, match := range safeMarker.FindAllStringSubmatchIndex(text, -1) {
		if text[match[2]:match[3]] == name {
			return isSuppressionReason(text[match[1]:])
		}
	}
	return false
}

// SuppressionCommentText strips comment delimiters from a suppression comment.
func SuppressionCommentText(comment string) string {
	text := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(comment), "/#*"))
	return strings.TrimSpace(strings.TrimSuffix(text, "*/"))
}

// isSuppressionReason reports text that explains: one with a letter or a
// digit.
func isSuppressionReason(text string) bool {
	return strings.ContainsFunc(text, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) })
}

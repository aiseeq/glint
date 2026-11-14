package core

import (
	"regexp"
	"slices"
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
// reason, nor are another marker, the rule names again, or a placeholder
// (<reason>, ${reason}).
func SuppressionHasReason(comment, name string) bool {
	text := SuppressionCommentText(comment)
	if after, ok := strings.CutPrefix(text, "nolint:"); ok {
		names, _ := nolintNames(text)
		for segment := range strings.SplitSeq(after, ",") {
			fields := strings.Fields(segment)
			if len(fields) == 0 {
				return false
			}
			if len(fields) > 1 {
				return isSuppressionReason(strings.TrimPrefix(strings.TrimSpace(segment), fields[0]), names)
			}
		}
		return false
	}
	for _, match := range safeMarker.FindAllStringSubmatchIndex(text, -1) {
		if text[match[2]:match[3]] == name {
			return isSuppressionReason(text[match[1]:], []string{name})
		}
	}
	return false
}

// SuppressionCommentText strips comment delimiters from a suppression comment.
func SuppressionCommentText(comment string) string {
	text := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(comment), "/#*"))
	return strings.TrimSpace(strings.TrimSuffix(text, "*/"))
}

// notReason matches what explains nothing in the text after a marker: a
// placeholder copied from an example (<reason>, ${reason}, {{reason}}) and
// another marker (nolint:<list>, <rule>: safe, a bare nolint).
var notReason = regexp.MustCompile(`<[^<>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|\bnolint(?::[A-Za-z0-9_,-]*)?|\b[a-z][a-z0-9]*(?:-[a-z0-9]+)+:\s?safe\b`)

// isSuppressionReason reports text that explains: one with a letter or a
// digit once placeholders, markers and the marker's own rule names are left
// out.
func isSuppressionReason(text string, names []string) bool {
	text = notReason.ReplaceAllString(text, " ")
	for _, field := range strings.FieldsFunc(text, func(r rune) bool { return !isReasonRune(r) && r != '-' && r != '_' }) {
		if slices.Contains(names, field) {
			continue
		}
		if strings.ContainsFunc(field, isReasonRune) {
			return true
		}
	}
	return false
}

func isReasonRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

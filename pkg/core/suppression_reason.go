package core

import "strings"

// SuppressionReasonRule names the rule that requires a reason after inline
// suppression markers. Its own marker suppresses only when it has a reason:
// a bare one would hide its own finding and the bare marker it stands over.
const SuppressionReasonRule = "suppression-without-reason"

// SuppressionHasReason reports whether the suppression comment gives a reason
// for the named rule: text after the rule list of "nolint:" or after "safe".
func SuppressionHasReason(comment, name string) bool {
	text := SuppressionCommentText(comment)
	if after, ok := strings.CutPrefix(text, "nolint:"); ok {
		segments := strings.SplitSeq(strings.TrimSuffix(after, "*/"), ",")
		for segment := range segments {
			fields := strings.Fields(segment)
			if len(fields) == 0 {
				return false
			}
			if len(fields) > 1 {
				tail := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(segment), fields[0]))
				return suppressionReasonText(tail) != ""
			}
		}
		return false
	}
	for _, marker := range []string{name + ": safe", name + ":safe"} {
		if _, after, ok := strings.Cut(text, marker); ok {
			return suppressionReasonText(after) != ""
		}
	}
	return false
}

// SuppressionCommentText strips comment delimiters from a suppression comment.
func SuppressionCommentText(comment string) string {
	text := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(comment), "/#*"))
	return strings.TrimSpace(strings.TrimSuffix(text, "*/"))
}

func suppressionReasonText(text string) string {
	return strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(text), "-—:"))
}

// markerSuppresses reports whether a line comment suppresses the rule.
func markerSuppresses(comment, ruleName string) bool {
	if !commentHasSuppressionMarker(comment, ruleName) {
		return false
	}
	return ruleName != SuppressionReasonRule || SuppressionHasReason(comment, ruleName)
}

// lineMarkerSuppresses reports whether the comment of a source line suppresses
// the rule. A Go doc code block (//<tab>) quotes an example and suppresses
// nothing, which is also why suppression-without-reason does not judge it.
func (ctx *FileContext) lineMarkerSuppresses(line, ruleName string) bool {
	comment := ctx.CommentOf(line)
	if ctx.IsGoFile() && strings.HasPrefix(comment, "//\t") {
		return false
	}
	return markerSuppresses(comment, ruleName)
}

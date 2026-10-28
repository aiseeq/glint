package shellrules

import (
	"regexp"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(newShellRule("shell-curl-status-unchecked-in-measurement",
		"Detects curl timing a request (-w '%{time_total}') without --fail and with no later check of the HTTP status — a 404 or 403 answer is timed as if it were a run of the endpoint",
		core.SeverityMedium, checkCurlMeasurementStatus))
}

var (
	curlTiming = regexp.MustCompile(`(?:^|[\s;&|(])curl\s[^|;&]*(?:\s-w|--write-out)\s*['"]?[^'"]*%\{time_[a-z]+\}`)
	// httpStatusCheck is a test, grep or case comparing an HTTP status.
	httpStatusCheck = regexp.MustCompile(`(?:\[\[?|\btest\b|\bgrep\b|\bcase\b|\(\()[^#]*(?:\b[2-5][0-9][0-9]\b|\b2\[0-9\]|\b2xx\b)`)
)

// checkCurlMeasurementStatus reports curl timing a request when nothing
// checks the answer was a success: no --fail, and no comparison of a status
// on a later line of the script.
func checkCurlMeasurementStatus(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	var out []*core.Violation
	for i, l := range src.Lines {
		for _, seg := range patternkit.Segments(l.Text) {
			at := curlTiming.FindStringIndex(seg.Text)
			if at == nil || curlFails.MatchString(seg.Text[at[0]:]) || statusCheckedAfter(src, i) {
				continue
			}
			out = appendReport(out, src.Report(r, l.LineAt(seg.Offset),
				"curl times the request with -w '%{time_...}' and nothing checks its status — an error answer (a wrong Host, a missing token) is timed as if it were a run of the endpoint",
				"Add --fail (or --fail-with-body), or compare %{http_code} with the expected status before reporting the time"))
		}
	}
	return out
}

// statusCheckedAfter reports a comparison of an HTTP status on the line or
// after it.
func statusCheckedAfter(src *patternkit.ShellSource, from int) bool {
	for _, l := range src.Lines[from:] {
		if httpStatusCheck.MatchString(patternkit.WithoutComment(l.Text)) {
			return true
		}
	}
	return false
}

package patternkit

import (
	"regexp"
)

var (
	CaptureCall     = regexp.MustCompile(`\$\(\s*([A-Za-z_][A-Za-z0-9_]*)\b`)
	LogFunctionName = regexp.MustCompile(`(?i)log|warn|info|error|success|debug|msg|print|step|notice|fail|say`)
	stdoutWrite     = regexp.MustCompile(`^(?:echo|printf)\b`)
	stderrRedirect  = regexp.MustCompile(`(?:^|\s)(?:1?>&2|>\s*/dev/stderr)`)
	FileRedirect    = regexp.MustCompile(`(?:^|[^0-9&])>{1,2}\s*[^&\s]`)
	CommandPrefix   = regexp.MustCompile(`^(?:(?:if|elif|then|else|do|while|until|!)\s+)+`)
)

// WritesToStdout reports a command whose output is not redirected.
func WritesToStdout(command string) bool {
	return !stderrRedirect.MatchString(command) && !FileRedirect.MatchString(command)
}

// StdoutWrites returns the lines where a function echoes to stdout.
func (src *ShellSource) StdoutWrites(fn ShellFunc) []int {
	var lines []int
	for _, l := range src.Body(fn) {
		for _, seg := range Segments(l.Text) {
			if write := seg.Trimmed(); stdoutWrite.MatchString(write) && WritesToStdout(write) {
				lines = append(lines, l.LineAt(seg.Offset))
			}
		}
	}
	return lines
}

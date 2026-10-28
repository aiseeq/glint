package shellrules

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

var (
	psqlCommandAssign = regexp.MustCompile(`(?:^|[\s;])(?:(?:local|export|readonly|declare)\s+)?([A-Za-z_][A-Za-z0-9_]*)=["']?psql\b`)
	expandedHead      = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?(?:\s|$)`)
)

// psqlCommandVariables returns the variables a script assigns a psql command
// line without ON_ERROR_STOP, with the line of that assignment: run later as
// $NAME -f file, the command is fixed where it is written.
func psqlCommandVariables(src *patternkit.ShellSource) map[string]int {
	vars := make(map[string]int)
	for _, l := range src.Lines {
		for _, seg := range patternkit.Segments(l.Text) {
			m := psqlCommandAssign.FindStringSubmatch(seg.Text)
			if m == nil {
				continue
			}
			if strings.Contains(seg.Text, "ON_ERROR_STOP") {
				delete(vars, m[1])
				continue
			}
			vars[m[1]] = l.LineAt(seg.Offset)
		}
	}
	return vars
}

// expandedCommand returns NAME of a command that is the expansion $NAME or
// ${NAME} followed by its arguments, after if/then/!.
func expandedCommand(command string) string {
	if m := expandedHead.FindStringSubmatch(patternkit.CommandPrefix.ReplaceAllString(command, "")); m != nil {
		return m[1]
	}
	return ""
}

var (
	capturedAssign = regexp.MustCompile(`^(?:(?:local|export|readonly|declare)\s+)?[A-Za-z_][A-Za-z0-9_]*=\$\(\s*([A-Za-z_][A-Za-z0-9_.-]*)`)
	// remoteCommands talk to a service: their failure is an outage, not an
	// answer such as grep's "no match".
	remoteCommands = map[string]bool{"curl": true, "wget": true, "ssh": true, "scp": true, "http": true, "https": true, "psql": true, "mysql": true, "kubectl": true, "aws": true, "gcloud": true, "nc": true}
)

// droppedStatus reports x=$(cmd) || true (or || :) where cmd calls a service
// or a function of the script.
func droppedStatus(command, fallback string, funcs map[string]patternkit.ShellFunc) bool {
	if word := patternkit.FirstShellWord(fallback); word != "true" && word != ":" {
		return false
	}
	command = patternkit.CommandPrefix.ReplaceAllString(command, "")
	if m := capturedAssign.FindStringSubmatch(command); m != nil {
		_, ownFunction := funcs[m[1]]
		return remoteCommands[m[1]] || ownFunction
	}
	// A sibling script run by its path: x=$("$repo/tools/run.sh" ...).
	return siblingCapture.MatchString(command)
}

var siblingCapture = regexp.MustCompile(`^(?:(?:local|export|readonly|declare)\s+)?[A-Za-z_][A-Za-z0-9_]*=\$\(\s*"?[^\s"()]*\.sh"?(?:\s|\))`)

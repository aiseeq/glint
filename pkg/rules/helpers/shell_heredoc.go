package helpers

import (
	"regexp"
	"strings"
)

// ShellHeredocOpen is the start of a heredoc (<<EOF, <<-'EOF'), not of a
// here string (<<<); group 1 is the terminator.
var ShellHeredocOpen = regexp.MustCompile(`(?:^|[^<])<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// ShellHeredoc is a heredoc of a script: the 0-based indexes of the line
// that opens it and of its terminator (len(lines) when nothing ends it), and
// the text of the opening line before the <<.
type ShellHeredoc struct {
	Open, End  int
	Terminator string
	Before     string
}

// ShellHeredocs returns the heredocs of a script's lines, in order. A
// comment line opens none.
func ShellHeredocs(lines []string) []ShellHeredoc {
	var out []ShellHeredoc
	var open *ShellHeredoc
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case open != nil:
			if EndsShellHeredoc(trimmed, open.Terminator) {
				open.End = i
				out = append(out, *open)
				open = nil
			}
		case strings.HasPrefix(trimmed, "#"):
		default:
			if m := ShellHeredocOpen.FindStringSubmatchIndex(line); m != nil {
				open = &ShellHeredoc{Open: i, End: len(lines), Terminator: line[m[2]:m[3]], Before: line[:m[0]]}
			}
		}
	}
	if open != nil {
		out = append(out, *open)
	}
	return out
}

// EndsShellHeredoc reports the terminator line of a heredoc. A heredoc
// inside a quoted bash -c script ends on a line the closing quote shares:
// PY' 2>/dev/null.
func EndsShellHeredoc(trimmed, terminator string) bool {
	rest, ok := strings.CutPrefix(trimmed, terminator)
	return ok && (rest == "" || strings.ContainsRune(`"')`, rune(rest[0])))
}

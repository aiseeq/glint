package patternkit

import (
	"strings"
)

// ShellStep is one command of a script or a recipe with the physical line it
// starts on and the list operator after it.
type ShellStep struct {
	Text  string
	Sep   string
	Line  int
	Block int
}

// Steps returns the commands of a file in order: every segment of every
// logical line, the last one of a line ended by a newline.
func (src *ShellSource) Steps() []ShellStep {
	var out []ShellStep
	for _, l := range src.Lines {
		for _, seg := range Segments(l.Text) {
			if seg.Trimmed() == "" || strings.HasPrefix(seg.Trimmed(), "#") {
				continue // a comment after a command is no step of its own
			}
			sep := seg.Sep
			if sep == "" {
				sep = "\n"
			}
			out = append(out, ShellStep{Text: seg.Trimmed(), Sep: sep, Line: l.LineAt(seg.Offset), Block: l.block})
		}
	}
	return out
}

package patternkit

import (
	"strings"
)

// ShellStep is one command of a script or a recipe with the physical line it
// starts on and the list operator after it. Source is the index of its
// logical line in Lines and Offset where its text starts in that line.
type ShellStep struct {
	Text   string
	Sep    string
	Line   int
	Block  int
	Source int
	Offset int
}

// Steps returns the commands of a file in order: every segment of every
// logical line, the last one of a line ended by a newline.
func (src *ShellSource) Steps() []ShellStep {
	var out []ShellStep
	for k, l := range src.Lines {
		for _, seg := range Segments(l.Text) {
			if seg.Trimmed() == "" || strings.HasPrefix(seg.Trimmed(), "#") {
				continue // a comment after a command is no step of its own
			}
			sep := seg.Sep
			if sep == "" {
				sep = "\n"
			}
			start := seg.Offset + len(seg.Text) - len(strings.TrimLeft(seg.Text, " \t\n"))
			out = append(out, ShellStep{Text: seg.Trimmed(), Sep: sep, Line: l.LineAt(seg.Offset), Block: l.block, Source: k, Offset: start})
		}
	}
	return out
}

package shellrules

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// insideQuotes reports an offset inside a quoted string of the text.
func insideQuotes(text string, offset int) bool { return patternkit.QuoteAt(text, offset) != 0 }

// insideSingleQuotes reports an offset inside '...', where $ is literal.
func insideSingleQuotes(text string, offset int) bool {
	return patternkit.QuoteAt(text, offset) == '\''
}

// flatSegments splits a command line at every list operator outside quotes,
// inside groups and subshells too: ( a & b & wait ) gives three commands.
func flatSegments(text string) []patternkit.ShellSegment { return patternkit.SplitList(text, true) }

// awkLoop is for ( or while ( of an awk or C program quoted into the script;
// a shell loop takes a word or (( after for and a command after while.
var awkLoop = regexp.MustCompile(`^(?:for|while)\s*\([^(]`)

// shellLoopStart reports a step that opens a shell loop.
func shellLoopStart(text string) bool {
	return loopStart.MatchString(text) && !awkLoop.MatchString(text)
}

// lastPipeCommand returns the first word of the last command of a pipeline
// written in text (inside groups too), "" when text has no pipe.
func lastPipeCommand(text string) string {
	var q patternkit.QuoteScanner
	last := -1
	for i := 0; i < len(text); {
		if n := q.Step(text, i); n > 0 {
			i += n
			continue
		}
		switch {
		case text[i] != '|':
		case i+1 < len(text) && text[i+1] == '|':
			i++ // ||
		case i > 0 && text[i-1] == '>':
			// >| redirection
		default:
			last = i
		}
		i++
	}
	if last < 0 {
		return ""
	}
	fields := strings.Fields(text[last+1:])
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], "({;")
}

// appendReport appends a violation unless it is nil.
func appendReport(list []*core.Violation, v *core.Violation) []*core.Violation {
	if v == nil {
		return list
	}
	return append(list, v)
}

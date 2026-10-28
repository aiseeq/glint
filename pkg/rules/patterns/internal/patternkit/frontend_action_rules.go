package patternkit

import (
	"strings"
)

// StatementAt returns the statement that starts at pos: a block, or a single
// statement up to its ';' or line end.
func (f JsFlat) StatementAt(pos int) (JsSpanRange, bool) {
	for pos < len(f.Code) && (f.Code[pos] == ' ' || f.Code[pos] == '\t') {
		pos++
	}
	if pos >= len(f.Code) {
		return JsSpanRange{}, false
	}
	if f.Code[pos] == '{' {
		end, ok := f.Closing(pos)
		return JsSpanRange{pos + 1, end}, ok
	}
	end := strings.IndexAny(f.Code[pos:], ";\n")
	if end < 0 {
		end = len(f.Code) - pos
	}
	return JsSpanRange{pos, pos + end}, true
}

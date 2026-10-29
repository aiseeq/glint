package patternkit

import (
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// JsIdentifier matches a whole JS identifier.
var JsIdentifier = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

// JsFlat is a jsSource joined into one string per view, for rules that follow
// brackets and statements across lines. Offsets are the same in both views.
type JsFlat struct {
	Code string
	Text string
	// starts holds the offset of every line's first byte.
	starts []int
}

func NewJSFlat(ctx *core.FileContext) JsFlat {
	src := NewJSSource(ctx)
	f := JsFlat{Code: strings.Join(src.Code, "\n"), Text: strings.Join(src.Text, "\n")}
	offset := 0
	for _, line := range src.Code {
		f.starts = append(f.starts, offset)
		offset += len(line) + 1
	}
	return f
}

// Line returns the 1-based line of the offset.
func (f JsFlat) Line(pos int) int {
	return sort.Search(len(f.starts), func(i int) bool { return f.starts[i] > pos })
}

// Closing returns the offset of the bracket that closes the '(', '[' or '{'
// at open. All three kinds nest together.
func (f JsFlat) Closing(open int) (int, bool) {
	depth := 0
	for i := open; i < len(f.Code); i++ {
		switch f.Code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// EnclosingBrace returns the offset of the innermost '{' whose block holds
// pos, or -1 at the top level of the file.
func (f JsFlat) EnclosingBrace(pos int) int {
	depth := 0
	for i := pos - 1; i >= 0; i-- {
		switch f.Code[i] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

// JsSpanRange is a half-open range of offsets.
type JsSpanRange struct{ Start, End int }

// Items splits the contents of the bracket pair at (open, close) at its
// top-level commas: the arguments of a call, the elements of an array. An
// empty item after a trailing comma is dropped.
func (f JsFlat) Items(open, close int) []JsSpanRange {
	var out []JsSpanRange
	depth, start := 0, open+1
	for i := open + 1; i < close; i++ {
		switch f.Code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, JsSpanRange{start, i})
				start = i + 1
			}
		}
	}
	if strings.TrimSpace(f.Code[start:close]) != "" {
		out = append(out, JsSpanRange{start, close})
	}
	return out
}

// CallArgs returns the arguments of the call whose '(' is at open.
func (f JsFlat) CallArgs(open int) []JsSpanRange {
	end, ok := f.Closing(open)
	if !ok {
		return nil
	}
	return f.Items(open, end)
}

// ArrayIdents returns the bare identifiers among the elements of the array
// literal that the span holds, in source order, each with the offset where it
// starts. A span that is not an array literal yields nothing.
func (f JsFlat) ArrayIdents(span JsSpanRange) []jsIdentAt {
	text := f.Code[span.Start:span.End]
	trimmed := strings.TrimSpace(text)
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return nil
	}
	open := span.Start + strings.Index(text, "[")
	close := span.Start + strings.LastIndex(text, "]")
	var idents []jsIdentAt
	seen := make(map[string]bool)
	for _, item := range f.Items(open, close) {
		raw := f.Code[item.Start:item.End]
		name := strings.TrimSpace(raw)
		if !JsIdentifier.MatchString(name) || seen[name] {
			continue
		}
		seen[name] = true
		idents = append(idents, jsIdentAt{Name: name, Pos: item.Start + strings.Index(raw, name)})
	}
	return idents
}

// jsIdentAt is an identifier and its offset.
type jsIdentAt struct {
	Name string
	Pos  int
}

// Header returns the code before the '{' at brace back to the start of its
// statement, and the offset where it starts: "if (ok)", "catch (error)",
// "async load(id: string): Promise<T>", "() =>". The scan stops at a ';', a
// '{' or '}' of the enclosing level, an unclosed '(' (a callback's call) and a
// line break outside brackets.
func (f JsFlat) Header(brace int) (string, int) {
	depth := 0
	for i := brace - 1; i >= 0; i-- {
		c := f.Code[i]
		switch {
		case c == ')' || c == ']' || (c == '}' && depth > 0):
			depth++
		case c == '(' || c == '[' || (c == '{' && depth > 0):
			if depth == 0 {
				return strings.TrimSpace(f.Code[i+1 : brace]), i + 1
			}
			depth--
		case depth == 0 && (c == ';' || c == '{' || c == '}' || c == '\n'):
			// A line break inside the header ("foo(\n a\n): T {") sits in brackets.
			return strings.TrimSpace(f.Code[i+1 : brace]), i + 1
		}
	}
	return strings.TrimSpace(f.Code[:brace]), 0
}

var (
	JsControlHeader = regexp.MustCompile(`^(?:else\b|try$|finally$|do$|(?:if|for|while|switch|catch|with)\s*\()`)
	jsIfHeader      = regexp.MustCompile(`^(?:else\s+)?if\s*\(`)
	jsFuncHeader    = regexp.MustCompile(`(?s)(?:=>|\)\s*(?::[^=]*)?)$`)
	jsNamedFunction = regexp.MustCompile(`\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)`)
	jsMethodHeader  = regexp.MustCompile(`^(?:(?:export|default|public|private|protected|static|async|override|get|set)\s+)*([A-Za-z_$][\w$]*)\s*(?:<[^()]*>)?\s*\(`)
	jsArrowBinding  = regexp.MustCompile(`(?s)^(?:(?:export|const|let|var|public|private|protected|static|readonly)\s+)*([A-Za-z_$][\w$]*)\s*(?::[^=]*)?[=:]\s*(?:async\b\s*)?(?:\(.*\)|[A-Za-z_$][\w$]*)\s*(?::.*)?=>$`)
)

// JsFunc is a function body found around a position.
type JsFunc struct {
	Brace int    // offset of the body's '{'
	Start int    // offset where the header starts
	Name  string // "" for an anonymous function
}

// EnclosingFunction returns the innermost function whose body holds pos.
func (f JsFlat) EnclosingFunction(pos int) (JsFunc, bool) {
	for brace := f.EnclosingBrace(pos); brace >= 0; brace = f.EnclosingBrace(brace) {
		head, start := f.Header(brace)
		if JsControlHeader.MatchString(head) || !jsFuncHeader.MatchString(head) {
			continue
		}
		fn := JsFunc{Brace: brace, Start: start}
		for _, re := range []*regexp.Regexp{jsNamedFunction, jsMethodHeader, jsArrowBinding} {
			if m := re.FindStringSubmatch(head); m != nil {
				fn.Name = m[1]
				break
			}
		}
		return fn, true
	}
	return JsFunc{}, false
}

// InsideNamedFunction reports whether pos is inside the named enclosing function.
func (f JsFlat) InsideNamedFunction(pos int, name string) bool {
	for pos >= 0 {
		fn, ok := f.EnclosingFunction(pos)
		if !ok {
			return false
		}
		if fn.Name == name {
			return true
		}
		if fn.Start >= pos {
			return false
		}
		pos = fn.Start
	}
	return false
}

// IfCondition returns the span of the condition of the "if (...)" header that
// opens the block at brace.
func (f JsFlat) IfCondition(brace int) (JsSpanRange, bool) {
	head, start := f.Header(brace)
	if !jsIfHeader.MatchString(head) {
		return JsSpanRange{}, false
	}
	return f.Parenthesized(start, brace)
}

// Parenthesized returns the inside of the first '(' ... ')' pair that opens
// in [from, to).
func (f JsFlat) Parenthesized(from, to int) (JsSpanRange, bool) {
	open := strings.IndexByte(f.Code[from:to], '(')
	if open < 0 {
		return JsSpanRange{}, false
	}
	end, ok := f.Closing(from + open)
	if !ok {
		return JsSpanRange{}, false
	}
	return JsSpanRange{from + open + 1, end}, true
}

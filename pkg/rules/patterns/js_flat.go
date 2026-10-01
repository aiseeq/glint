package patterns

import (
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// jsIdentifier matches a whole JS identifier.
var jsIdentifier = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

// jsFlat is a jsSource joined into one string per view, for rules that follow
// brackets and statements across lines. Offsets are the same in both views.
type jsFlat struct {
	code string
	text string
	// starts holds the offset of every line's first byte.
	starts []int
}

func newJSFlat(ctx *core.FileContext) jsFlat {
	src := newJSSource(ctx)
	f := jsFlat{code: strings.Join(src.code, "\n"), text: strings.Join(src.text, "\n")}
	offset := 0
	for _, line := range src.code {
		f.starts = append(f.starts, offset)
		offset += len(line) + 1
	}
	return f
}

// line returns the 1-based line of the offset.
func (f jsFlat) line(pos int) int {
	return sort.Search(len(f.starts), func(i int) bool { return f.starts[i] > pos })
}

// closing returns the offset of the bracket that closes the '(', '[' or '{'
// at open. All three kinds nest together.
func (f jsFlat) closing(open int) (int, bool) {
	depth := 0
	for i := open; i < len(f.code); i++ {
		switch f.code[i] {
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

// enclosingBrace returns the offset of the innermost '{' whose block holds
// pos, or -1 at the top level of the file.
func (f jsFlat) enclosingBrace(pos int) int {
	depth := 0
	for i := pos - 1; i >= 0; i-- {
		switch f.code[i] {
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

// jsSpanRange is a half-open range of offsets.
type jsSpanRange struct{ start, end int }

// items splits the contents of the bracket pair at (open, close) at its
// top-level commas: the arguments of a call, the elements of an array. An
// empty item after a trailing comma is dropped.
func (f jsFlat) items(open, close int) []jsSpanRange {
	var out []jsSpanRange
	depth, start := 0, open+1
	for i := open + 1; i < close; i++ {
		switch f.code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, jsSpanRange{start, i})
				start = i + 1
			}
		}
	}
	if strings.TrimSpace(f.code[start:close]) != "" {
		out = append(out, jsSpanRange{start, close})
	}
	return out
}

// callArgs returns the arguments of the call whose '(' is at open.
func (f jsFlat) callArgs(open int) []jsSpanRange {
	end, ok := f.closing(open)
	if !ok {
		return nil
	}
	return f.items(open, end)
}

// arrayIdents returns the bare identifiers among the elements of the array
// literal that the span holds, in source order, each with the offset where it
// starts. A span that is not an array literal yields nothing.
func (f jsFlat) arrayIdents(span jsSpanRange) []jsIdentAt {
	text := f.code[span.start:span.end]
	trimmed := strings.TrimSpace(text)
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return nil
	}
	open := span.start + strings.Index(text, "[")
	close := span.start + strings.LastIndex(text, "]")
	var idents []jsIdentAt
	seen := make(map[string]bool)
	for _, item := range f.items(open, close) {
		raw := f.code[item.start:item.end]
		name := strings.TrimSpace(raw)
		if !jsIdentifier.MatchString(name) || seen[name] {
			continue
		}
		seen[name] = true
		idents = append(idents, jsIdentAt{name: name, pos: item.start + strings.Index(raw, name)})
	}
	return idents
}

// jsIdentAt is an identifier and its offset.
type jsIdentAt struct {
	name string
	pos  int
}

// header returns the code before the '{' at brace back to the start of its
// statement, and the offset where it starts: "if (ok)", "catch (error)",
// "async load(id: string): Promise<T>", "() =>". The scan stops at a ';', a
// '{' or '}' of the enclosing level, an unclosed '(' (a callback's call) and a
// line break outside brackets.
func (f jsFlat) header(brace int) (string, int) {
	depth := 0
	for i := brace - 1; i >= 0; i-- {
		c := f.code[i]
		switch {
		case c == ')' || c == ']' || (c == '}' && depth > 0):
			depth++
		case c == '(' || c == '[' || (c == '{' && depth > 0):
			if depth == 0 {
				return strings.TrimSpace(f.code[i+1 : brace]), i + 1
			}
			depth--
		case depth == 0 && (c == ';' || c == '{' || c == '}' || c == '\n'):
			// A line break inside the header ("foo(\n a\n): T {") sits in brackets.
			return strings.TrimSpace(f.code[i+1 : brace]), i + 1
		}
	}
	return strings.TrimSpace(f.code[:brace]), 0
}

var (
	jsControlHeader = regexp.MustCompile(`^(?:else\b|try$|finally$|do$|(?:if|for|while|switch|catch|with)\s*\()`)
	jsIfHeader      = regexp.MustCompile(`^(?:else\s+)?if\s*\(`)
	jsFuncHeader    = regexp.MustCompile(`(?s)(?:=>|\)\s*(?::[^=]*)?)$`)
	jsNamedFunction = regexp.MustCompile(`\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)`)
	jsMethodHeader  = regexp.MustCompile(`^(?:(?:export|default|public|private|protected|static|async|override|get|set)\s+)*([A-Za-z_$][\w$]*)\s*(?:<[^()]*>)?\s*\(`)
	jsArrowBinding  = regexp.MustCompile(`(?s)^(?:(?:export|const|let|var|public|private|protected|static|readonly)\s+)*([A-Za-z_$][\w$]*)\s*(?::[^=]*)?[=:]\s*(?:async\b\s*)?(?:\(.*\)|[A-Za-z_$][\w$]*)\s*(?::.*)?=>$`)
)

// jsFunc is a function body found around a position.
type jsFunc struct {
	brace int    // offset of the body's '{'
	start int    // offset where the header starts
	name  string // "" for an anonymous function
}

// enclosingFunction returns the innermost function whose body holds pos.
func (f jsFlat) enclosingFunction(pos int) (jsFunc, bool) {
	for brace := f.enclosingBrace(pos); brace >= 0; brace = f.enclosingBrace(brace) {
		head, start := f.header(brace)
		if jsControlHeader.MatchString(head) || !jsFuncHeader.MatchString(head) {
			continue
		}
		fn := jsFunc{brace: brace, start: start}
		for _, re := range []*regexp.Regexp{jsNamedFunction, jsMethodHeader, jsArrowBinding} {
			if m := re.FindStringSubmatch(head); m != nil {
				fn.name = m[1]
				break
			}
		}
		return fn, true
	}
	return jsFunc{}, false
}

// ifCondition returns the span of the condition of the "if (...)" header that
// opens the block at brace.
func (f jsFlat) ifCondition(brace int) (jsSpanRange, bool) {
	head, start := f.header(brace)
	if !jsIfHeader.MatchString(head) {
		return jsSpanRange{}, false
	}
	return f.parenthesized(start, brace)
}

// parenthesized returns the inside of the first '(' ... ')' pair that opens
// in [from, to).
func (f jsFlat) parenthesized(from, to int) (jsSpanRange, bool) {
	open := strings.IndexByte(f.code[from:to], '(')
	if open < 0 {
		return jsSpanRange{}, false
	}
	end, ok := f.closing(from + open)
	if !ok {
		return jsSpanRange{}, false
	}
	return jsSpanRange{from + open + 1, end}, true
}

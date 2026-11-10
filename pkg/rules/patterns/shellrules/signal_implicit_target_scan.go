package shellrules

import (
	"strings"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// signalInput is one line the scanner reads: a physical line of a script, a
// recipe line of a make file or a line of a Go string.
type signalInput struct {
	text   string
	lineAt func(offset int) int // the 1-based source line of an offset
	next   string               // the physical line after it, "" at the end
}

// signalPiece is where an input begins in a logical line.
type signalPiece struct{ start, input int }

// signalHeredoc is a level of here-documents opened by one command line;
// executed is a body that a shell runs, not data.
type signalHeredoc struct {
	delims   []patternkit.HeredocRedirect
	executed bool
}

// signalScanner reads shell lines once. It joins a command written over
// several lines (a trailing backslash, | or &&, a quote left open), drops
// comments, and skips the bodies of here-documents that are data. The quote
// state carries over to the next line, so each byte is read once.
type signalScanner struct {
	inputs   []signalInput
	make     bool // each input is a whole command line: make runs each alone
	quote    signalQuote
	building bool
	buf      strings.Builder
	pieces   []signalPiece
	last     int
	heredocs []signalHeredoc
	found    []int
}

// scanSignalLines returns the source line of each command line that signals
// the parent, every process or the caller's process group.
func scanSignalLines(inputs []signalInput, makeRecipes bool) []int {
	s := &signalScanner{inputs: inputs, make: makeRecipes}
	for j, in := range inputs {
		if len(s.heredocs) > 0 && s.closesHeredoc(in.text) {
			s.flush()
			continue
		}
		if top := len(s.heredocs) - 1; top >= 0 && !s.heredocs[top].executed {
			continue
		}
		s.feed(j, in.text)
	}
	s.flush()
	return s.found
}

// closesHeredoc ends the here-document whose delimiter the line is; a line
// that ends an outer one ends the ones opened inside it too.
func (s *signalScanner) closesHeredoc(text string) bool {
	text = strings.TrimSuffix(text, "\r")
	for k, level := range s.heredocs {
		d := level.delims[0]
		body := text
		if d.StripTabs {
			body = strings.TrimLeft(body, "\t")
		}
		if body != d.Word {
			continue
		}
		if len(level.delims) > 1 {
			s.heredocs[k].delims = level.delims[1:]
			s.heredocs = s.heredocs[:k+1]
		} else {
			s.heredocs = s.heredocs[:k]
		}
		return true
	}
	return false
}

func (s *signalScanner) feed(j int, text string) {
	switch {
	case !s.building:
		if t := strings.TrimSpace(text); t == "" || strings.HasPrefix(t, "#") {
			return
		}
		s.building = true
	case s.quote.open != 0:
		s.buf.WriteByte('\n')
	default:
		s.buf.WriteByte(' ')
	}
	kept, backslash, operator := s.read(text)
	s.pieces = append(s.pieces, signalPiece{start: s.buf.Len(), input: j})
	s.buf.WriteString(kept)
	s.last = j
	if !s.make && (backslash || operator || s.quote.open != 0) {
		return
	}
	s.flush()
}

// read returns the line without its comment, and whether it goes on on the
// next line: after a trailing backslash, or after a | or && outside quotes.
// The quote open at its end stays in the scanner.
func (s *signalScanner) read(text string) (kept string, backslash, operator bool) {
	lastSyntax := -1
	for i := 0; i < len(text); {
		n := s.quote.Step(text, i)
		if n == 2 && i+1 == len(text) {
			return text[:i], true, false
		}
		if n > 0 {
			i += n
			continue
		}
		if text[i] == '#' && (i == 0 || text[i-1] == ' ' || text[i-1] == '\t') {
			text = text[:i]
			break
		}
		if text[i] != ' ' && text[i] != '\t' && text[i] != '\r' {
			lastSyntax = i
		}
		i++
	}
	trimmed := strings.TrimRight(text, " \t\r")
	operator = s.quote.open == 0 && lastSyntax == len(trimmed)-1 &&
		(strings.HasSuffix(trimmed, "|") || strings.HasSuffix(trimmed, "&&"))
	return text, false, operator
}

func (s *signalScanner) flush() {
	if !s.building {
		return
	}
	text := s.buf.String()
	if delims := patternkit.HeredocDelimiters(text); len(delims) > 0 {
		s.heredocs = append(s.heredocs, signalHeredoc{
			delims:   delims,
			executed: shellHeredocFeedsInterpreter(text) || strings.HasPrefix(strings.TrimSpace(s.inputs[s.last].next), "#!"),
		})
	}
	for _, command := range commandsInScript(text, 0, 0) {
		if badKill(command.text) {
			s.found = append(s.found, s.lineAt(command.offset))
			break
		}
	}
	s.building = false
	s.quote = signalQuote{}
	s.buf.Reset()
	s.pieces = s.pieces[:0]
}

func (s *signalScanner) lineAt(offset int) int {
	p := s.pieces[0]
	for _, next := range s.pieces[1:] {
		if next.start > offset {
			break
		}
		p = next
	}
	return s.inputs[p.input].lineAt(offset - p.start)
}

// signalQuote tracks the quote open in shell text: ', " or the ANSI-C
// $'…', in which a backslash escapes the next byte, \' included.
type signalQuote struct{ open byte }

const ansiCQuote = '$'

// Step returns how many bytes at i are quoted or escaped and so are no
// shell syntax; 0 when text[i] is an unquoted byte to look at.
func (q *signalQuote) Step(text string, i int) int {
	c := text[i]
	switch q.open {
	case 0:
	case '\'':
		if c == '\'' {
			q.open = 0
		}
		return 1
	default:
		if c == '\\' {
			return 2
		}
		if c == '"' && q.open == '"' || c == '\'' && q.open == ansiCQuote {
			q.open = 0
		}
		return 1
	}
	switch {
	case c == '\\':
		return 2
	case c == '$' && i+1 < len(text) && text[i+1] == '\'':
		q.open = ansiCQuote
		return 2
	case c == '\'' || c == '"':
		q.open = c
		return 1
	}
	return 0
}

// withoutComment cuts a comment that starts outside quotes.
func withoutComment(text string) string {
	kept, _, _ := (&signalScanner{}).read(text)
	return strings.TrimRight(kept, " \t")
}

package core

import (
	"regexp"
	"strings"
)

// hashComments returns the '#' comments of lines read one by one
// (hashCommentPart): make files, env templates, nginx configurations.
func hashComments(lines []string) []lineComment {
	var comments []lineComment
	for i, line := range lines {
		if comment := hashCommentPart(line); comment != "" {
			code := strings.TrimSpace(line[:len(line)-len(comment)]) != ""
			comments = append(comments, lineComment{Line: i + 1, Text: comment, Code: code})
		}
	}
	return comments
}

// shellWordBreak are the characters after which a '#' starts a shell word,
// and with it a comment.
const shellWordBreak = " \t;&|()"

// heredoc is a here-document whose body is still to come: the line that
// ends it, and whether leading tabs are stripped before the comparison
// (<<-).
type heredoc struct {
	delim     string
	stripTabs bool
}

// shellScanner reads the comments of a shell script. A '#' starts one at
// the start of a word, outside quotes; '…', "…" and $'…' span lines. The
// body of a here-document is read as a script of its own, as the shell
// rules read it (cat <<EOF | bash, ssh host <<EOF, a script written to a
// file): what it leaves open ends with its delimiter.
type shellScanner struct {
	quote    string // the open quote: ', " or $', "" when none
	pending  []heredoc
	bodies   []heredoc     // the here-documents being read, the current one first
	inner    *shellScanner // the reader of the current body
	comments []lineComment
}

func shellComments(lines []string) []lineComment {
	s := &shellScanner{}
	for i, line := range lines {
		s.scanLine(i+1, line)
	}
	return s.comments
}

func (s *shellScanner) scanLine(n int, line string) {
	if len(s.bodies) > 0 {
		s.scanBody(n, line)
		return
	}
	code := s.quote != ""
	i := 0
	if s.quote != "" {
		i = s.closeQuote(line, 0)
	}
	arith := 0 // the open parentheses of an arithmetic expression, (( included
	for i < len(line) && s.quote == "" {
		c := line[i]
		switch {
		case c == '#' && (i == 0 || strings.IndexByte(shellWordBreak, line[i-1]) >= 0):
			s.comments = append(s.comments, lineComment{Line: n, Text: line[i:], Code: code})
			i = len(line)
			continue
		case c == ' ' || c == '\t':
			i++
			continue
		}
		code = true
		switch {
		case c == '\\':
			i += 2
		case c == '\'' || c == '"':
			s.quote = string(c)
			i = s.closeQuote(line, i+1)
		case c == '$' && strings.HasPrefix(line[i:], "$'"):
			s.quote = "$'"
			i = s.closeQuote(line, i+2)
		case strings.HasPrefix(line[i:], "(("):
			arith += 2
			i += 2
		case arith > 0 && c == '(':
			arith++
			i++
		case arith > 0 && c == ')':
			arith--
			i++
		case arith == 0 && strings.HasPrefix(line[i:], "<<"):
			i = s.openHeredoc(line, i+2)
		default:
			i++
		}
	}
	s.bodies = append(s.bodies, s.pending...)
	s.pending = nil
}

// scanBody reads a line of the current here-document as script: its
// delimiter ends it, whatever the body left open.
func (s *shellScanner) scanBody(n int, line string) {
	body := s.bodies[0]
	end := line
	if body.stripTabs {
		end = strings.TrimLeft(line, "\t")
	}
	if end == body.delim {
		s.bodies, s.inner = s.bodies[1:], nil
		return
	}
	if s.inner == nil {
		s.inner = &shellScanner{}
	}
	s.inner.scanLine(n, line)
	s.comments = append(s.comments, s.inner.comments...)
	s.inner.comments = s.inner.comments[:0]
}

// closeQuote returns where the code after the open quote starts, len(line)
// when the quote goes on to the next line. A backslash escapes in "…" and
// $'…', not in '…'.
func (s *shellScanner) closeQuote(line string, i int) int {
	closer := s.quote[len(s.quote)-1]
	for i < len(line) {
		switch {
		case line[i] == '\\' && s.quote != "'":
			i += 2
			continue
		case line[i] == closer:
			s.quote = ""
			return i + 1
		}
		i++
	}
	return len(line)
}

// heredocWord matches the delimiter word of a here-document after <<: a
// quoted word or a bare one, a backslash quoting it too.
var heredocWord = regexp.MustCompile(`^(-?)[ \t]*(?:'([^']*)'|"([^"]*)"|\\?([A-Za-z0-9_.-]+))`)

// openHeredoc reads the delimiter of a here-document whose << ends before i
// and returns where the code after it starts. Its body starts on the next
// line.
func (s *shellScanner) openHeredoc(line string, i int) int {
	m := heredocWord.FindStringSubmatch(line[i:])
	if m == nil {
		return i
	}
	s.pending = append(s.pending, heredoc{delim: m[2] + m[3] + m[4], stripTabs: m[1] == "-"})
	return i + len(m[0])
}

// dockerHeredoc matches a word of a Dockerfile instruction that opens a
// here-document (RUN <<EOF, COPY <<-"EOF" /dst), as BuildKit reads one.
var dockerHeredoc = regexp.MustCompile(`^[0-9]*<<(-?)(?:'([^']+)'|"([^"]+)"|([^<'"]+))$`)

// dockerfileComments returns the comments of a Dockerfile: a line whose
// first character past the indentation is '#'. A '#' further on is an
// argument of the instruction, and a here-document's body is its text.
func dockerfileComments(lines []string) []lineComment {
	var comments []lineComment
	var bodies []heredoc
	for i, line := range lines {
		if len(bodies) > 0 {
			end := line
			if bodies[0].stripTabs {
				end = strings.TrimLeft(line, "\t")
			}
			if end == bodies[0].delim {
				bodies = bodies[1:]
			}
			continue
		}
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			comments = append(comments, lineComment{Line: i + 1, Text: trimmed})
			continue
		}
		for word := range strings.FieldsSeq(line) {
			if m := dockerHeredoc.FindStringSubmatch(word); m != nil {
				bodies = append(bodies, heredoc{delim: m[2] + m[3] + m[4], stripTabs: m[1] == "-"})
			}
		}
	}
	return comments
}

// yamlScanner reads the comments of a YAML file: a '#' after a space or at
// the start of a line, outside a quoted scalar and outside the body of a
// block scalar (| or >). A quote opens a scalar only where a scalar starts:
// in "a: don't" the apostrophe is text.
type yamlScanner struct {
	quote byte // the open quote of a quoted scalar spanning lines, 0 when none
	// block is the indentation of the line that opened a block scalar
	// whose body may follow, -1 when none; bodyIndent the indentation of
	// its body once its first line is read, 0 before.
	block      int
	bodyIndent int
	comments   []lineComment
}

func yamlComments(lines []string) []lineComment {
	s := &yamlScanner{block: -1}
	for i, line := range lines {
		s.scanLine(i+1, line)
	}
	return s.comments
}

func (s *yamlScanner) scanLine(n int, line string) {
	indent := len(line) - len(strings.TrimLeft(line, " "))
	if s.inBlockBody(line, indent) {
		return
	}
	code := s.quote != 0
	i := 0
	if s.quote != 0 {
		i = s.closeQuote(line, 0)
	}
	// start: a scalar may start here; flow: the depth of the flow
	// collections open on the line.
	start, flow := true, 0
	for i < len(line) && s.quote == 0 {
		switch c := line[i]; {
		case c == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			s.comments = append(s.comments, lineComment{Line: n, Text: line[i:], Code: code})
			return
		case c == ' ' || c == '\t':
			i++
		default:
			code = true
			i, start = s.token(line, i, indent, start, &flow)
		}
	}
}

// inBlockBody reports whether the line, of the given indentation, is part
// of the body of an open block scalar, and ends the scalar at the first line
// that is not.
func (s *yamlScanner) inBlockBody(line string, indent int) bool {
	if s.block < 0 {
		return false
	}
	blank := strings.TrimSpace(line) == ""
	if s.bodyIndent == 0 && !blank && indent > s.block {
		s.bodyIndent = indent
	}
	if blank || s.bodyIndent > 0 && indent >= s.bodyIndent {
		return true
	}
	s.block, s.bodyIndent = -1, 0
	return false
}

// token reads the token of code at i of a line of the given indentation and
// returns where the next starts and whether a scalar may start there.
func (s *yamlScanner) token(line string, i, indent int, start bool, flow *int) (int, bool) {
	c := line[i]
	next := byte(' ')
	if i+1 < len(line) {
		next = line[i+1]
	}
	switch {
	case start && (c == '\'' || c == '"'):
		s.quote = c
		return s.closeQuote(line, i+1), false
	case start && (c == '|' || c == '>'):
		s.block = indent
	case start && (c == '&' || c == '!'):
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		return i, true
	case start && (c == '[' || c == '{'):
		*flow++
	case *flow > 0 && (c == ']' || c == '}'):
		*flow--
	case *flow > 0 && c == ',' || c == ':' && (next == ' ' || next == '\t'):
		return i + 1, true
	case start && (c == '-' || c == '?') && (next == ' ' || next == '\t'):
	default:
		return i + 1, false
	}
	return i + 1, start
}

// closeQuote returns where the code after the open quoted scalar starts,
// len(line) when it goes on to the next line. "…" escapes with a backslash,
// '…' doubles its quote.
func (s *yamlScanner) closeQuote(line string, i int) int {
	for i < len(line) {
		switch {
		case s.quote == '"' && line[i] == '\\':
			i += 2
			continue
		case line[i] == s.quote && s.quote == '\'' && i+1 < len(line) && line[i+1] == '\'':
			i += 2
			continue
		case line[i] == s.quote:
			s.quote = 0
			return i + 1
		}
		i++
	}
	return len(line)
}

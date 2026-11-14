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

// regionLines records, line by line, the embedded region of text (a
// multi-line quote, a heredoc body, a block scalar) a line ends in, 0 for the
// text of the file itself. Each region has an id of its own.
type regionLines struct {
	ends []int
	last int
}

// open returns the id of a new region.
func (r *regionLines) open() int {
	r.last++
	return r.last
}

// record adds the region the next line ends in.
func (r *regionLines) record(end int) {
	r.ends = append(r.ends, end)
}

// confine sets Confined on the comments of a region whose next line is not
// wholly in it: a marker there covers its own line only, not the line after
// the closing quote, the terminator or the end of the block. A region once
// closed never opens again (another one gets another id), so the next line is
// wholly in the region of a comment when it ends in it.
func (r *regionLines) confine(comments []lineComment) {
	for i := range comments {
		c := &comments[i]
		next := c.Line // the index of the next line
		c.Confined = c.Region != 0 && (next >= len(r.ends) || r.ends[next] != c.Region)
	}
}

// embed reads text of line n, embedded text of the given region, with
// inner and adds its comments to out as comments of the region; code is set
// when the line holds code before the text.
func embed(inner *shellScanner, n int, text string, region int, code bool, out *[]lineComment) {
	inner.scanLine(n, text)
	for _, c := range inner.comments {
		c.Region, c.Code = region, c.Code || code
		*out = append(*out, c)
	}
	inner.comments = inner.comments[:0]
}

// shellScanner reads the comments of a shell script. A '#' starts one at
// the start of a word, outside quotes; '…', "…" and $'…' span lines. The
// text of a quote that spans lines and the body of a here-document are code
// too (ssh host "…", bash -c '…', cat <<EOF | bash, a script written to a
// file) and are read as script by an inner reader, line by line: a quote
// opened there ends with its line, so an apostrophe of text does not hide
// what follows. Such text is a region (regionLines) its markers do not
// leave.
type shellScanner struct {
	quote   string // the open quote: ', " or $', "" when none
	pending []heredoc
	bodies  []heredoc // the here-documents being read, the current one first
	// inner reads the embedded text being read: the open quote or the
	// current body; region is its id, 0 outside one.
	inner  *shellScanner
	region int
	// local is set on an inner reader: its quotes end with the line, and the
	// text it reads is the region of its outer reader.
	local    bool
	lines    regionLines
	comments []lineComment
}

func shellComments(lines []string) []lineComment {
	s := &shellScanner{}
	for i, line := range lines {
		s.scanLine(i+1, line)
	}
	s.lines.confine(s.comments)
	return s.comments
}

func (s *shellScanner) scanLine(n int, line string) {
	if len(s.bodies) > 0 {
		s.scanBody(n, line)
	} else {
		s.scanCode(n, line)
	}
	s.lines.record(s.region)
}

// enter starts a new region of embedded text and its reader.
func (s *shellScanner) enter() {
	s.region, s.inner = s.lines.open(), &shellScanner{local: true}
}

func (s *shellScanner) scanCode(n int, line string) {
	code := s.quote != ""
	i := 0
	if s.quote != "" {
		i = s.continueQuote(n, line)
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
			i = s.openQuote(n, line, i+1, string(c))
		case c == '$' && strings.HasPrefix(line[i:], "$'"):
			i = s.openQuote(n, line, i+2, "$'")
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
	if s.local {
		s.quote = "" // a quote in embedded text ends with its line
	}
	// The bodies start on the line after the one where the open quote, if
	// any, closes.
	if len(s.pending) > 0 && s.quote == "" {
		s.bodies, s.pending = append(s.bodies, s.pending...), nil
		s.enter()
	}
}

// openQuote opens the quote whose text starts at i and returns where the
// code after it starts. The text of one that goes on to the next line is
// read as script: the line holds code before it.
func (s *shellScanner) openQuote(n int, line string, i int, quote string) int {
	s.quote = quote
	end := s.closeQuote(line, i)
	if s.quote != "" && !s.local {
		s.enter()
		embed(s.inner, n, line[i:], s.region, true, &s.comments)
	}
	return end
}

// continueQuote reads the text of the open quote on a line it goes on to
// and returns where the code after the closing quote starts.
func (s *shellScanner) continueQuote(n int, line string) int {
	end := s.closeQuote(line, 0)
	if s.quote != "" {
		embed(s.inner, n, line, s.region, false, &s.comments)
		return end
	}
	embed(s.inner, n, line[:end-1], s.region, false, &s.comments)
	s.region, s.inner = 0, nil
	return end
}

// scanBody reads a line of the current here-document as script: its
// delimiter ends it, whatever the body left open.
func (s *shellScanner) scanBody(n int, line string) {
	body := s.bodies[0]
	end := line
	if body.stripTabs {
		end = strings.TrimLeft(line, "\t")
	}
	if end != body.delim {
		embed(s.inner, n, line, s.region, false, &s.comments)
		return
	}
	s.bodies, s.region, s.inner = s.bodies[1:], 0, nil
	if len(s.bodies) > 0 {
		s.enter()
	}
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

// dockerfileScanner reads the comments of a Dockerfile: a line whose first
// character past the indentation is '#'. A '#' further on is an argument of
// the instruction. The body of a here-document of RUN is a script, read as
// shell, a region its markers do not leave; that of another instruction
// (COPY <<EOF /dst) is data.
type dockerfileScanner struct {
	bodies []heredoc
	script bool // the bodies are scripts of RUN
	inner  *shellScanner
	region int
	lines  regionLines
	// comments are those read so far.
	comments []lineComment
}

func dockerfileComments(lines []string) []lineComment {
	s := &dockerfileScanner{}
	for i, line := range lines {
		s.scanLine(i+1, line)
		s.lines.record(s.region)
	}
	s.lines.confine(s.comments)
	return s.comments
}

func (s *dockerfileScanner) scanLine(n int, line string) {
	if len(s.bodies) > 0 {
		s.scanBody(n, line)
		return
	}
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "#") {
		s.comments = append(s.comments, lineComment{Line: n, Text: trimmed})
		return
	}
	fields := strings.Fields(line)
	for _, word := range fields {
		if m := dockerHeredoc.FindStringSubmatch(word); m != nil {
			s.bodies = append(s.bodies, heredoc{delim: m[2] + m[3] + m[4], stripTabs: m[1] == "-"})
		}
	}
	s.script = len(s.bodies) > 0 && strings.EqualFold(fields[0], "RUN")
	s.enter()
}

// enter starts the region of the current body when it is a script.
func (s *dockerfileScanner) enter() {
	s.region, s.inner = 0, nil
	if s.script {
		s.region, s.inner = s.lines.open(), &shellScanner{local: true}
	}
}

func (s *dockerfileScanner) scanBody(n int, line string) {
	end := line
	if s.bodies[0].stripTabs {
		end = strings.TrimLeft(line, "\t")
	}
	if end == s.bodies[0].delim {
		s.bodies = s.bodies[1:]
		s.script = s.script && len(s.bodies) > 0
		s.enter()
		return
	}
	if s.script {
		embed(s.inner, n, line, s.region, false, &s.comments)
	}
}

// yamlScanner reads the comments of a YAML file: a '#' after a space or at
// the start of a line, outside a quoted scalar. A quote opens a scalar only
// where a scalar starts: in "a: don't" the apostrophe is text. The body of a
// block scalar (| or >) is mostly a script (run: |) and is read as shell, a
// region its markers do not leave.
type yamlScanner struct {
	quote byte // the open quote of a quoted scalar spanning lines, 0 when none
	// block is the indentation of the line that opened a block scalar
	// whose body may follow, -1 when none; bodyIndent the indentation of
	// its body once its first line is read, 0 before.
	block      int
	bodyIndent int
	// inner reads the body of the block scalar, region is its id, 0
	// outside one.
	inner    *shellScanner
	region   int
	lines    regionLines
	comments []lineComment
}

func yamlComments(lines []string) []lineComment {
	s := &yamlScanner{block: -1}
	for i, line := range lines {
		s.scanLine(i+1, line)
		s.lines.record(s.region)
	}
	s.lines.confine(s.comments)
	return s.comments
}

func (s *yamlScanner) scanLine(n int, line string) {
	indent := len(line) - len(strings.TrimLeft(line, " "))
	if s.inBlockBody(line, indent) {
		if s.inner == nil {
			s.region, s.inner = s.lines.open(), &shellScanner{local: true}
		}
		embed(s.inner, n, line, s.region, false, &s.comments)
		return
	}
	s.region, s.inner = 0, nil
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

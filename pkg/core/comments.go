package core

import (
	"path/filepath"
	"regexp"
	"strings"
)

// lineComment is the part of one line a comment takes. A comment that spans
// lines gives one per line; Cont is set on the lines after its first.
type lineComment struct {
	Line int
	Text string
	Cont bool
}

// commentSyntax describes the comments and literals of a language well
// enough to tell a comment from text that only looks like one.
type commentSyntax struct {
	line   []string
	blocks []blockSyntax
	quotes []quoteSyntax
	// delimited languages (Markdown, SQL) have comment delimiters a marker
	// parser does not know: their comment text is given without them.
	delimited bool
	// dollarQuotes reads PostgreSQL dollar quoting: $$…$$, $tag$…$tag$. A
	// dollar quote after DO or AS opens a body of code (a DO block, a
	// function), whose comments are comments; elsewhere it is a string.
	dollarQuotes bool
	// codeSpans reads Markdown code spans: a run of backticks up to the next
	// run of the same length on the line.
	codeSpans bool
}

type blockSyntax struct{ open, close string }

type quoteSyntax struct {
	open, close string
	escape      bool
	multiline   bool
	// wordStart: the opener counts only where no word goes on before it
	// (E'…' in SQL, unlike the name E followed by a quote).
	wordStart bool
}

var (
	goSyntax = commentSyntax{
		line:   []string{"//"},
		blocks: []blockSyntax{{"/*", "*/"}},
		quotes: []quoteSyntax{{open: "`", close: "`", multiline: true}, {open: `"`, close: `"`, escape: true}, {open: "'", close: "'", escape: true}},
	}
	jsonSyntax = commentSyntax{
		line:   []string{"//"},
		blocks: []blockSyntax{{"/*", "*/"}},
		quotes: []quoteSyntax{{open: `"`, close: `"`, escape: true}},
	}
	pythonSyntax = commentSyntax{
		line: []string{"#"},
		quotes: []quoteSyntax{
			{open: `"""`, close: `"""`, escape: true, multiline: true}, {open: "'''", close: "'''", escape: true, multiline: true},
			{open: `"`, close: `"`, escape: true}, {open: "'", close: "'", escape: true},
		},
	}
	// SQL literals span lines; E'…' takes backslash escapes, '…' doubles its
	// quote ('it''s' reads as two literals, which is the same for comments).
	sqlSyntax = commentSyntax{
		line:   []string{"--"},
		blocks: []blockSyntax{{"/*", "*/"}},
		quotes: []quoteSyntax{
			{open: "E'", close: "'", escape: true, multiline: true, wordStart: true},
			{open: "e'", close: "'", escape: true, multiline: true, wordStart: true},
			{open: "'", close: "'", multiline: true}, {open: `"`, close: `"`, multiline: true},
		},
		dollarQuotes: true,
		delimited:    true,
	}
	// Markdown: HTML comments in prose (code blocks are blanked before the
	// scan); a code span quotes one.
	markdownSyntax = commentSyntax{
		blocks:    []blockSyntax{{"<!--", "-->"}},
		codeSpans: true,
		delimited: true,
	}
)

// fileComments returns the comments of the file in the syntax of its
// language, nil for a file that has none glint knows. A line's trailing CR
// (CRLF files) is no part of it.
func fileComments(ctx *FileContext) []lineComment {
	lines := make([]string, len(ctx.Lines))
	for i, line := range ctx.Lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	ext := strings.ToLower(filepath.Ext(ctx.Path))
	switch {
	case ctx.IsGoFile():
		return scanComments(lines, goSyntax)
	case ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile():
		return jsComments(lines)
	case ctx.HashComments() || ext == ".conf":
		var comments []lineComment
		for i, line := range lines {
			if comment := hashCommentPart(line); comment != "" {
				comments = append(comments, lineComment{Line: i + 1, Text: comment})
			}
		}
		return comments
	case ext == ".py":
		return scanComments(lines, pythonSyntax)
	case ext == ".sql":
		return scanComments(lines, sqlSyntax)
	case ext == ".md":
		return scanComments(markdownProse(lines), markdownSyntax)
	case ctx.IsTemplate():
		return htmlComments(lines)
	case ctx.IsTSConfig():
		return scanComments(lines, jsonSyntax)
	}
	return nil
}

// markdownProse blanks the code blocks of Markdown lines, fenced and
// indented: what they hold is quoted, not part of the document. A fence
// closes on a fence of its character at least as long as the opening one; an
// indented line is code unless it continues a paragraph.
func markdownProse(lines []string) []string {
	out := make([]string, len(lines))
	fenceChar, fenceLen := byte(0), 0
	paragraph := false
	for i, line := range lines {
		if fenceLen > 0 {
			if c, n, rest := fenceRun(line); c == fenceChar && n >= fenceLen && strings.TrimSpace(rest) == "" {
				fenceLen = 0
			}
			continue
		}
		if c, n, rest := fenceRun(line); n >= 3 && (c == '~' || !strings.Contains(rest, "`")) {
			fenceChar, fenceLen, paragraph = c, n, false
			continue
		}
		blank := strings.TrimSpace(line) == ""
		if !blank && !paragraph && indentWidth(line) >= 4 {
			continue // indented code
		}
		out[i] = line
		trimmed := strings.TrimLeft(line, " \t")
		paragraph = !blank && !strings.HasPrefix(trimmed, "#")
	}
	return out
}

// fenceRun reads a code fence: up to three spaces, then a run of backticks
// or tildes. It returns the character, the run's length (0 when the line is
// no fence) and what follows the run.
func fenceRun(line string) (byte, int, string) {
	indent := len(line) - len(strings.TrimLeft(line, " "))
	if indent > 3 || indent == len(line) {
		return 0, 0, ""
	}
	c := line[indent]
	if c != '`' && c != '~' {
		return 0, 0, ""
	}
	n := indent
	for n < len(line) && line[n] == c {
		n++
	}
	if n-indent < 3 {
		return 0, 0, ""
	}
	return c, n - indent, line[n:]
}

// indentWidth is the indentation of a line in columns, a tab to the next
// multiple of four.
func indentWidth(line string) int {
	width := 0
	for _, c := range line {
		switch c {
		case ' ':
			width++
		case '\t':
			width += 4 - width%4
		default:
			return width
		}
	}
	return width
}

// scanComments returns the comments of lines in the given syntax.
func scanComments(lines []string, syntax commentSyntax) []lineComment {
	s := commentScanner{syntax: syntax, block: -1}
	for i, line := range lines {
		s.scanLine(i+1, line)
	}
	return s.comments
}

type commentScanner struct {
	syntax  commentSyntax
	block   int // index of the open block comment, -1 when none
	quoting bool
	quote   quoteSyntax // the open literal while quoting
	// lastWord is the word the code read last, "" when other code follows
	// it; bodies are the tags of the open dollar-quoted bodies, innermost
	// last.
	lastWord string
	bodies   []string
	// comments are the comments read so far.
	comments []lineComment
}

func (s *commentScanner) add(line int, text string, cont bool) {
	if s.syntax.delimited {
		for _, open := range s.syntax.line {
			text = strings.TrimPrefix(text, open)
		}
		if !cont && s.block >= 0 {
			text = strings.TrimPrefix(text, s.syntax.blocks[s.block].open)
		}
	}
	if strings.TrimSpace(text) != "" {
		s.comments = append(s.comments, lineComment{Line: line, Text: text, Cont: cont})
	}
}

func (s *commentScanner) scanLine(n int, line string) {
	i := 0
	if s.block >= 0 {
		i = s.closeBlock(n, line, 0, true)
	}
	if s.quoting {
		i = s.closeQuote(line, i)
	}
	for i < len(line) && s.block < 0 && !s.quoting {
		rest := line[i:]
		if s.opensLineComment(rest) {
			s.add(n, rest, false)
			return
		}
		if b := s.opensBlock(rest); b >= 0 {
			s.block = b
			i = s.closeBlock(n, line, i, false)
			continue
		}
		if next, ok := s.dollarBody(line, i); ok {
			i = next
			continue
		}
		if q, ok := s.opensQuote(line, i); ok {
			s.quote, s.quoting, s.lastWord = q, true, ""
			i = s.closeQuote(line, i+len(q.open))
			if s.quoting && !q.multiline {
				s.quoting = false // a one-line literal ends with its line
				return
			}
			continue
		}
		if s.syntax.codeSpans && line[i] == '`' {
			i = codeSpanEnd(line, i)
			continue
		}
		if s.syntax.dollarQuotes {
			if end := wordEnd(line, i); end > i {
				s.lastWord, i = line[i:end], end
				continue
			}
			if line[i] != ' ' && line[i] != '\t' {
				s.lastWord = ""
			}
		}
		i++
	}
}

// dollarBody reads a dollar quote at i that opens or closes a body of code:
// the tag of the innermost open body closes it, a tag after DO or AS opens
// one. It returns where the code after the tag starts.
func (s *commentScanner) dollarBody(line string, i int) (int, bool) {
	if !s.syntax.dollarQuotes || line[i] != '$' || (i > 0 && isRuleNameChar(line[i-1])) {
		return 0, false
	}
	tag := dollarQuote.FindString(line[i:])
	switch {
	case tag == "":
		return 0, false
	case len(s.bodies) > 0 && s.bodies[len(s.bodies)-1] == tag:
		s.bodies = s.bodies[:len(s.bodies)-1]
	case strings.EqualFold(s.lastWord, "do") || strings.EqualFold(s.lastWord, "as"):
		s.bodies = append(s.bodies, tag)
	default:
		return 0, false
	}
	s.lastWord = ""
	return i + len(tag), true
}

// wordEnd returns where the SQL word that starts at i ends, i when none does.
func wordEnd(line string, i int) int {
	end := i
	for end < len(line) && (line[end] == '_' || isASCIILetter(line[end]) || (end > i && line[end] >= '0' && line[end] <= '9')) {
		end++
	}
	return end
}

func (s *commentScanner) opensLineComment(rest string) bool {
	for _, open := range s.syntax.line {
		if strings.HasPrefix(rest, open) {
			return true
		}
	}
	return false
}

func (s *commentScanner) opensBlock(rest string) int {
	for b, block := range s.syntax.blocks {
		if strings.HasPrefix(rest, block.open) {
			return b
		}
	}
	return -1
}

// dollarQuote matches the opening delimiter of a PostgreSQL dollar-quoted
// string: $$ or $tag$.
var dollarQuote = regexp.MustCompile(`^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$`)

func (s *commentScanner) opensQuote(line string, i int) (quoteSyntax, bool) {
	rest := line[i:]
	wordBefore := i > 0 && isRuleNameChar(line[i-1])
	if s.syntax.dollarQuotes && rest[0] == '$' && !wordBefore {
		if tag := dollarQuote.FindString(rest); tag != "" {
			return quoteSyntax{open: tag, close: tag, multiline: true}, true
		}
	}
	for _, quote := range s.syntax.quotes {
		if strings.HasPrefix(rest, quote.open) && (!quote.wordStart || !wordBefore) {
			return quote, true
		}
	}
	return quoteSyntax{}, false
}

// codeSpanEnd returns where the code span opened by the backtick run at i
// ends: after the next run of the same length on the line, or after the run
// itself when none closes it (the backticks are then text).
func codeSpanEnd(line string, i int) int {
	run := backtickRun(line, i)
	for j := i + run; j < len(line); {
		if line[j] != '`' {
			j++
			continue
		}
		closing := backtickRun(line, j)
		if closing == run {
			return j + closing
		}
		j += closing
	}
	return i + run
}

func backtickRun(line string, i int) int {
	n := 0
	for i+n < len(line) && line[i+n] == '`' {
		n++
	}
	return n
}

// closeBlock records the part of the open block comment that starts at
// start of the line and returns where the code after it starts, len(line)
// when the comment goes on.
func (s *commentScanner) closeBlock(n int, line string, start int, cont bool) int {
	block := s.syntax.blocks[s.block]
	from := start
	if !cont {
		from += len(block.open)
	}
	end := strings.Index(line[from:], block.close)
	if end < 0 {
		s.add(n, line[start:], cont)
		return len(line)
	}
	end += from
	text := line[start : end+len(block.close)]
	if s.syntax.delimited {
		text = line[start:end]
	}
	s.add(n, text, cont)
	s.block = -1
	return end + len(block.close)
}

// closeQuote returns where the code after the open literal starts, len(line)
// when the literal goes on.
func (s *commentScanner) closeQuote(line string, i int) int {
	for i < len(line) {
		if s.quote.escape && line[i] == '\\' {
			i += 2
			continue
		}
		if strings.HasPrefix(line[i:], s.quote.close) {
			s.quoting = false
			return i + len(s.quote.close)
		}
		i++
	}
	return len(line)
}

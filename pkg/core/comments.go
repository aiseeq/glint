package core

import (
	"path/filepath"
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
	// delimited languages (HTML, SQL) have comment delimiters a marker parser
	// does not know: their comment text is given without them.
	delimited bool
}

type blockSyntax struct{ open, close string }

type quoteSyntax struct {
	open, close string
	escape      bool
	multiline   bool
}

var (
	goSyntax = commentSyntax{
		line:   []string{"//"},
		blocks: []blockSyntax{{"/*", "*/"}},
		quotes: []quoteSyntax{{"`", "`", false, true}, {`"`, `"`, true, false}, {"'", "'", true, false}},
	}
	jsonSyntax = commentSyntax{
		line:   []string{"//"},
		blocks: []blockSyntax{{"/*", "*/"}},
		quotes: []quoteSyntax{{`"`, `"`, true, false}},
	}
	pythonSyntax = commentSyntax{
		line: []string{"#"},
		quotes: []quoteSyntax{
			{`"""`, `"""`, true, true}, {"'''", "'''", true, true},
			{`"`, `"`, true, false}, {"'", "'", true, false},
		},
	}
	sqlSyntax = commentSyntax{
		line:      []string{"--"},
		blocks:    []blockSyntax{{"/*", "*/"}},
		quotes:    []quoteSyntax{{"'", "'", false, false}, {`"`, `"`, false, false}},
		delimited: true,
	}
	// Markdown: HTML comments; inline code quotes one (fenced blocks are
	// blanked before the scan).
	markdownSyntax = commentSyntax{
		blocks:    []blockSyntax{{"<!--", "-->"}},
		quotes:    []quoteSyntax{{"`", "`", false, false}},
		delimited: true,
	}
	// HTML and Go templates: HTML comments and template comments.
	templateSyntax = commentSyntax{
		blocks:    []blockSyntax{{"<!--", "-->"}, {"{{/*", "*/"}, {"{{- /*", "*/"}},
		delimited: true,
	}
)

// fileComments returns the comments of the file in the syntax of its
// language, nil for a file that has none glint knows.
func fileComments(ctx *FileContext) []lineComment {
	lines := ctx.Lines
	switch {
	case ctx.IsGoFile():
		return scanComments(lines, goSyntax)
	case ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile():
		return jsComments(lines)
	case ctx.HashComments() || strings.EqualFold(filepath.Ext(ctx.Path), ".conf"):
		var comments []lineComment
		for i, line := range lines {
			if comment := hashCommentPart(line); comment != "" {
				comments = append(comments, lineComment{Line: i + 1, Text: comment})
			}
		}
		return comments
	case strings.EqualFold(filepath.Ext(ctx.Path), ".py"):
		return scanComments(lines, pythonSyntax)
	case strings.EqualFold(filepath.Ext(ctx.Path), ".sql"):
		return scanComments(lines, sqlSyntax)
	case strings.EqualFold(filepath.Ext(ctx.Path), ".md"):
		return scanComments(withoutFences(lines), markdownSyntax)
	case ctx.IsTemplate():
		return scanComments(lines, templateSyntax)
	case ctx.IsTSConfig():
		return scanComments(lines, jsonSyntax)
	}
	return nil
}

// withoutFences blanks the fenced code blocks of Markdown lines: what they
// hold is quoted, not part of the document.
func withoutFences(lines []string) []string {
	out := make([]string, len(lines))
	fence := ""
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		switch {
		case fence != "":
			if strings.HasPrefix(trimmed, fence) && strings.Trim(trimmed, fence[:1]+" \t") == "" {
				fence = ""
			}
		case strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~"):
			fence = trimmed[:3]
		default:
			out[i] = line
		}
	}
	return out
}

// scanComments returns the comments of lines in the given syntax.
func scanComments(lines []string, syntax commentSyntax) []lineComment {
	s := commentScanner{syntax: syntax, block: -1, quote: -1}
	for i, line := range lines {
		s.scanLine(i+1, line)
	}
	return s.comments
}

type commentScanner struct {
	syntax   commentSyntax
	block    int // index of the open block comment, -1 when none
	quote    int // index of the open multi-line literal, -1 when none
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
	if s.quote >= 0 {
		i = s.closeQuote(line, i)
	}
	for i < len(line) {
		if s.block >= 0 || s.quote >= 0 {
			return
		}
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
		if q := s.opensQuote(rest); q >= 0 {
			s.quote = q
			i = s.closeQuote(line, i+len(s.syntax.quotes[q].open))
			if s.quote >= 0 && !s.syntax.quotes[q].multiline {
				s.quote = -1 // a one-line literal ends with its line
				return
			}
			continue
		}
		i++
	}
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

func (s *commentScanner) opensQuote(rest string) int {
	for q, quote := range s.syntax.quotes {
		if strings.HasPrefix(rest, quote.open) {
			return q
		}
	}
	return -1
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
	quote := s.syntax.quotes[s.quote]
	for i < len(line) {
		if quote.escape && line[i] == '\\' {
			i += 2
			continue
		}
		if strings.HasPrefix(line[i:], quote.close) {
			s.quote = -1
			return i + len(quote.close)
		}
		i++
	}
	return len(line)
}

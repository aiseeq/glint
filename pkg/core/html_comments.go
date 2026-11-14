package core

import "strings"

// htmlState is where an HTML or Go template scan stands.
type htmlState int

const (
	htmlText htmlState = iota
	htmlTag
	htmlComment
	htmlRawText
	htmlAction
	htmlActionComment
)

// htmlScanner reads the comments of HTML and Go templates: <!-- … --> in
// text and {{/* … */}} actions, in text and in the raw text of an element
// alike. Text that only looks like a comment is none: inside a tag (an
// attribute value), in the raw text of <script>, <style>, <textarea> and
// <title>, and in a string of a template action.
type htmlScanner struct {
	state htmlState
	// outer is the state a template action returns to: htmlText or
	// htmlRawText.
	outer    htmlState
	quote    byte   // the open quote inside a tag or an action, 0 when none
	rawEnd   string // the end tag of raw text, lowercase
	tagName  string // the name of the tag being read, lowercase
	comments []lineComment
}

func htmlComments(lines []string) []lineComment {
	s := &htmlScanner{}
	for i, line := range lines {
		s.scanLine(i+1, line)
	}
	return s.comments
}

func (s *htmlScanner) add(line int, text string, cont bool) {
	if strings.TrimSpace(text) != "" {
		s.comments = append(s.comments, lineComment{Line: line, Text: text, Cont: cont})
	}
}

func (s *htmlScanner) scanLine(n int, line string) {
	cont := s.state == htmlComment || s.state == htmlActionComment
	for i := 0; i < len(line); {
		switch s.state {
		case htmlComment, htmlActionComment:
			i = s.closeComment(n, line, i, cont)
		case htmlTag:
			i = s.scanTag(line, i)
		case htmlRawText:
			i = s.scanRawText(line, i)
		case htmlAction:
			i = s.scanAction(line, i)
		default:
			i = s.scanText(line, i)
		}
		cont = false
	}
	// An attribute value may span lines; a string of an action may not,
	// unless it is a raw string.
	if s.state == htmlAction && s.quote != '`' {
		s.quote = 0
	}
}

// closeComment records the part of the open comment from i and returns where
// the text after it starts.
func (s *htmlScanner) closeComment(n int, line string, i int, cont bool) int {
	closer := "-->"
	if s.state == htmlActionComment {
		closer = "*/"
	}
	end := strings.Index(line[i:], closer)
	if end < 0 {
		s.add(n, line[i:], cont)
		return len(line)
	}
	s.add(n, line[i:i+end], cont)
	if s.state == htmlActionComment {
		s.state = htmlAction
	} else {
		s.state = htmlText
	}
	return i + end + len(closer)
}

func (s *htmlScanner) scanText(line string, i int) int {
	rest := line[i:]
	switch {
	case strings.HasPrefix(rest, "<!--"):
		s.state = htmlComment
		return i + 4
	case strings.HasPrefix(rest, "{{"):
		return s.openAction(line, i, htmlText)
	case rest[0] == '<' && len(rest) > 1 && (isASCIILetter(rest[1]) || rest[1] == '/' || rest[1] == '!' || rest[1] == '?'):
		s.state = htmlTag
		name := rest[1:]
		end := 0
		for end < len(name) && isRuleNameChar(name[end]) {
			end++
		}
		s.tagName = strings.ToLower(name[:end])
		return i + 1 + end
	}
	return i + 1
}

// openAction reads the template action that opens at i and returns where its
// body starts; the action returns to outer when it closes.
func (s *htmlScanner) openAction(line string, i int, outer htmlState) int {
	s.outer = outer
	after := strings.TrimLeft(strings.TrimPrefix(line[i+2:], "-"), " \t")
	if strings.HasPrefix(after, "/*") {
		s.state = htmlActionComment
		return len(line) - len(after) + 2
	}
	s.state = htmlAction
	return i + 2
}

// scanRawText reads raw text from i up to the end tag of its element or a
// template action, whichever comes first.
func (s *htmlScanner) scanRawText(line string, i int) int {
	end := strings.Index(strings.ToLower(line[i:]), s.rawEnd)
	action := strings.Index(line[i:], "{{")
	switch {
	case action >= 0 && (end < 0 || action < end):
		return s.openAction(line, i+action, htmlRawText)
	case end < 0:
		return len(line)
	}
	s.state, s.tagName = htmlTag, ""
	return i + end + 2
}

func (s *htmlScanner) scanTag(line string, i int) int {
	c := line[i]
	switch {
	case s.quote != 0:
		if c == s.quote {
			s.quote = 0
		}
	case c == '"' || c == '\'':
		s.quote = c
	case c == '>':
		s.state = htmlText
		if s.tagName == "script" || s.tagName == "style" || s.tagName == "textarea" || s.tagName == "title" {
			s.state, s.rawEnd = htmlRawText, "</"+s.tagName
		}
	}
	return i + 1
}

func (s *htmlScanner) scanAction(line string, i int) int {
	c := line[i]
	switch {
	case s.quote != 0:
		if c == '\\' && s.quote != '`' {
			return i + 2
		}
		if c == s.quote {
			s.quote = 0
		}
	case c == '"' || c == '\'' || c == '`':
		s.quote = c
	case strings.HasPrefix(line[i:], "}}"):
		s.state = s.outer
		return i + 2
	}
	return i + 1
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

package doccheck

import "strings"

// The one recognizer of Markdown code for the md-* rules: fenced and indented
// code blocks, inline code spans and HTML comments, following CommonMark.
// Everything inside them is an example or hidden text, not prose the rules
// judge.

// markdownLine is one line of a Markdown document as the md-* rules see it.
type markdownLine struct {
	// code is true for a line of a fenced code block (fences included) or of
	// an indented code block.
	code bool
	// prose is the line with inline code spans and HTML comments blanked out
	// by spaces, so columns stay where they were. Empty for a code line.
	prose string
}

// markdownFence is an open fenced code block: its character and length.
type markdownFence struct {
	char   byte
	length int
}

// scanMarkdown classifies every line of a Markdown document.
func scanMarkdown(lines []string) []markdownLine {
	result := make([]markdownLine, len(lines))
	var fence *markdownFence
	inComment := false
	// listContent is the column where the content of the innermost open list
	// item starts; an indented line is code only four columns past it.
	listContent := 0
	previousBlank := true
	previousCode := false

	for i, line := range lines {
		indent, rest := leadingColumns(line)
		blank := strings.TrimSpace(line) == ""

		if fence != nil {
			result[i].code = true
			if closesFence(rest, indent, *fence) {
				fence = nil
			}
			previousBlank, previousCode = false, true
			continue
		}
		if !inComment {
			if opened, ok := opensFence(rest, indent); ok {
				fence = &opened
				result[i].code = true
				previousBlank, previousCode = false, true
				continue
			}
			if !blank && indent-listContent >= 4 && (previousBlank || previousCode) {
				result[i].code = true
				previousBlank, previousCode = false, true
				continue
			}
		}

		if !blank && !inComment {
			switch content, isItem := listItemContent(line, indent); {
			case isItem:
				listContent = content
			case indent < listContent && previousBlank:
				listContent = 0 // a paragraph back at the margin ends the list
			}
		}

		result[i].prose, inComment = blankInlineCode(line, inComment)
		previousBlank, previousCode = blank, false
	}
	return result
}

// leadingColumns returns the indentation of a line in columns (a tab advances
// to the next multiple of four) and the text after it.
func leadingColumns(line string) (int, string) {
	columns := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ':
			columns++
		case '\t':
			columns += 4 - columns%4
		default:
			return columns, line[i:]
		}
	}
	return columns, ""
}

// opensFence recognizes an opening code fence: up to three columns of
// indentation, then three or more backticks or tildes. A backtick fence's
// info string cannot hold a backtick.
func opensFence(rest string, indent int) (markdownFence, bool) {
	if indent > 3 || len(rest) < 3 || (rest[0] != '`' && rest[0] != '~') {
		return markdownFence{}, false
	}
	char := rest[0]
	length := runLength(rest, char)
	if length < 3 {
		return markdownFence{}, false
	}
	if char == '`' && strings.IndexByte(rest[length:], '`') >= 0 {
		return markdownFence{}, false
	}
	return markdownFence{char: char, length: length}, true
}

// closesFence recognizes the closing fence of an open block: the same
// character, at least as many of it, nothing but spaces after.
func closesFence(rest string, indent int, fence markdownFence) bool {
	if indent > 3 {
		return false
	}
	length := runLength(rest, fence.char)
	return length >= fence.length && strings.TrimSpace(rest[length:]) == ""
}

func runLength(s string, char byte) int {
	n := 0
	for n < len(s) && s[n] == char {
		n++
	}
	return n
}

// listItemContent recognizes a list item marker (-, *, + or 1. / 1)) after the
// line's indentation and returns the column where the item's content starts.
func listItemContent(line string, indent int) (int, bool) {
	_, rest := leadingColumns(line)
	marker := 0
	switch {
	case rest != "" && strings.IndexByte("-*+", rest[0]) >= 0:
		marker = 1
	default:
		for marker < len(rest) && marker < 9 && rest[marker] >= '0' && rest[marker] <= '9' {
			marker++
		}
		if marker == 0 || marker >= len(rest) || (rest[marker] != '.' && rest[marker] != ')') {
			return 0, false
		}
		marker++
	}
	if marker < len(rest) && rest[marker] != ' ' && rest[marker] != '\t' {
		return 0, false
	}
	spaces := runLength(rest[marker:], ' ')
	if spaces == 0 || spaces > 4 {
		spaces = 1
	}
	return indent + marker + spaces, true
}

// blankInlineCode replaces the content of inline code spans and HTML comments
// with spaces. inComment says whether the line starts inside an HTML comment
// opened on an earlier line; the result says whether it ends inside one. A
// backtick run without a closing run of the same length is literal text.
func blankInlineCode(line string, inComment bool) (string, bool) {
	out := []byte(line)
	for i := 0; i < len(out); {
		if inComment {
			end := strings.Index(line[i:], "-->")
			if end < 0 {
				blank(out, i, len(out))
				return string(out), true
			}
			blank(out, i, i+end+3)
			i += end + 3
			inComment = false
			continue
		}
		switch {
		case strings.HasPrefix(line[i:], "<!--"):
			inComment = true
		case line[i] == '`':
			open := runLength(line[i:], '`')
			closeAt := closingBacktickRun(line, i+open, open)
			if closeAt < 0 {
				i += open
				continue
			}
			blank(out, i, closeAt+open)
			i = closeAt + open
		default:
			i++
		}
	}
	return string(out), inComment
}

// closingBacktickRun finds a run of exactly n backticks at or after from.
func closingBacktickRun(line string, from, n int) int {
	for i := from; i < len(line); {
		if line[i] != '`' {
			i++
			continue
		}
		run := runLength(line[i:], '`')
		if run == n {
			return i
		}
		i += run
	}
	return -1
}

func blank(b []byte, from, to int) {
	for i := from; i < to; i++ {
		b[i] = ' '
	}
}

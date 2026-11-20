package core

import (
	"bytes"
	"regexp"
	"strings"
)

// ExtractTemplateJavaScript returns one JavaScript context holding every inline
// script of a Go HTML template. The virtual source keeps the template's byte
// offsets and line numbers so rules can report against the original .html
// path. A file without a template action is plain HTML, not a Go template, and
// gets none.
func ExtractTemplateJavaScript(ctx *FileContext) []*FileContext {
	if ctx == nil || !ctx.IsTemplate() || !bytes.Contains(ctx.Content, []byte("{{")) {
		return nil
	}
	source := string(ctx.Content)
	var virtual []byte
	for offset := 0; offset < len(source); {
		start, end, ok := scriptTag(source, offset)
		if !ok {
			break
		}
		closeStart, closeEnd := scriptClose(source, end)
		if closeStart < 0 {
			break
		}
		offset = closeEnd
		if !isJavaScriptScriptTag(source[start:end]) {
			continue
		}
		if virtual == nil {
			virtual = []byte(source)
			blank(virtual, 0, len(virtual))
		}
		// Tags are markup, not JavaScript: only the body is copied.
		copy(virtual[end:closeStart], source[end:closeStart])
		maskTemplateActions(virtual, end, closeStart)
	}
	if virtual == nil {
		return nil
	}
	v := NewFileContext(ctx.Path, ctx.ProjectRoot, virtual, ctx.Config)
	v.VirtualJavaScript = true
	return []*FileContext{v}
}

func isJavaScriptScriptTag(tag string) bool {
	lower := strings.ToLower(tag)
	for i := 0; i < len(lower); {
		rel := strings.Index(lower[i:], "type")
		if rel < 0 {
			return true
		}
		at := i + rel
		beforeOK := at == 0 || lower[at-1] == ' ' || lower[at-1] == '\t' || lower[at-1] == '\r' || lower[at-1] == '\n'
		after := at + len("type")
		afterOK := after == len(lower) || lower[after] == '=' || lower[after] == ' ' || lower[after] == '\t'
		if !beforeOK || !afterOK {
			i = after
			continue
		}
		for after < len(lower) && (lower[after] == ' ' || lower[after] == '\t' || lower[after] == '\r' || lower[after] == '\n') {
			after++
		}
		if after == len(lower) || lower[after] != '=' {
			return true
		}
		after++
		for after < len(lower) && (lower[after] == ' ' || lower[after] == '\t') {
			after++
		}
		if after == len(lower) {
			return false
		}
		quote := lower[after]
		if quote == '\'' || quote == '"' {
			after++
			end := strings.IndexByte(lower[after:], quote)
			if end >= 0 {
				lower = strings.TrimSpace(lower[after : after+end])
			} else {
				lower = strings.TrimSpace(lower[after:])
			}
		} else {
			end := strings.IndexAny(lower[after:], " \t\r\n>")
			if end >= 0 {
				lower = lower[after : after+end]
			} else {
				lower = lower[after:]
			}
		}
		switch strings.TrimSpace(lower) {
		case "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript":
			return true
		default:
			return false
		}
	}
	return true
}

// hasPrefixFold reports whether s[i:] starts with the ASCII prefix, ignoring
// case; it compares bytes so indexes stay those of s.
func hasPrefixFold(s string, i int, prefix string) bool {
	return len(s)-i >= len(prefix) && strings.EqualFold(s[i:i+len(prefix)], prefix)
}

func scriptTag(s string, from int) (int, int, bool) {
	for i := from; i < len(s); {
		if strings.HasPrefix(s[i:], "{{") {
			if end := strings.Index(s[i+2:], "}}"); end >= 0 {
				i += end + 4
				continue
			}
			return 0, 0, false
		}
		if hasPrefixFold(s, i, "<script") {
			boundary := i + len("<script")
			if boundary < len(s) && (s[boundary] == '>' || s[boundary] == '/' || s[boundary] == ' ' || s[boundary] == '\t' || s[boundary] == '\r' || s[boundary] == '\n') {
				if endRel := strings.IndexByte(s[boundary:], '>'); endRel >= 0 {
					return i, boundary + endRel + 1, true
				}
			}
		}
		i++
	}
	return 0, 0, false
}

func scriptClose(s string, from int) (int, int) {
	for i := from; i < len(s); {
		if strings.HasPrefix(s[i:], "{{") {
			if end := strings.Index(s[i+2:], "}}"); end >= 0 {
				i += end + 4
				continue
			}
			return -1, -1
		}
		if hasPrefixFold(s, i, "</script") {
			if endRel := strings.IndexByte(s[i:], '>'); endRel >= 0 {
				return i, i + endRel + 1
			}
			return -1, -1
		}
		i++
	}
	return -1, -1
}

func blank(b []byte, start, end int) {
	for i := start; i < end; i++ {
		if b[i] != '\n' && b[i] != '\r' {
			b[i] = ' '
		}
	}
}

type templateBranch struct {
	parentActive bool
}

// maskTemplateActions removes Go actions while keeping JavaScript parseable
// and preserving every source line. if selects the first branch; range keeps
// its body once. The replacement is padded to the action's original width.
func maskTemplateActions(b []byte, start, end int) {
	var branches []templateBranch
	active := true
	i := start
	for i < end {
		open := bytes.Index(b[i:end], []byte("{{"))
		if open < 0 {
			if !active {
				blank(b, i, end)
			}
			break
		}
		a := i + open
		closeRel := bytes.Index(b[a+2:end], []byte("}}"))
		if closeRel < 0 {
			if !active {
				blank(b, i, end)
			}
			blank(b, a, end)
			break
		}
		z := a + 2 + closeRel + 2
		body := strings.TrimSpace(string(b[a+2 : z-2]))
		body = strings.TrimSpace(strings.TrimPrefix(body, "-"))
		body = strings.TrimSpace(strings.TrimSuffix(body, "-"))
		verb := strings.Fields(body)
		kind := ""
		if len(verb) > 0 {
			kind = verb[0]
		}
		if !active {
			blank(b, i, a)
		}
		switch kind {
		case "if":
			branches = append(branches, templateBranch{parentActive: active})
			blank(b, a, z)
		case "else":
			// The first branch is the one kept: every else, else if and
			// else with after it is another version of the same code.
			if len(branches) > 0 {
				active = false
			}
			blank(b, a, z)
		case "end":
			blank(b, a, z)
			if len(branches) > 0 {
				active = branches[len(branches)-1].parentActive
				branches = branches[:len(branches)-1]
			}
		case "range":
			branches = append(branches, templateBranch{parentActive: active})
			blank(b, a, z)
		case "with", "block":
			branches = append(branches, templateBranch{parentActive: active})
			blank(b, a, z)
		case "define":
			// A define body is another template, not code of this script.
			branches = append(branches, templateBranch{parentActive: active})
			active = false
			blank(b, a, z)
		default:
			if !active {
				blank(b, a, z)
			} else {
				// A template call is a statement or a value, like any other
				// action: the code before it tells which.
				replaceTemplateAction(b, a, z, templateExpression(b, start, a, z))
			}
		}
		i = z
	}
	if !active {
		blank(b, i, end)
	}
}

func templateExpression(b []byte, start, at, end int) string {
	code, inQuote := templateCodePrefix(b, start, at)
	if inQuote {
		return "x"
	}
	prefix := strings.TrimSpace(string(code))
	if strings.HasSuffix(prefix, ".") {
		return "_"
	}
	if strings.HasSuffix(prefix, "from") && (len(prefix) == len("from") || isTemplateWordBoundary(prefix[len(prefix)-len("from")-1])) {
		return `"x"`
	}
	for _, keyword := range []string{"return", "throw", "yield", "await", "typeof", "void", "delete", "new", "=>"} {
		if strings.HasSuffix(prefix, keyword) {
			return "null"
		}
	}
	lineStart := bytes.LastIndexAny(code, "\r\n") + 1
	previous := lastNonSpaceByte(code[lineStart:])
	next := nextNonSpaceByte(b, end)
	before, after := lastWord(code[lineStart:]), nextWord(b, end)
	if before == "try" || before == "finally" || templateCatchClause.Match(code[lineStart:]) {
		// try, catch (e) and finally take a block, not a statement.
		return "{}"
	}
	if isTemplateOperandEnd(previous) && isTemplateOperandStart(next) &&
		!templateKeyword(before) && (!templateKeyword(after) || templateValueKeywords[after]) {
		return "+"
	}
	for i := at - 1; i >= start; i-- {
		if b[i] == '\n' || b[i] == '\r' {
			continue
		}
		if strings.ContainsRune("=([{,:+-*/%!&|^<>?.", rune(b[i])) {
			return "null"
		}
		if b[i] == ' ' || b[i] == '\t' {
			continue
		}
		break
	}
	return ";"
}

func templateCodePrefix(b []byte, start, at int) ([]byte, bool) {
	quote := byte(0)
	escaped := false
	lineComment := false
	blockComment := false
	code := make([]byte, 0, at-start)
	for i := start; i < at; i++ {
		c := b[i]
		if lineComment {
			if c == '\n' || c == '\r' {
				lineComment = false
				code = append(code, c)
			}
			continue
		}
		if blockComment {
			if c == '\n' || c == '\r' {
				code = append(code, c)
			} else if c == '*' && i+1 < at && b[i+1] == '/' {
				blockComment = false
				i++
				code = append(code, ' ')
			}
			continue
		}
		if quote != 0 {
			code = append(code, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
		} else if c == '/' && i+1 < at && b[i+1] == '/' {
			lineComment = true
			code = append(code, ' ')
			i++
		} else if c == '/' && i+1 < at && b[i+1] == '*' {
			blockComment = true
			code = append(code, ' ')
			i++
		} else if c == '\'' || c == '"' || c == '`' {
			quote = c
			code = append(code, c)
		} else {
			code = append(code, c)
		}
	}
	return code, quote != 0
}

func lastNonSpaceByte(b []byte) byte {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != ' ' && b[i] != '\t' && b[i] != '\r' && b[i] != '\n' {
			return b[i]
		}
	}
	return 0
}

func nextNonSpaceByte(b []byte, at int) byte {
	for at < len(b) {
		if b[at] == '\r' || b[at] == '\n' {
			return 0
		}
		if b[at] != ' ' && b[at] != '\t' {
			return b[at]
		}
		at++
	}
	return 0
}

func isTemplateWordBoundary(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '$':
		return false
	default:
		return true
	}
}

// templateKeywords are the JavaScript words that are not values: an action
// next to one (if (a) {{template "s" .}} else ..., do {{...}} while) is a
// statement, not an operator between two operands.
var templateKeywords = map[string]bool{
	"break": true, "case": true, "catch": true, "class": true, "const": true, "continue": true,
	"debugger": true, "default": true, "delete": true, "do": true, "else": true, "export": true,
	"extends": true, "finally": true, "for": true, "function": true, "if": true, "import": true,
	"in": true, "instanceof": true, "let": true, "new": true, "of": true, "return": true,
	"switch": true, "throw": true, "try": true, "typeof": true, "var": true, "void": true,
	"while": true, "with": true, "yield": true, "await": true,
}

// templateValueKeywords start a value: a {{.Op}} new Date() is still an
// operator between operands.
var templateValueKeywords = map[string]bool{
	"new": true, "typeof": true, "void": true, "delete": true, "function": true, "class": true, "await": true,
}

var templateCatchClause = regexp.MustCompile(`\bcatch\s*(\([^()]*\))?\s*$`)

func templateKeyword(word string) bool {
	return templateKeywords[word]
}

// lastWord returns the identifier that ends code, or "" when there is none
// or it is a property name (opts.default).
func lastWord(code []byte) string {
	end := len(code)
	for end > 0 && (code[end-1] == ' ' || code[end-1] == '\t') {
		end--
	}
	start := end
	for start > 0 && !isTemplateWordBoundary(code[start-1]) {
		start--
	}
	dot := start
	for dot > 0 && (code[dot-1] == ' ' || code[dot-1] == '\t') {
		dot--
	}
	if dot > 0 && code[dot-1] == '.' {
		return ""
	}
	return string(code[start:end])
}

// nextWord returns the identifier that starts after at on the same line, or "".
func nextWord(b []byte, at int) string {
	for at < len(b) && (b[at] == ' ' || b[at] == '\t') {
		at++
	}
	end := at
	for end < len(b) && !isTemplateWordBoundary(b[end]) {
		end++
	}
	return string(b[at:end])
}

func isTemplateOperandEnd(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$' || c == ')' || c == ']' || c == '\'' || c == '"' || c == '`'
}

func isTemplateOperandStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '(' || c == '[' || c == '\'' || c == '"' || c == '`'
}

func replaceTemplateAction(b []byte, start, end int, replacement string) {
	blank(b, start, end)
	segmentEnd := start
	for segmentEnd < end && b[segmentEnd] != '\n' && b[segmentEnd] != '\r' {
		segmentEnd++
	}
	if segmentEnd-start < len(replacement) {
		// Tiny actions such as {{.}} cannot hold "null"; zero is a valid
		// neutral expression and keeps the original source width.
		replacement = "0"
	}
	if segmentEnd-start >= len(replacement) {
		copy(b[start:], replacement)
	}
}

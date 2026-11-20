package core

import (
	"bytes"
	"strings"
)

// ExtractTemplateJavaScript returns JavaScript contexts for inline scripts in
// a Go HTML template. The virtual source keeps the template's byte offsets and
// line numbers so rules can report against the original .html path.
func ExtractTemplateJavaScript(ctx *FileContext) []*FileContext {
	if ctx == nil || !ctx.IsTemplate() {
		return nil
	}
	source := string(ctx.Content)
	var out []*FileContext
	for offset := 0; offset < len(source); {
		start, end, ok := scriptTag(source, offset)
		if !ok {
			break
		}
		closeStart, closeEnd := scriptClose(source, end)
		if closeStart < 0 {
			break
		}
		if !isJavaScriptScriptTag(source[start:end]) {
			offset = closeEnd
			continue
		}
		virtual := []byte(source)
		blank(virtual, 0, len(virtual))
		copy(virtual[start:end], source[start:end])
		copy(virtual[end:closeStart], source[end:closeStart])
		copy(virtual[closeStart:closeEnd], source[closeStart:closeEnd])
		// Tags are markup, not JavaScript.
		blank(virtual, start, end)
		blank(virtual, closeStart, closeEnd)
		maskTemplateActions(virtual, end, closeStart)
		v := NewFileContext(ctx.Path, ctx.ProjectRoot, virtual, ctx.Config)
		v.VirtualJavaScript = true
		out = append(out, v)
		offset = closeEnd
	}
	return out
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
	elseSeen     bool
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
			if len(branches) > 0 {
				branch := &branches[len(branches)-1]
				useElse := !branch.elseSeen
				branch.elseSeen = true
				active = branch.parentActive && !useElse
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
			} else if kind == "template" {
				replaceTemplateAction(b, a, z, ";")
			} else {
				replaceTemplateAction(b, a, z, templateExpression(b, start, a))
			}
		}
		i = z
	}
	if !active {
		blank(b, i, end)
	}
}

func templateExpression(b []byte, start, at int) string {
	quote := byte(0)
	escaped := false
	for i := start; i < at; i++ {
		c := b[i]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
		} else if c == '\'' || c == '"' || c == '`' {
			quote = c
		}
	}
	if quote != 0 {
		return "x"
	}
	prefix := strings.TrimSpace(string(b[start:at]))
	for _, keyword := range []string{"return", "throw", "yield", "await", "typeof", "void", "delete", "new", "=>"} {
		if strings.HasSuffix(prefix, keyword) {
			return "null"
		}
	}
	for i := at - 1; i >= start; i-- {
		if b[i] == '\n' || b[i] == '\r' {
			continue
		}
		if strings.ContainsRune("=([{,:+-*/%!&|^<>?", rune(b[i])) {
			return "null"
		}
		if b[i] == ' ' || b[i] == '\t' {
			continue
		}
		break
	}
	return ";"
}

func replaceTemplateAction(b []byte, start, end int, replacement string) {
	blank(b, start, end)
	segmentStart, segmentEnd := -1, -1
	for i := start + 2; i < end-2; {
		j := i
		for j < end-2 && b[j] != '\n' && b[j] != '\r' {
			j++
		}
		if j-i >= len(replacement) {
			segmentStart, segmentEnd = i, j
			break
		}
		i = j + 1
	}
	if segmentStart < 0 {
		// Tiny actions such as {{.}} cannot hold "null"; zero is a valid
		// neutral expression and keeps the original source width.
		replacement = "0"
		for i := start + 2; i < end-2; {
			j := i
			for j < end-2 && b[j] != '\n' && b[j] != '\r' {
				j++
			}
			if j > i {
				segmentStart, segmentEnd = i, j
				break
			}
			i = j + 1
		}
	}
	if segmentStart >= 0 && segmentEnd-segmentStart >= len(replacement) {
		copy(b[segmentStart:], replacement)
	}
}

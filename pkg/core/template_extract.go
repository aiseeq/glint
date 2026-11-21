package core

import (
	"bytes"
	"regexp"
	"slices"
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
	line := lastTemplateCodeLine(code)
	before := lastWord(line)
	previous := lastNonSpaceByte(line)
	next := nextNonSpaceByte(b, end)
	after := nextWord(b, end)
	if replacement, ok := templateLexicalReplacement(b, at, end, code, line, before, next); ok {
		return replacement
	}
	if replacement, ok := templateStructuralReplacement(b, at, end, code, line, before, previous, next, after); ok {
		return replacement
	}
	return templateOperatorReplacement(b, end, code, before, after, previous, next)
}

func templateLexicalReplacement(b []byte, at, end int, code, line []byte, before string, next byte) (string, bool) {
	prefix := strings.TrimSpace(string(code))
	if strings.HasSuffix(prefix, ".") {
		if templateDecimalPoint(code) {
			return "0", true
		}
		return "_", true
	}
	if templateEmptyAction(b[at+2 : end-2]) {
		return "", true
	}
	if before == "import" {
		return `"x"`, true
	}
	if templateBindingPosition(line, next) || (before == "class" || before == "function") && (next == '{' || next == '(') {
		return "_", true
	}
	trimmed := strings.TrimSpace(string(line))
	if before == "from" && (len(trimmed) == len("from") || isTemplateWordBoundary(trimmed[len(trimmed)-len("from")-1])) {
		return `"x"`, true
	}
	// html/template pads values adjacent to keywords with spaces. Preserve
	// that lexical boundary in the virtual source as well.
	if (before == "yield" || before == "await") && templateValueStart(next) {
		return "+", true
	}
	if slices.Contains([]string{"return", "throw", "yield", "await", "typeof", "void", "delete", "new"}, before) {
		return " null", true
	}
	return "", false
}

func templateStructuralReplacement(b []byte, at, end int, code, line []byte, before string, previous, next byte, after string) (string, bool) {
	if before == "try" || before == "finally" || templateIsCatchClause(line) {
		// try, catch (e) and finally take a block, not a statement.
		return "{}", true
	}
	if previous == 0 && templateActionIsTemplate(b[at+2:end-2]) {
		if templateObjectLiteralContext(code) {
			return "", true
		}
		if templateSwitchBlock(code) {
			return "default:;", true
		}
	}
	if previous == 0 && next == ':' && templateObjectLiteralContext(code) {
		return "null", true
	}
	if replacement, ok := templateStructuralKeyword(before, line, code, next); ok {
		return replacement, true
	}
	if replacement, ok := templateStructuralColonOrBody(b, at, end, code, line, previous, next); ok {
		return replacement, true
	}
	if before == "else" || after == "else" {
		if templateActionIsTemplate(b[at+2 : end-2]) {
			return ";", true
		}
		return "null", true
	}
	return "", false
}

func templateStructuralKeyword(before string, line, code []byte, next byte) (string, bool) {
	if templateForHeaderValue(code) || templateOperatorWord(before, line) || before == "extends" || before == "case" || before == "instanceof" {
		return "null", true
	}
	if (before == "yield" || before == "await") && (isTemplateOperandStart(next) || next == '{') {
		return "+", true
	}
	if before == "in" {
		trimmed := strings.TrimSpace(string(line))
		operand := strings.TrimSpace(strings.TrimSuffix(trimmed, "in"))
		if len(operand) > 0 && isTemplateOperandEnd(operand[len(operand)-1]) {
			return " null", true
		}
	}
	if before == "default" && strings.Contains(string(line), "export") {
		return "null", true
	}
	return "", false
}

func templateStructuralColonOrBody(b []byte, at, end int, code, line []byte, previous, next byte) (string, bool) {
	if previous == ':' {
		if templateCaseOrLabelColon(line, code) && next != '.' && next != '(' {
			return ";", true
		}
		return "null", true
	}
	if templateActionIsTemplate(b[at+2:end-2]) && (previous == '{' || previous == ',') {
		if templateObjectLiteralContext(code) {
			return "", true
		}
		if previous == '{' {
			if templateSwitchBlock(code) {
				return "default:;", true
			}
			return ";", true
		}
	}
	return "", false
}

func templateOperatorReplacement(b []byte, end int, code []byte, before, after string, previous, next byte) string {
	if isTemplateOperandEnd(previous) && (isTemplateOperandStart(next) || templateUnaryStart(next) || templateNextActionIsValue(b, end)) && !templateControlHeaderEnd(code) &&
		!templateKeyword(before) && (!templateKeyword(after) || templateValueKeywords[after]) {
		return "+"
	}
	if previous == ';' && templateForHeaderValue(code) {
		return "null"
	}
	if previous == 0 &&
		(strings.ContainsRune(".([=", rune(next)) || templateBinaryStart(next)) {
		return "null"
	}
	if strings.ContainsRune("=([{,:+-*/%!&|^<>?", rune(previous)) || templateUnaryStart(next) {
		return "null"
	}
	return ";"
}

func lastTemplateCodeLine(code []byte) []byte {
	line := code[bytes.LastIndexAny(code, "\r\n")+1:]
	if len(bytes.TrimSpace(line)) == 0 {
		for end := bytes.LastIndexAny(code, "\r\n"); end >= 0; end = bytes.LastIndexAny(code[:end], "\r\n") {
			start := bytes.LastIndexAny(code[:end], "\r\n") + 1
			if len(bytes.TrimSpace(code[start:end])) != 0 {
				last := lastNonSpaceByte(code[start:end])
				if last == ';' || last == '}' || last == '{' {
					return line
				}
				return code[start:end]
			}
		}
	}
	return line
}

func templateEmptyAction(action []byte) bool {
	body := strings.TrimSpace(string(action))
	return strings.HasPrefix(body, "/*") || strings.Contains(body, ":=")
}

func templateBindingPosition(line []byte, next byte) bool {
	trimmed := strings.TrimSpace(string(line))
	switch trimmed {
	case "const", "let", "var", "function", "class", "export":
		return true
	}
	return next == '=' && strings.TrimSpace(string(line)) == ""
}

func templateActionIsTemplate(action []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(action)), "template ")
}

func templateOperatorWord(word string, line []byte) bool {
	switch word {
	case "case", "instanceof":
		return true
	case "in":
		return templateForEachHeader(line)
	case "of":
		return templateForEachHeader(line)
	}
	return false
}

func templateUnaryStart(c byte) bool {
	return strings.ContainsRune("-+!~.", rune(c))
}

func templateValueStart(c byte) bool {
	return isTemplateOperandStart(c) || c == '{'
}

func templateBinaryStart(c byte) bool {
	return strings.ContainsRune("+-*/%&|^<>", rune(c))
}

func templateNextActionIsValue(b []byte, end int) bool {
	for end < len(b) && (b[end] == ' ' || b[end] == '\t') {
		end++
	}
	if !bytes.HasPrefix(b[end:], []byte("{{")) {
		return false
	}
	close := bytes.Index(b[end+2:], []byte("}}"))
	if close < 0 {
		return false
	}
	return !templateEmptyAction(b[end+2:end+2+close]) && !templateActionIsTemplate(b[end+2:end+2+close])
}

func templateSwitchBlock(code []byte) bool {
	open := templateUnmatchedOpenBrace(code)
	if open < 0 {
		return false
	}
	head := bytes.TrimSpace(code[:open])
	if len(head) == 0 || head[len(head)-1] != ')' {
		return false
	}
	depth := 0
	for i := len(head) - 1; i >= 0; i-- {
		switch head[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return lastWord(head[:i]) == "switch" && !templateSwitchDefault.Match(code[open+1:])
			}
		}
	}
	return false
}

func templateUnmatchedOpenBrace(code []byte) int {
	depth := 0
	for i := len(code) - 1; i >= 0; i-- {
		switch code[i] {
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

func templateTernaryColon(code []byte) bool {
	end := len(code)
	for end > 0 && (code[end-1] == ' ' || code[end-1] == '\t' || code[end-1] == '\r' || code[end-1] == '\n') {
		end--
	}
	if end > 0 && code[end-1] == ':' {
		end--
	}
	return bytes.LastIndexByte(code[:end], '?') > bytes.LastIndexByte(code[:end], ':')
}

func templateDecimalPoint(code []byte) bool {
	end := len(code)
	for end > 0 && (code[end-1] == ' ' || code[end-1] == '\t') {
		end--
	}
	if end < 2 || code[end-1] != '.' || code[end-2] < '0' || code[end-2] > '9' {
		return false
	}
	start := end - 2
	for start > 0 && code[start-1] >= '0' && code[start-1] <= '9' {
		start--
	}
	return start == 0 || isTemplateWordBoundary(code[start-1])
}

func templateForHeaderValue(code []byte) bool {
	close := len(code)
	for close > 0 && (code[close-1] == ' ' || code[close-1] == '\t' || code[close-1] == '\r' || code[close-1] == '\n') {
		close--
	}
	if close == 0 || code[close-1] != ';' {
		return false
	}
	open := bytes.LastIndexByte(code[:close], '(')
	if open < 0 || lastWord(code[:open]) != "for" {
		return false
	}
	return true
}

func templateForEachHeader(line []byte) bool {
	trimmed := strings.TrimSpace(string(line))
	return strings.HasPrefix(trimmed, "for ") || strings.HasPrefix(trimmed, "for(")
}

func templateCaseOrLabelColon(line, code []byte) bool {
	if templateObjectLiteralContext(code) || templateTernaryColon(code) {
		return false
	}
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 || trimmed[len(trimmed)-1] != ':' {
		return false
	}
	text := string(trimmed)
	if strings.Contains(text, "case ") {
		return true
	}
	if strings.ContainsAny(text, "=([{,?+*/") {
		return false
	}
	return lastWord(trimmed[:len(trimmed)-1]) != ""
}

func templateObjectLiteralContext(code []byte) bool {
	depth := 0
	open := -1
	for i := len(code) - 1; i >= 0; i-- {
		switch code[i] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				open = i
				i = -1
			} else {
				depth--
			}
		}
	}
	if open < 0 {
		return false
	}
	before := strings.TrimSpace(string(code[:open]))
	if strings.HasSuffix(before, ")") {
		return false
	}
	if strings.HasSuffix(before, ",") {
		call := bytes.LastIndexByte(code[:open], '(')
		if call >= 0 && templateCallHead(code[:call]) {
			return true
		}
	}
	return strings.Contains(before, "=") || strings.HasSuffix(before, "return") || strings.HasSuffix(before, "(") || strings.HasSuffix(before, ":")
}

func templateCallHead(code []byte) bool {
	code = bytes.TrimSpace(code)
	if len(code) == 0 {
		return false
	}
	last := code[len(code)-1]
	return isTemplateOperandEnd(last) || last == '>'
}

type templatePrefixScanner struct {
	code         []byte
	quote        byte
	escaped      bool
	lineComment  bool
	blockComment bool
	inRegex      bool
	templates    []templateLiteralFrame
}

type templateLiteralFrame struct {
	inExpression bool
	braceDepth   int
	escaped      bool
}

func templateCodePrefix(b []byte, start, at int) ([]byte, bool) {
	scanner := templatePrefixScanner{code: make([]byte, 0, at-start)}
	for i := start; i < at; {
		i = scanner.consume(b, i, at)
	}
	return scanner.code, scanner.quote != 0 || scanner.inRegex || scanner.inTemplateRaw()
}

func (s *templatePrefixScanner) consume(b []byte, i, end int) int {
	if s.inTemplateRaw() {
		return s.consumeTemplateRaw(b, i, end)
	}
	c := b[i]
	if s.lineComment {
		return s.consumeLineComment(c, i)
	}
	if s.blockComment {
		return s.consumeBlockComment(b, c, i, end)
	}
	if s.quote != 0 {
		return s.consumeQuoted(c, i)
	}
	if len(s.templates) > 0 && s.templates[len(s.templates)-1].inExpression && (c == '{' || c == '}') {
		return s.consumeTemplateBrace(c, i)
	}
	if c == '/' && i+1 < end && (b[i+1] == '/' || b[i+1] == '*') {
		s.code = append(s.code, ' ')
		if b[i+1] == '/' {
			s.lineComment = true
		} else {
			s.blockComment = true
		}
		return i + 2
	}
	if c == '/' && templateRegexCanStart(s.code) {
		return s.consumeRegex(b, i, end)
	}
	if c == '`' {
		s.templates = append(s.templates, templateLiteralFrame{})
		s.code = append(s.code, c)
		return i + 1
	}
	if c == '\'' || c == '"' {
		s.quote = c
	}
	s.code = append(s.code, c)
	return i + 1
}

func (s *templatePrefixScanner) inTemplateRaw() bool {
	return len(s.templates) > 0 && !s.templates[len(s.templates)-1].inExpression
}

func (s *templatePrefixScanner) consumeTemplateRaw(b []byte, i, end int) int {
	frame := &s.templates[len(s.templates)-1]
	c := b[i]
	s.code = append(s.code, c)
	if frame.escaped {
		frame.escaped = false
		return i + 1
	}
	if c == '\\' {
		frame.escaped = true
		return i + 1
	}
	if c == '`' {
		s.templates = s.templates[:len(s.templates)-1]
		return i + 1
	}
	if c == '$' && i+1 < end && b[i+1] == '{' {
		frame.inExpression = true
		frame.braceDepth = 1
		s.code = append(s.code, '{')
		return i + 2
	}
	return i + 1
}

func (s *templatePrefixScanner) consumeTemplateBrace(c byte, i int) int {
	frame := &s.templates[len(s.templates)-1]
	if c == '{' {
		frame.braceDepth++
	} else {
		frame.braceDepth--
		if frame.braceDepth == 0 {
			frame.inExpression = false
		}
	}
	s.code = append(s.code, c)
	return i + 1
}

func (s *templatePrefixScanner) consumeLineComment(c byte, i int) int {
	if c == '\n' || c == '\r' {
		s.lineComment = false
		s.code = append(s.code, c)
	}
	return i + 1
}

func (s *templatePrefixScanner) consumeBlockComment(b []byte, c byte, i, end int) int {
	if c == '\n' || c == '\r' {
		s.code = append(s.code, c)
		return i + 1
	}
	if c == '*' && i+1 < end && b[i+1] == '/' {
		s.blockComment = false
		s.code = append(s.code, ' ')
		return i + 2
	}
	return i + 1
}

func (s *templatePrefixScanner) consumeQuoted(c byte, i int) int {
	s.code = append(s.code, c)
	if s.escaped {
		s.escaped = false
	} else if c == '\\' {
		s.escaped = true
	} else if c == s.quote {
		s.quote = 0
	}
	return i + 1
}

func (s *templatePrefixScanner) consumeRegex(b []byte, i, end int) int {
	inClass, escaped := false, false
	s.inRegex = true
	for i++; i < end; i++ {
		c := b[i]
		if escaped {
			escaped = false
		} else if c == '\\' {
			escaped = true
		} else if c == '[' {
			inClass = true
		} else if c == ']' {
			inClass = false
		} else if c == '/' && !inClass {
			s.inRegex = false
			i = templateRegexFlagsEnd(b, i+1, end) - 1
			break
		}
	}
	s.code = append(s.code, 'r')
	return i + 1
}

func templateRegexFlagsEnd(b []byte, i, end int) int {
	for i < end && ((b[i] >= 'a' && b[i] <= 'z') || (b[i] >= 'A' && b[i] <= 'Z')) {
		i++
	}
	return i
}

func templateRegexCanStart(code []byte) bool {
	trimmed := bytes.TrimSpace(code)
	if bytes.HasSuffix(trimmed, []byte("++")) || bytes.HasSuffix(trimmed, []byte("--")) {
		return false
	}
	previous := lastNonSpaceByte(code)
	if previous == 0 || strings.ContainsRune("=(:,[!&|?{};+-*%^~<>", rune(previous)) {
		return true
	}
	word := lastWord(code)
	if word == "of" && !templateForEachHeader(lastTemplateCodeLine(code)) {
		return false
	}
	if (word == "await" || word == "yield") && templateContextualBinding.Match(code) {
		return false
	}
	switch word {
	case "return", "throw", "case", "delete", "void", "typeof", "instanceof", "in", "yield", "await":
		return true
	}
	return false
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

// templateKeywords are the JavaScript reserved words that are not values
// (let, of, yield and await are names outside their contexts): an action
// next to one (if (a) {{template "s" .}} else ..., do {{...}} while) is a
// statement, not an operator between two operands.
var templateKeywords = map[string]bool{
	"break": true, "case": true, "catch": true, "class": true, "const": true, "continue": true,
	"debugger": true, "default": true, "delete": true, "do": true, "else": true, "export": true,
	"extends": true, "finally": true, "for": true, "function": true, "if": true, "import": true,
	"in": true, "instanceof": true, "new": true, "return": true,
	"switch": true, "throw": true, "try": true, "typeof": true, "var": true, "void": true,
	"while": true, "with": true,
}

// templateValueKeywords start a value: a {{.Op}} new Date() is still an
// operator between operands.
var templateValueKeywords = map[string]bool{
	"new": true, "typeof": true, "void": true, "delete": true, "function": true, "class": true, "await": true,
}

// templateCatchPrefix is a catch clause, not a .catch method or property.
var templateCatchPrefix = regexp.MustCompile(`(?:^|[^.\s])\s*\bcatch\b`)
var templateContextualBinding = regexp.MustCompile(`\b(?:var|let|const)\s+(?:await|yield)\b`)
var templateSwitchDefault = regexp.MustCompile(`\bdefault\s*:`)

func templateIsCatchClause(line []byte) bool {
	match := templateCatchPrefix.FindIndex(line)
	if match == nil {
		return false
	}
	i := match[1]
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i == len(line) {
		return true
	}
	if line[i] != '(' {
		return false
	}
	depth := 0
	for ; i < len(line); i++ {
		switch line[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				i++
				for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
					i++
				}
				return i == len(line)
			}
		}
	}
	return false
}

func templateKeyword(word string) bool {
	return templateKeywords[word]
}

// templateControlHeaderEnd reports whether code ends with the closing
// parenthesis of an if, while, for or with header: what follows it is the
// statement body, not an operand.
func templateControlHeaderEnd(code []byte) bool {
	end := len(code)
	for end > 0 && (code[end-1] == ' ' || code[end-1] == '\t' || code[end-1] == '\n' || code[end-1] == '\r') {
		end--
	}
	if end == 0 || code[end-1] != ')' {
		return false
	}
	depth := 0
	for i := end - 1; i >= 0; i-- {
		switch code[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				switch lastWord(code[:i]) {
				case "if", "while", "for", "with":
					return true
				}
				return false
			}
		}
	}
	return false
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

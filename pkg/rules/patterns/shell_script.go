package patterns

import (
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// shellLine is one logical command line of a shell script or a make recipe:
// physical lines joined at their trailing backslash. In a make recipe the
// leading tab and the @, - and + prefixes are dropped and $$ reads as $, so
// the text is what the shell runs.
type shellLine struct {
	text   string
	starts []int // offset in text where each physical line begins
	nums   []int // the 1-based number of each of those physical lines
	block  int   // make: index of the recipe; a script is one block
}

// lineAt returns the physical line of an offset in the text.
func (l shellLine) lineAt(offset int) int {
	i := sort.Search(len(l.starts), func(i int) bool { return l.starts[i] > offset }) - 1
	if i < 0 {
		i = 0
	}
	return l.nums[i]
}

// lineBuilder joins physical lines into a logical one.
type lineBuilder struct {
	text   strings.Builder
	starts []int
	nums   []int
}

// add appends a physical line.
func (b *lineBuilder) add(num int, text string) {
	b.starts = append(b.starts, b.text.Len())
	b.nums = append(b.nums, num)
	b.text.WriteString(text)
}

// addLine appends a logical line with its physical lines.
func (b *lineBuilder) addLine(l shellLine) {
	base := b.text.Len()
	for j := range l.starts {
		b.starts = append(b.starts, base+l.starts[j])
		b.nums = append(b.nums, l.nums[j])
	}
	b.text.WriteString(l.text)
}

// line returns the logical line built so far.
func (b *lineBuilder) line(block int) shellLine {
	return shellLine{text: b.text.String(), starts: b.starts, nums: b.nums, block: block}
}

// shellSource is a script or a make file read as shell.
type shellSource struct {
	ctx   *core.FileContext
	make  bool
	lines []shellLine
	// makeShell is the SHELL a make file sets outside its recipes, "" when
	// it sets none; makeFlags its .SHELLFLAGS.
	makeShell, makeFlags string
}

// readShell returns the shell of a script (.sh) or of the recipes of a make
// file; false for any other file.
func readShell(ctx *core.FileContext) (*shellSource, bool) {
	switch {
	case ctx.IsShellFile():
		return &shellSource{ctx: ctx, lines: scriptLines(ctx.Lines)}, true
	case ctx.IsMakefile():
		src := &shellSource{ctx: ctx, make: true}
		src.lines = recipeLines(ctx.Lines, src)
		return src, true
	}
	return nil, false
}

// units returns what one shell runs: the whole script, or each logical line
// of a recipe (make starts a shell per line). A script's lines are joined
// with newlines, which segments treats as a list operator.
func (src *shellSource) units() []shellLine {
	if src.make {
		return src.lines
	}
	if len(src.lines) == 0 {
		return nil
	}
	var whole lineBuilder
	for i, l := range src.lines {
		if i > 0 {
			whole.text.WriteString("\n")
		}
		whole.addLine(l)
	}
	return []shellLine{whole.line(0)}
}

var makeShellAssign = regexp.MustCompile(`^\s*(?:export\s+)?(SHELL|\.SHELLFLAGS)\s*[:?+!]?=\s*(.*)$`)

func scriptLines(lines []string) []shellLine {
	var out []shellLine
	var cur *lineBuilder
	for i, raw := range lines {
		if cur == nil {
			if t := strings.TrimSpace(raw); t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			cur = &lineBuilder{}
		}
		body, more := strings.CutSuffix(raw, "\\")
		cur.add(i+1, body)
		if more {
			cur.text.WriteString(" ")
			continue
		}
		if continuesCommand(cur.text.String()) {
			cur.text.WriteString(" ")
			continue
		}
		out = append(out, cur.line(0))
		cur = nil
	}
	if cur != nil {
		out = append(out, cur.line(0))
	}
	return out
}

// continuesCommand reports a command line ending in an unquoted |, && or
// ||: the command goes on on the next line.
func continuesCommand(text string) bool {
	trimmed := strings.TrimRight(withoutComment(text), " \t")
	if !strings.HasSuffix(trimmed, "|") && !strings.HasSuffix(trimmed, "&&") {
		return false
	}
	return quoteAt(trimmed, len(trimmed)-1) == 0
}

func recipeLines(lines []string, src *shellSource) []shellLine {
	var out []shellLine
	var cur *lineBuilder
	block := 0
	for i, raw := range lines {
		if cur == nil {
			if !strings.HasPrefix(raw, "\t") {
				src.readMakeSetting(raw)
				if strings.TrimSpace(raw) != "" {
					block++
				}
				continue
			}
			body := strings.TrimLeft(raw[1:], " \t")
			if strings.HasPrefix(body, "#") || body == "" {
				continue
			}
			cur = &lineBuilder{}
			raw = strings.TrimLeft(body, "@-+ \t")
		}
		body, more := strings.CutSuffix(raw, "\\")
		if strings.HasPrefix(strings.TrimSpace(body), "#") {
			body = "" // a comment ends at its newline; the next line still runs
		}
		cur.add(i+1, strings.ReplaceAll(body, "$$", "$"))
		if more {
			cur.text.WriteString(" ")
			continue
		}
		out = append(out, unwrapBashC(cur.line(block)))
		cur = nil
	}
	if cur != nil {
		out = append(out, unwrapBashC(cur.line(block)))
	}
	return out
}

// readMakeSetting records a SHELL or .SHELLFLAGS assignment of a make file.
func (src *shellSource) readMakeSetting(raw string) {
	m := makeShellAssign.FindStringSubmatch(raw)
	switch {
	case m == nil:
	case m[1] == "SHELL":
		src.makeShell = m[2]
	default:
		src.makeFlags = m[2]
	}
}

var bashCScript = regexp.MustCompile(`^(\s*(?:bash|sh)\s+-c\s+')(.*)'\s*$`)

// unwrapBashC turns a recipe line written as bash -c '<script>' into the
// script: the wrapper is blanked, and each escaped quote inside the script
// (closing quote, escaped quote, reopening quote) becomes the one quote it
// stands for, padded so that the offsets keep their lines.
func unwrapBashC(l shellLine) shellLine {
	m := bashCScript.FindStringSubmatchIndex(l.text)
	if m == nil {
		return l
	}
	raw := l.text[m[4]:m[5]]
	script := strings.ReplaceAll(raw, `'"'"'`, `    '`)
	script = strings.ReplaceAll(script, `'\''`, `   '`)
	if strings.Count(raw, "'") != 3*strings.Count(raw, `'"'"'`)+3*strings.Count(raw, `'\''`) {
		return l // a bare quote closes the script early: not one script
	}
	l.text = strings.Repeat(" ", m[3]) + script + strings.Repeat(" ", len(l.text)-m[5])
	return l
}

// suppressed reports a "# nolint:<rule>" or "# <rule>: safe" comment on the
// line or the one above it.
func (src *shellSource) suppressed(line int, rule string) bool {
	for l := line - 1; l <= line; l++ {
		if l < 1 || l > len(src.ctx.Lines) {
			continue
		}
		text := src.ctx.Lines[l-1]
		if i := strings.Index(text, "#"); i >= 0 && core.LineSuppresses("//"+text[i+1:], rule) {
			return true
		}
	}
	return false
}

// quoteScanner walks a command line and tells which bytes stand outside
// quotes.
type quoteScanner struct{ quote byte }

// step returns how many bytes at i are quoted or escaped and so are no
// shell syntax; 0 when text[i] is an unquoted byte to look at.
func (q *quoteScanner) step(text string, i int) int {
	c := text[i]
	switch {
	case q.quote != 0:
		if c == '\\' && q.quote == '"' {
			return 2
		}
		if c == q.quote {
			q.quote = 0
		}
		return 1
	case c == '\\':
		return 2
	case c == '\'' || c == '"':
		q.quote = c
		return 1
	}
	return 0
}

// quoteAt returns the quote open at an offset of the text, 0 outside quotes.
func quoteAt(text string, offset int) byte {
	var q quoteScanner
	for i := 0; i < offset && i < len(text); {
		if n := q.step(text, i); n > 0 {
			i += n
			continue
		}
		i++
	}
	return q.quote
}

// insideQuotes reports an offset inside a quoted string of the text.
func insideQuotes(text string, offset int) bool { return quoteAt(text, offset) != 0 }

// insideSingleQuotes reports an offset inside '...', where $ is literal.
func insideSingleQuotes(text string, offset int) bool { return quoteAt(text, offset) == '\'' }

// shellSegment is a command between the list operators of a line (;, &&,
// ||, &, newline); a pipeline stays one segment. Groups, subshells and
// command substitutions are part of the segment they are written in.
type shellSegment struct {
	text   string
	offset int    // in the line text
	sep    string // the operator after it, "" at the end
}

// trimmed returns the segment without surrounding blanks.
func (s shellSegment) trimmed() string { return strings.TrimSpace(s.text) }

// segments splits a command line at the list operators outside quotes and
// groups.
func segments(text string) []shellSegment { return splitList(text, false) }

// flatSegments splits a command line at every list operator outside quotes,
// inside groups and subshells too: ( a & b & wait ) gives three commands.
func flatSegments(text string) []shellSegment { return splitList(text, true) }

func splitList(text string, flat bool) []shellSegment {
	var out []shellSegment
	var q quoteScanner
	depth, start := 0, 0
	emit := func(end int, sep string) {
		// The segment starts at its command, so that it reports that line.
		for start < end && strings.ContainsRune(" \t\n", rune(text[start])) {
			start++
		}
		out = append(out, shellSegment{text: text[start:end], offset: start, sep: sep})
	}
	for i := 0; i < len(text); {
		if n := q.step(text, i); n > 0 {
			i += n
			continue
		}
		depth += groupChange(text, i, depth)
		if sep := listOperator(text, i); sep != "" && (depth == 0 || flat) {
			emit(i, sep)
			i += len(sep)
			start = i
			continue
		}
		i++
	}
	emit(len(text), "")
	return out
}

// groupChange returns how an unquoted byte changes the group depth: ( and
// "{ " open a group, ) and a "}" ending a command close one.
func groupChange(text string, i, depth int) int {
	switch text[i] {
	case '(':
		return 1
	case ')':
		return -1
	case '{':
		// A brace ending its line - f() { or f() { # comment - leaves the
		// body's commands at the level of the line, closed by a } in the
		// first column; one followed by a command on the line opens a group.
		if i+1 < len(text) && (text[i+1] == ' ' || text[i+1] == '\t') && !restIsComment(text[i+1:]) {
			return 1
		}
	case '}':
		if depth > 0 && (i == 0 || strings.ContainsRune(" ;\t", rune(text[i-1]))) {
			return -1
		}
	}
	return 0
}

// withoutComment cuts a trailing comment: an unquoted # that starts a word.
func withoutComment(text string) string {
	var q quoteScanner
	for i := 0; i < len(text); {
		if n := q.step(text, i); n > 0 {
			i += n
			continue
		}
		if text[i] == '#' && (i == 0 || text[i-1] == ' ' || text[i-1] == '\t') {
			return strings.TrimRight(text[:i], " \t")
		}
		i++
	}
	return text
}

// awkLoop is for ( or while ( of an awk or C program quoted into the script;
// a shell loop takes a word or (( after for and a command after while.
var awkLoop = regexp.MustCompile(`^(?:for|while)\s*\([^(]`)

// shellLoopStart reports a step that opens a shell loop.
func shellLoopStart(text string) bool {
	return loopStart.MatchString(text) && !awkLoop.MatchString(text)
}

// restIsComment reports a line remainder that holds only blanks and a
// comment, or nothing.
func restIsComment(rest string) bool {
	line, _, _ := strings.Cut(rest, "\n")
	line = strings.TrimLeft(line, " \t")
	return line == "" || line[0] == '#'
}

// listOperator returns the list operator at an unquoted byte: a newline, ;,
// &&, || or &; "" for anything else, a pipe and the &> and >& redirections
// included.
func listOperator(text string, i int) string {
	c := text[i]
	double := i+1 < len(text) && text[i+1] == c
	switch {
	case c == '\n' || c == ';':
		return text[i : i+1]
	case (c == '&' || c == '|') && double:
		return text[i : i+2]
	case c == '&' && !isRedirection(text, i):
		return text[i : i+1]
	}
	return ""
}

// isRedirection reports an & that belongs to >&, <& or &>.
func isRedirection(text string, i int) bool {
	before := i > 0 && (text[i-1] == '>' || text[i-1] == '<')
	return before || (i+1 < len(text) && text[i+1] == '>')
}

// lastPipeCommand returns the first word of the last command of a pipeline
// written in text (inside groups too), "" when text has no pipe.
func lastPipeCommand(text string) string {
	var q quoteScanner
	last := -1
	for i := 0; i < len(text); {
		if n := q.step(text, i); n > 0 {
			i += n
			continue
		}
		switch {
		case text[i] != '|':
		case i+1 < len(text) && text[i+1] == '|':
			i++ // ||
		case i > 0 && text[i-1] == '>':
			// >| redirection
		default:
			last = i
		}
		i++
	}
	if last < 0 {
		return ""
	}
	fields := strings.Fields(text[last+1:])
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], "({;")
}

// shellFunc is a function of a script.
type shellFunc struct {
	name   string
	first  int    // index of its first logical line
	last   int    // index of its last logical line
	inline string // the body written on the definition line after "{"
	indent int    // the indent of the definition line
}

var shellFuncStart = regexp.MustCompile(`^(\s*)(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{(.*)$`)

// functions returns the functions of a script by name. A one-line function
// ends on its own line; a longer one at the first "}" indented as its
// definition.
func (src *shellSource) functions() map[string]shellFunc {
	funcs := make(map[string]shellFunc)
	if src.make {
		return funcs
	}
	var open *shellFunc
	for i, l := range src.lines {
		if open != nil {
			if strings.TrimSpace(l.text) == "}" && len(l.text)-len(strings.TrimLeft(l.text, " \t")) <= open.indent {
				open.last = i
				funcs[open.name] = *open
				open = nil
			}
			continue
		}
		m := shellFuncStart.FindStringSubmatch(l.text)
		if m == nil {
			continue
		}
		fn := shellFunc{name: m[2], first: i, last: i, inline: m[3], indent: len(m[1])}
		if strings.HasSuffix(strings.TrimSpace(m[3]), "}") {
			funcs[fn.name] = fn
			continue
		}
		open = &fn
	}
	if open != nil {
		funcs[open.name] = *open // never closed: only its definition line
	}
	return funcs
}

// body returns the logical lines of a function's body with the text of the
// definition line cut to what follows its "{".
func (src *shellSource) body(fn shellFunc) []shellLine {
	var out []shellLine
	for i := fn.first; i <= fn.last && i < len(src.lines); i++ {
		l := src.lines[i]
		if i == fn.first {
			inline := strings.TrimSuffix(strings.TrimSpace(fn.inline), "}")
			l = shellLine{text: inline, starts: []int{0}, nums: []int{l.nums[0]}}
		}
		out = append(out, l)
	}
	return out
}

// violationMaker is what a shell rule reports with.
type violationMaker interface {
	Name() string
	CreateViolation(string, int, string) *core.Violation
}

// report builds a violation of a shell rule at a physical line, nil when a
// comment there suppresses the rule.
func (src *shellSource) report(rule violationMaker, line int, message, suggestion string) *core.Violation {
	if src.suppressed(line, rule.Name()) {
		return nil
	}
	v := rule.CreateViolation(src.ctx.RelPath, line, message)
	if line >= 1 && line <= len(src.ctx.Lines) {
		v.WithCode(strings.TrimSpace(src.ctx.Lines[line-1]))
	}
	v.WithSuggestion(suggestion)
	return v
}

// appendReport appends a violation unless it is nil.
func appendReport(list []*core.Violation, v *core.Violation) []*core.Violation {
	if v == nil {
		return list
	}
	return append(list, v)
}

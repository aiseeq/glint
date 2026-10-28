package patternkit

import (
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// ShellLine is one logical command line of a shell script or a make recipe:
// physical lines joined at their trailing backslash. In a make recipe the
// leading tab and the @, - and + prefixes are dropped and $$ reads as $, so
// the text is what the shell runs.
type ShellLine struct {
	Text   string
	starts []int // offset in text where each physical line begins
	Nums   []int // the 1-based number of each of those physical lines
	block  int   // make: index of the recipe; a script is one block
}

// LineAt returns the physical line of an offset in the text.
func (l ShellLine) LineAt(offset int) int {
	i := max(sort.Search(len(l.starts), func(i int) bool { return l.starts[i] > offset })-1, 0)
	return l.Nums[i]
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
func (b *lineBuilder) addLine(l ShellLine) {
	base := b.text.Len()
	for j := range l.starts {
		b.starts = append(b.starts, base+l.starts[j])
		b.nums = append(b.nums, l.Nums[j])
	}
	b.text.WriteString(l.Text)
}

// line returns the logical line built so far.
func (b *lineBuilder) line(block int) ShellLine {
	return ShellLine{Text: b.text.String(), starts: b.starts, Nums: b.nums, block: block}
}

// ShellSource is a script or a make file read as shell.
type ShellSource struct {
	Ctx   *core.FileContext
	Make  bool
	Lines []ShellLine
	// MakeShell is the SHELL a make file sets outside its recipes, "" when
	// it sets none; makeFlags its .SHELLFLAGS.
	MakeShell, MakeFlags string
}

// ReadShell returns the shell of a script (.sh) or of the recipes of a make
// file; false for any other file.
func ReadShell(ctx *core.FileContext) (*ShellSource, bool) {
	switch {
	case ctx.IsShellFile():
		return &ShellSource{Ctx: ctx, Lines: scriptLines(ctx.Lines)}, true
	case ctx.IsMakefile():
		src := &ShellSource{Ctx: ctx, Make: true}
		src.Lines = recipeLines(ctx.Lines, src)
		return src, true
	}
	return nil, false
}

// Units returns what one shell runs: the whole script, or each logical line
// of a recipe (make starts a shell per line). A script's lines are joined
// with newlines, which segments treats as a list operator.
func (src *ShellSource) Units() []ShellLine {
	if src.Make {
		return src.Lines
	}
	if len(src.Lines) == 0 {
		return nil
	}
	var whole lineBuilder
	for i, l := range src.Lines {
		if i > 0 {
			whole.text.WriteString("\n")
		}
		whole.addLine(l)
	}
	return []ShellLine{whole.line(0)}
}

var makeShellAssign = regexp.MustCompile(`^\s*(?:export\s+)?(SHELL|\.SHELLFLAGS)\s*[:?+!]?=\s*(.*)$`)

func scriptLines(lines []string) []ShellLine {
	var out []ShellLine
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
	trimmed := strings.TrimRight(WithoutComment(text), " \t")
	if !strings.HasSuffix(trimmed, "|") && !strings.HasSuffix(trimmed, "&&") {
		return false
	}
	return QuoteAt(trimmed, len(trimmed)-1) == 0
}

func recipeLines(lines []string, src *ShellSource) []ShellLine {
	var out []ShellLine
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
func (src *ShellSource) readMakeSetting(raw string) {
	m := makeShellAssign.FindStringSubmatch(raw)
	switch {
	case m == nil:
	case m[1] == "SHELL":
		src.MakeShell = m[2]
	default:
		src.MakeFlags = m[2]
	}
}

var bashCScript = regexp.MustCompile(`^(\s*(?:bash|sh)\s+-c\s+')(.*)'\s*$`)

// unwrapBashC turns a recipe line written as bash -c '<script>' into the
// script: the wrapper is blanked, and each escaped quote inside the script
// (closing quote, escaped quote, reopening quote) becomes the one quote it
// stands for, padded so that the offsets keep their lines.
func unwrapBashC(l ShellLine) ShellLine {
	m := bashCScript.FindStringSubmatchIndex(l.Text)
	if m == nil {
		return l
	}
	raw := l.Text[m[4]:m[5]]
	script := strings.ReplaceAll(raw, `'"'"'`, `    '`)
	script = strings.ReplaceAll(script, `'\''`, `   '`)
	if strings.Count(raw, "'") != 3*strings.Count(raw, `'"'"'`)+3*strings.Count(raw, `'\''`) {
		return l // a bare quote closes the script early: not one script
	}
	l.Text = strings.Repeat(" ", m[3]) + script + strings.Repeat(" ", len(l.Text)-m[5])
	return l
}

// suppressed reports a "# nolint:<rule>" or "# <rule>: safe" comment on the
// line or the one above it.
func (src *ShellSource) suppressed(line int, rule string) bool {
	return src.Ctx.IsSuppressed(line, rule)
}

// QuoteScanner walks a command line and tells which bytes stand outside
// quotes.
type QuoteScanner struct{ Quote byte }

// Step returns how many bytes at i are quoted or escaped and so are no
// shell syntax; 0 when text[i] is an unquoted byte to look at.
func (q *QuoteScanner) Step(text string, i int) int {
	c := text[i]
	switch {
	case q.Quote != 0:
		if c == '\\' && q.Quote == '"' {
			return 2
		}
		if c == q.Quote {
			q.Quote = 0
		}
		return 1
	case c == '\\':
		return 2
	case c == '\'' || c == '"':
		q.Quote = c
		return 1
	}
	return 0
}

// QuoteAt returns the quote open at an offset of the text, 0 outside quotes.
func QuoteAt(text string, offset int) byte {
	var q QuoteScanner
	for i := 0; i < offset && i < len(text); {
		if n := q.Step(text, i); n > 0 {
			i += n
			continue
		}
		i++
	}
	return q.Quote
}

// ShellSegment is a command between the list operators of a line (;, &&,
// ||, &, newline); a pipeline stays one segment. Groups, subshells and
// command substitutions are part of the segment they are written in.
type ShellSegment struct {
	Text   string
	Offset int    // in the line text
	Sep    string // the operator after it, "" at the end
}

// Trimmed returns the segment without surrounding blanks.
func (s ShellSegment) Trimmed() string { return strings.TrimSpace(s.Text) }

// Segments splits a command line at the list operators outside quotes and
// groups.
func Segments(text string) []ShellSegment { return SplitList(text, false) }

func SplitList(text string, flat bool) []ShellSegment {
	var out []ShellSegment
	var q QuoteScanner
	depth, start := 0, 0
	emit := func(end int, sep string) {
		// The segment starts at its command, so that it reports that line.
		for start < end && strings.ContainsRune(" \t\n", rune(text[start])) {
			start++
		}
		out = append(out, ShellSegment{Text: text[start:end], Offset: start, Sep: sep})
	}
	for i := 0; i < len(text); {
		if n := q.Step(text, i); n > 0 {
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
		// An unopened ")" ends a case pattern, not a group.
		if depth > 0 {
			return -1
		}
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

// WithoutComment cuts a trailing comment: an unquoted # that starts a word.
func WithoutComment(text string) string {
	var q QuoteScanner
	for i := 0; i < len(text); {
		if n := q.Step(text, i); n > 0 {
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

// ShellFunc is a function of a script.
type ShellFunc struct {
	Name   string
	First  int    // index of its first logical line
	Last   int    // index of its last logical line
	inline string // the body written on the definition line after "{"
	indent int    // the indent of the definition line
}

var ShellFuncStart = regexp.MustCompile(`^(\s*)(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{(.*)$`)

// Functions returns the functions of a script by name. A one-line function
// ends on its own line; a longer one at the first "}" indented as its
// definition.
func (src *ShellSource) Functions() map[string]ShellFunc {
	funcs := make(map[string]ShellFunc)
	if src.Make {
		return funcs
	}
	var open *ShellFunc
	for i, l := range src.Lines {
		if open != nil {
			if strings.TrimSpace(l.Text) == "}" && len(l.Text)-len(strings.TrimLeft(l.Text, " \t")) <= open.indent {
				open.Last = i
				funcs[open.Name] = *open
				open = nil
			}
			continue
		}
		m := ShellFuncStart.FindStringSubmatch(l.Text)
		if m == nil {
			continue
		}
		fn := ShellFunc{Name: m[2], First: i, Last: i, inline: m[3], indent: len(m[1])}
		if strings.HasSuffix(strings.TrimSpace(WithoutComment(m[3])), "}") {
			funcs[fn.Name] = fn
			continue
		}
		open = &fn
	}
	if open != nil {
		funcs[open.Name] = *open // never closed: only its definition line
	}
	return funcs
}

// Body returns the logical lines of a function's body with the text of the
// definition line cut to what follows its "{".
func (src *ShellSource) Body(fn ShellFunc) []ShellLine {
	var out []ShellLine
	for i := fn.First; i <= fn.Last && i < len(src.Lines); i++ {
		l := src.Lines[i]
		if i == fn.First {
			inline := strings.TrimSuffix(strings.TrimSpace(fn.inline), "}")
			l = ShellLine{Text: inline, starts: []int{0}, Nums: []int{l.Nums[0]}}
		}
		out = append(out, l)
	}
	return out
}

// ViolationMaker is what a shell rule reports with.
type ViolationMaker interface {
	Name() string
	CreateViolation(string, int, string) *core.Violation
}

// Report builds a violation of a shell rule at a physical line, nil when a
// comment there suppresses the rule.
func (src *ShellSource) Report(rule ViolationMaker, line int, message, suggestion string) *core.Violation {
	if src.suppressed(line, rule.Name()) {
		return nil
	}
	v := rule.CreateViolation(src.Ctx.RelPath, line, message)
	if line >= 1 && line <= len(src.Ctx.Lines) {
		v.WithCode(strings.TrimSpace(src.Ctx.Lines[line-1]))
	}
	v.WithSuggestion(suggestion)
	return v
}

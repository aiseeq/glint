package shellrules

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

const signalSuggestion = "Prefer not to signal another process: exit with a status code so the parent can handle the failure. If emergency termination is unavoidable, signal only a process you started, using its PID from $!."
const goSignalSuggestion = "Prefer returning an error or exit code so the caller can handle failure. If emergency termination is unavoidable, signal only your own child process using cmd.Process."

type signalImplicitTargetRule struct{ *rules.BaseRule }

var (
	signalShellAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=.*$`)
)

func init() {
	rules.Register(newSignalImplicitTargetRule())
}

func newSignalImplicitTargetRule() *signalImplicitTargetRule {
	return &signalImplicitTargetRule{rules.NewBaseRule("signal-implicit-target", "patterns", "Detects a terminating signal sent to the parent, every process or the caller's process group", core.SeverityHigh)}
}

// AnalyzeFile reads shell scripts and Makefiles; Go files are read by
// AnalyzeGoProject.
func (r *signalImplicitTargetRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.GoAST != nil || !strings.Contains(string(ctx.Content), "kill") {
		return nil
	}
	src, ok := patternkit.ReadShell(ctx)
	if !ok {
		return nil
	}
	return r.shell(ctx, src)
}

func (r *signalImplicitTargetRule) RequiresSSA() bool { return false }

// ReadsNonGoFiles: shell scripts and Makefiles go through AnalyzeFile, cached
// by the file.
func (r *signalImplicitTargetRule) ReadsNonGoFiles() {}

func (r *signalImplicitTargetRule) AnalyzeGoProject(project *core.GoProjectContext) ([]*core.Violation, error) {
	return analyzeSignalProject(project, r.goFile)
}

// ReportsOn reports whether signalImplicitTargetRule can report on this file:
// Go (tests too: their scripts run), shell scripts and Makefiles.
func (r *signalImplicitTargetRule) ReportsOn(ctx *core.FileContext) bool {
	return ctx.IsGoFile() || ctx.IsShellFile() || ctx.IsMakefile()
}

func (r *signalImplicitTargetRule) shell(ctx *core.FileContext, src *patternkit.ShellSource) []*core.Violation {
	var inputs []signalInput
	if src.Make {
		for _, l := range src.Lines {
			next := ""
			if last := l.Nums[len(l.Nums)-1]; last < len(ctx.Lines) {
				next = ctx.Lines[last]
			}
			inputs = append(inputs, signalInput{text: l.Text, lineAt: l.LineAt, next: next})
		}
	} else {
		inputs = textInputs(ctx.Lines, func(i int) int { return i + 1 })
	}
	var out []*core.Violation
	for _, line := range scanSignalLines(inputs, src.Make) {
		out = append(out, signalViolationAt(r, ctx, line))
	}
	return out
}

// textInputs reads lines of text as scanner inputs; line gives the source
// line of the i-th one.
func textInputs(lines []string, line func(i int) int) []signalInput {
	inputs := make([]signalInput, len(lines))
	for i, text := range lines {
		num := line(i)
		inputs[i] = signalInput{text: text, lineAt: func(int) int { return num }}
		if i+1 < len(lines) {
			inputs[i].next = lines[i+1]
		}
	}
	return inputs
}

type shellCommand struct {
	text   string
	offset int
}

type shellWord struct {
	text  string
	start int
}

func shellCommands(line string) []shellCommand {
	line = withoutComment(line)
	return commandsInScript(line, 0, 0)
}

func commandsInScript(text string, base, depth int) []shellCommand {
	if depth > 8 {
		return nil
	}
	var out []shellCommand
	for _, segment := range shellSegments(text, base) {
		words := signalShellWords(segment.text, segment.offset)
		idx := shellCommandIndex(words)
		if idx < 0 || idx >= len(words) {
			continue
		}
		command := filepath.Base(unquote(words[idx].text))
		if command == "kill" {
			args := words[idx+1:]
			out = append(out, shellCommand{text: "kill " + joinShellWords(args), offset: words[idx].start})
		}
		if command == "sh" || command == "bash" {
			if idx+2 < len(words) && unquote(words[idx+1].text) == "-c" {
				out = append(out, commandsInScript(unquote(words[idx+2].text), words[idx+2].start, depth+1)...)
			}
		}
		if command == "trap" && idx+1 < len(words) {
			out = append(out, commandsInScript(unquote(words[idx+1].text), words[idx+1].start, depth+1)...)
		}
	}
	return out
}

type shellSyntax struct {
	quote             signalQuote
	substitutionQuote signalQuote
	substitutionDepth int
	parameterDepth    int
	backtick          bool
}

func (s *shellSyntax) Step(text string, i int) int {
	if s.substitutionDepth > 0 {
		if n := s.substitutionQuote.Step(text, i); n > 0 {
			return n
		}
		if text[i] == '(' {
			s.substitutionDepth++
			return 1
		}
		if text[i] == ')' {
			s.substitutionDepth--
			return 1
		}
		return 1
	}
	if s.parameterDepth > 0 {
		if text[i] == '}' {
			s.parameterDepth--
		}
		return 1
	}
	if s.backtick {
		if text[i] == '\\' && i+1 < len(text) {
			return 2
		}
		if text[i] == '`' {
			s.backtick = false
		}
		return 1
	}
	if n := s.quote.Step(text, i); n > 0 {
		return n
	}
	if text[i] == '$' && i+1 < len(text) && text[i+1] == '(' {
		s.substitutionDepth = 1
		return 2
	}
	if text[i] == '$' && i+1 < len(text) && text[i+1] == '{' {
		s.parameterDepth = 1
		return 2
	}
	if text[i] == '`' {
		s.backtick = true
		return 1
	}
	return 0
}

func shellSegments(text string, base int) []shellCommand {
	var out []shellCommand
	start := 0
	var syntax shellSyntax
	for i := 0; i < len(text); {
		if n := syntax.Step(text, i); n > 0 {
			i += n
			continue
		}
		c := text[i]
		if c == ';' || c == '|' || c == '&' || c == '\n' || c == '(' || c == ')' || c == '{' || c == '}' {
			if strings.TrimSpace(text[start:i]) != "" {
				out = append(out, shellCommand{text: text[start:i], offset: base + start})
			}
			if (c == '|' || c == '&') && i+1 < len(text) && text[i+1] == c {
				i++
			}
			start = i + 1
		}
		i++
	}
	if strings.TrimSpace(text[start:]) != "" {
		out = append(out, shellCommand{text: text[start:], offset: base + start})
	}
	return out
}

func signalShellWords(segment string, base int) []shellWord {
	var out []shellWord
	var syntax shellSyntax
	start := -1
	for i := 0; i < len(segment); {
		if n := syntax.Step(segment, i); n > 0 {
			if start < 0 {
				start = i
			}
			i += n
			continue
		}
		if segment[i] == ' ' || segment[i] == '\t' || segment[i] == '\r' {
			if start >= 0 {
				out = append(out, shellWord{text: segment[start:i], start: base + start})
				start = -1
			}
			i++
			continue
		}
		if start < 0 {
			start = i
		}
		i++
	}
	if start >= 0 {
		out = append(out, shellWord{text: segment[start:], start: base + start})
	}
	return out
}

func shellCommandIndex(words []shellWord) int {
	for i := 0; i < len(words); {
		w := unquote(words[i].text)
		switch {
		case w == "if" || w == "then" || w == "do" || w == "elif" || w == "else" || w == "while" || w == "until" || w == "!" || w == "(" || w == ")" || w == "{" || w == "}":
			i++
		case signalShellAssignment.MatchString(w):
			i++
		case w == "sudo" || w == "exec" || w == "command" || w == "builtin" || w == "nohup":
			i++
		case w == "timeout":
			i++
			if i < len(words) {
				i++
			}
		default:
			return i
		}
	}
	return -1
}

func joinShellWords(words []shellWord) string {
	var parts []string
	for _, w := range words {
		parts = append(parts, w.text)
	}
	return strings.Join(parts, " ")
}

func shellHeredocFeedsInterpreter(line string) bool {
	for _, segment := range shellSegments(withoutComment(line), 0) {
		words := signalShellWords(segment.text, segment.offset)
		idx := shellCommandIndex(words)
		if idx < 0 {
			continue
		}
		name := filepath.Base(unquote(words[idx].text))
		if name == "sh" || name == "bash" || name == "ssh" {
			return true
		}
	}
	return false
}

func badKill(s string) bool {
	words := signalShellWords(s, 0)
	if len(words) == 0 || unquote(words[0].text) != "kill" {
		return false
	}
	args := words[1:]
	j, sig := 0, ""
	for j < len(args) {
		x := unquote(args[j].text)
		if x == "--" {
			j++
			break
		}
		if x == "-l" || x == "-L" {
			return false
		}
		if x == "--signal" || x == "-s" || x == "-n" {
			if j+1 >= len(args) {
				return false
			}
			sig = unquote(args[j+1].text)
			j += 2
			continue
		}
		if after, ok := strings.CutPrefix(x, "--signal="); ok {
			sig = after
			j++
			continue
		}
		if (strings.HasPrefix(x, "-s") || strings.HasPrefix(x, "-n")) && len(x) > 2 {
			sig = x[2:]
			j++
			continue
		}
		if strings.HasPrefix(x, "-") && x != "-" {
			if x == "-1" && sig != "" {
				break
			}
			sig = strings.TrimLeft(x, "-")
			j++
			continue
		}
		break
	}
	if !terminatingShellSignal(sig) {
		return false
	}
	for ; j < len(args); j++ {
		x := unquote(args[j].text)
		if x == "$PPID" || x == "${PPID}" || x == "-1" || x == "0" {
			return true
		}
	}
	return false
}

// harmlessSignals are the signals that end no process by default: 0 only
// checks the target, CHLD, WINCH and URG are ignored, CONT resumes it. The
// numbers are Linux's.
var harmlessSignals = map[string]bool{
	"0": true, "CHLD": true, "17": true, "CONT": true, "18": true,
	"URG": true, "23": true, "WINCH": true, "28": true,
}

func terminatingShellSignal(sig string) bool {
	name := strings.ToUpper(sig)
	return !harmlessSignals[strings.TrimPrefix(name, "SIG")]
}

func unquote(s string) string { return strings.Trim(s, `"'`) }

func (r *signalImplicitTargetRule) goFile(f *core.FileContext, pkg *signalPackage) []*core.Violation {
	if f.GoAST == nil {
		return nil
	}
	var out []*core.Violation
	for _, site := range fileSignalSites(f, pkg) {
		if site.implicitTarget() {
			out = append(out, signalViolation(r, f, site.node))
		}
	}
	if !strings.Contains(string(f.Content), "kill") {
		return out
	}
	var info *types.Info
	if pkg != nil {
		info = pkg.info
	}
	return append(out, goStringFindings(r, f, info)...)
}

func goStringFindings(r *signalImplicitTargetRule, f *core.FileContext, info *types.Info) []*core.Violation {
	var out []*core.Violation
	executed := shellExecutedLiterals(f.GoAST)
	data := dataLiterals(f.GoAST, info)
	ast.Inspect(f.GoAST, func(n ast.Node) bool {
		l, ok := n.(*ast.BasicLit)
		if !ok || l.Kind != token.STRING {
			return true
		}
		value, e := strconv.Unquote(l.Value)
		if e != nil {
			return true
		}
		script := executed[l] || strings.HasPrefix(value, "#!")
		if !script && (singleKillFixture(value) || strings.Contains(value, "\n") || data[l]) {
			return true
		}
		start := f.LineFor(l)
		rawLines := l.Value[0] == '`'
		inputs := textInputs(strings.Split(value, "\n"), func(i int) int {
			if rawLines {
				return start + i
			}
			return start
		})
		for _, line := range scanSignalLines(inputs, false) {
			out = append(out, signalViolationAt(r, f, line))
		}
		return true
	})
	return out
}

func singleKillFixture(value string) bool {
	trimmed := strings.TrimSpace(value)
	if strings.ContainsAny(trimmed, "\r\n") || strings.ContainsAny(trimmed, ";&|") {
		return false
	}
	commands := shellCommands(trimmed)
	if len(commands) != 1 {
		return false
	}
	word := signalShellWords(trimmed, 0)
	if len(word) == 0 || unquote(word[0].text) != "kill" {
		return false
	}
	return true
}

func shellExecutedLiterals(file *ast.File) map[*ast.BasicLit]bool {
	executed := make(map[*ast.BasicLit]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext" {
			return true
		}
		start := 0
		if selector.Sel.Name == "CommandContext" {
			start = 1
		}
		if len(call.Args) < start+3 {
			return true
		}
		shell, shellOK := helpers.StringLiteral(call.Args[start])
		flag, flagOK := helpers.StringLiteral(call.Args[start+1])
		shell = filepath.Base(shell)
		if !shellOK || shell != "sh" && shell != "bash" || !flagOK || flag != "-c" {
			return true
		}
		if literal, ok := ast.Unparen(call.Args[start+2]).(*ast.BasicLit); ok && literal.Kind == token.STRING {
			executed[literal] = true
		}
		return true
	})
	return executed
}

// dataLiterals returns the string literals that code reads as text rather
// than runs: what it compares with, logs or names a subtest by.
func dataLiterals(file *ast.File, info *types.Info) map[*ast.BasicLit]bool {
	data := make(map[*ast.BasicLit]bool)
	mark := func(e ast.Expr) {
		if lit, ok := ast.Unparen(e).(*ast.BasicLit); ok && lit.Kind == token.STRING {
			data[lit] = true
		}
	}
	markAll := func(args []ast.Expr) {
		for _, arg := range args {
			ast.Inspect(arg, func(child ast.Node) bool {
				if e, ok := child.(ast.Expr); ok {
					mark(e)
				}
				return true
			})
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BinaryExpr:
			if n.Op == token.EQL || n.Op == token.NEQ {
				mark(n.X)
				mark(n.Y)
			}
		case *ast.CallExpr:
			switch {
			case isLoggingCall(n, info) || isTextComparison(n):
				markAll(n.Args)
			case isSubtest(n, info):
				mark(n.Args[0])
			}
		}
		return true
	})
	return data
}

// textComparisons are the functions of strings and bytes that look for or
// compare text.
var textComparisons = map[string]bool{
	"Contains": true, "ContainsAny": true, "HasPrefix": true, "HasSuffix": true,
	"Index": true, "IndexAny": true, "LastIndex": true, "LastIndexAny": true,
	"EqualFold": true, "Compare": true, "Count": true, "Cut": true,
	"CutPrefix": true, "CutSuffix": true, "TrimPrefix": true, "TrimSuffix": true,
}

func isTextComparison(call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || !textComparisons[sel.Sel.Name] {
		return false
	}
	pkg, ok := ast.Unparen(sel.X).(*ast.Ident)
	return ok && (pkg.Name == "strings" || pkg.Name == "bytes")
}

// isSubtest reports t.Run or b.Run, whose first argument names a subtest.
func isSubtest(call *ast.CallExpr, info *types.Info) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Run" || len(call.Args) == 0 {
		return false
	}
	// A receiver typed only partially (a test file on an unloaded import) is
	// known by its name.
	if info != nil {
		if t := info.TypeOf(sel.X); t != nil && t != types.Typ[types.Invalid] {
			return testingReceiver(t)
		}
	}
	id, ok := ast.Unparen(sel.X).(*ast.Ident)
	return ok && (id.Name == "t" || id.Name == "b")
}

// loggerPrefixes start the names of logging functions and methods, whatever
// their receiver.
var loggerPrefixes = []string{"Print", "Info", "Warn", "Error", "Debug", "Fatal", "Log"}

func isLoggingCall(call *ast.CallExpr, info *types.Info) bool {
	var name string
	var receiver ast.Expr
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		name, receiver = fun.Sel.Name, fun.X
	default:
		return false
	}
	for _, prefix := range loggerPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	id, ok := receiver.(*ast.Ident)
	if !ok {
		return false
	}
	switch id.Name {
	case "log", "slog":
		return true
	case "fmt":
		return strings.HasPrefix(name, "Sprint") || strings.HasPrefix(name, "Fprint")
	case "errors":
		return name == "New"
	}
	if name != "Skipf" {
		return false
	}
	if info == nil {
		return true
	}
	return testingReceiver(info.TypeOf(receiver))
}

func testingReceiver(t types.Type) bool {
	if pointer, ok := t.(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := t.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "testing" &&
		(named.Obj().Name() == "T" || named.Obj().Name() == "B" || named.Obj().Name() == "TB")
}

func signalViolation(r *signalImplicitTargetRule, f *core.FileContext, n ast.Node) *core.Violation {
	return signalViolationAt(r, f, f.LineFor(n))
}
func signalViolationAt(r *signalImplicitTargetRule, f *core.FileContext, line int) *core.Violation {
	v := r.CreateViolation(f.RelPath, line, "This signal targets the parent, every process or the caller's process group; after orphaning, $PPID may be init or the service manager, and the signal can end the whole session")
	v.WithCode(strings.TrimSpace(f.GetLine(line)))
	if filepath.Ext(f.RelPath) == ".go" {
		v.WithSuggestion(goSignalSuggestion)
	} else {
		v.WithSuggestion(signalSuggestion)
	}
	return v
}

func infoObject(i *types.Info, id *ast.Ident) types.Object {
	if i == nil {
		return nil
	}
	return i.ObjectOf(id)
}
func pidsFrom(e ast.Expr, i *types.Info, p map[types.Object]bool) bool {
	id, ok := ast.Unparen(e).(*ast.Ident)
	return ok && p[infoObject(i, id)]
}
func isTarget(e ast.Expr, i *types.Info, p map[types.Object]bool) bool {
	if isParentProcessID(e, i) || pidsFrom(e, i, p) {
		return true
	}
	u, ok := ast.Unparen(e).(*ast.UnaryExpr)
	return ok && u.Op == token.SUB && strings.HasPrefix(iValue(e, i), "-")
}
func isZeroInt(e ast.Expr, i *types.Info) bool { return iValue(e, i) == "0" }

// harmlessSignal reports a signal value that ends no process by default.
func harmlessSignal(e ast.Expr, i *types.Info) bool { return harmlessSignals[iValue(e, i)] }
func iValue(e ast.Expr, i *types.Info) string {
	if i != nil {
		if v := i.Types[e].Value; v != nil {
			return v.ExactString()
		}
	}
	if b, ok := e.(*ast.BasicLit); ok {
		return b.Value
	}
	return ""
}

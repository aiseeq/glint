package shellrules

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(newShellRule("shell-jq-null-passes-as-value",
		"Detects jq -r '.path' without -e or a // alternative whose output a script compares or builds a name or path from — a missing key arrives as the string null",
		core.SeverityMedium, checkJqNullValue))
	rules.Register(newShellRule("shell-getter-default-on-missing-file",
		"Detects a function whose output callers capture that prints a literal when its state file is missing — the made-up value passes for the real one",
		core.SeverityMedium, checkGetterDefault))
}

var (
	// jqRawPath is jq with its options and a plain path filter: .a.b, .a[0].
	jqRawPath = regexp.MustCompile(`\bjq((?:\s+-{1,2}[A-Za-z-]+)*)\s+(?:'(\.[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])*)'|"(\.[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])*)")`)
	// captureAssignment is NAME=$(...), with local, readonly or declare.
	captureAssignment = regexp.MustCompile(`^(?:(?:local|readonly|declare|export)\s+(?:-\w+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)="?\$\(`)
)

// jqRawOutput reports a jq invocation printing a plain path raw, without -e
// (--exit-status): a missing key prints null and exits 0.
func jqRawOutput(command string) bool {
	m := jqRawPath.FindStringSubmatch(command)
	if m == nil {
		return false
	}
	raw, exit := false, false
	for opt := range strings.FieldsSeq(m[1]) {
		switch {
		case opt == "--raw-output":
			raw = true
		case opt == "--exit-status":
			exit = true
		case !strings.HasPrefix(opt, "--"):
			raw = raw || strings.Contains(opt, "r")
			exit = exit || strings.Contains(opt, "e")
		}
	}
	return raw && !exit
}

// checkJqNullValue reports jq -r reading a plain path whose value the script
// uses to choose between working branches or puts into a name or a path
// without checking it for null: the value is captured into a variable, or
// printed by a function whose output a caller captures.
func checkJqNullValue(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	if src.Make {
		return nil
	}
	funcs := src.Functions()
	captures := captureTargets(src, funcs)
	var out []*core.Violation
	report := func(line int, variable string) {
		out = appendReport(out, src.Report(r, line,
			"jq -r prints null for a missing key and succeeds, and $"+variable+" picks a branch or builds a name without a check for null",
			"Make a missing key fail (jq -er) or give it a value (jq -r '.key // empty'), or check the result for \"null\""))
	}
	for name, fn := range funcs {
		for _, l := range src.Body(fn) {
			for _, seg := range patternkit.Segments(l.Text) {
				text := patternkit.CommandPrefix.ReplaceAllString(seg.Trimmed(), "")
				if !strings.HasPrefix(text, "jq ") || !jqRawOutput(text) || !patternkit.WritesToStdout(text) {
					continue
				}
				for _, c := range captures[name] {
					if usedAsValue(c.scope, c.variable) {
						report(l.LineAt(seg.Offset), c.variable)
						break
					}
				}
			}
		}
	}
	for i, l := range src.Lines {
		for _, seg := range patternkit.Segments(l.Text) {
			text := seg.Trimmed()
			m := captureAssignment.FindStringSubmatch(text)
			if m == nil || !jqRawOutput(text) {
				continue
			}
			if usedAsValue(scopeOf(src, funcs, i), m[1]) {
				report(l.LineAt(seg.Offset), m[1])
			}
		}
	}
	return out
}

// capture is a variable a command's output is captured into, with the lines
// where the variable lives.
type capture struct {
	variable string
	scope    []patternkit.ShellLine
}

// captureTargets returns, per command name, the variables its output is
// captured into: active=$(get_active_color).
func captureTargets(src *patternkit.ShellSource, funcs map[string]patternkit.ShellFunc) map[string][]capture {
	targets := make(map[string][]capture)
	for i, l := range src.Lines {
		for _, seg := range patternkit.Segments(l.Text) {
			text := seg.Trimmed()
			m := captureAssignment.FindStringSubmatch(text)
			if m == nil {
				continue
			}
			if call := patternkit.CaptureCall.FindStringSubmatch(text[len(m[0])-2:]); call != nil {
				targets[call[1]] = append(targets[call[1]], capture{variable: m[1], scope: scopeOf(src, funcs, i)})
			}
		}
	}
	return targets
}

// scopeOf returns the lines of the innermost function that holds the line,
// or the whole script for a line outside functions.
func scopeOf(src *patternkit.ShellSource, funcs map[string]patternkit.ShellFunc, index int) []patternkit.ShellLine {
	var inner *patternkit.ShellFunc
	innerName := ""
	for name, fn := range funcs {
		if fn.First > index || index > fn.Last {
			continue
		}
		// Two functions defined on one line start together; the name decides.
		if inner == nil || fn.First > inner.First || fn.First == inner.First && name < innerName {
			inner, innerName = &fn, name
		}
	}
	if inner == nil {
		return src.Lines
	}
	return src.Body(*inner)
}

var (
	ifTest         = regexp.MustCompile(`^\s*(?:if|elif)\s+(?:!\s+)?(?:\[\[?|test)\s`)
	caseOn         = regexp.MustCompile(`^\s*case\s`)
	messageCommand = regexp.MustCompile(`^(?:echo|printf|log_?\w*)\b`)
	branchFailure  = regexp.MustCompile(`(?i)\bexit\b|\breturn\s+[1-9]|\blog_?(?:error|fatal|fail|warn)|\b(?:die|fail|error|warn)\b|>&2`)
)

// usedAsValue reports a variable the lines glue into a word (a name, a
// path; a message only shows it) or test to choose between branches that both go on working, and
// never check for null. A test with a branch that fails or warns validates
// the value: "null" takes that branch.
func usedAsValue(scope []patternkit.ShellLine, variable string) bool {
	ref := regexp.MustCompile(`\$(?:\{` + variable + `\}|` + variable + `\b)`)
	glued := regexp.MustCompile(`[\w./-]\$(?:\{` + variable + `\}|` + variable + `\b)|\$\{` + variable + `\}[\w./-]|\$` + variable + `[./-]`)
	used := false
	for i, l := range scope {
		if !ref.MatchString(l.Text) {
			continue
		}
		if strings.Contains(l.Text, "null") {
			return false
		}
		if captureAssignment.MatchString(strings.TrimSpace(l.Text)) && !strings.Contains(l.Text, ";") {
			continue // the assignment itself
		}
		switch {
		case glued.MatchString(l.Text) && !messageCommand.MatchString(strings.TrimSpace(l.Text)):
			used = true
		case ifTest.MatchString(l.Text) || caseOn.MatchString(l.Text):
			alternatives, validates := branchKinds(scope, i)
			if validates {
				return false
			}
			used = used || alternatives
		}
	}
	return used
}

// branchKinds tells whether the if or case statement at index i chooses
// between working branches (more than one, none failing or warning), and
// whether one of its branches fails or warns.
func branchKinds(scope []patternkit.ShellLine, i int) (alternatives, validates bool) {
	if branchFailure.MatchString(scope[i].Text) {
		return false, true
	}
	return workingAlternatives(scope, i), branchFails(scope, i)
}

// branchFails reports a failing or warning command inside the if or case
// statement at index i.
func branchFails(scope []patternkit.ShellLine, i int) bool {
	depth := 0
	for j := i + 1; j < len(scope); j++ {
		text := strings.TrimSpace(scope[j].Text)
		if branchFailure.MatchString(text) {
			return true
		}
		switch {
		case strings.HasPrefix(text, "if ") || caseOn.MatchString(text):
			depth++
		case text == "fi" || text == "esac" || strings.HasPrefix(text, "fi;") || strings.HasPrefix(text, "esac;"):
			if depth == 0 {
				return false
			}
			depth--
		}
	}
	return false
}

// workingAlternatives reports an if or case statement at index i with more
// than one branch and no branch that fails or warns.
func workingAlternatives(scope []patternkit.ShellLine, i int) bool {
	closer := "fi"
	if caseOn.MatchString(scope[i].Text) {
		closer = "esac"
	}
	depth, branches := 0, 1
	for j := i + 1; j < len(scope); j++ {
		text := strings.TrimSpace(scope[j].Text)
		if branchFailure.MatchString(text) {
			return false
		}
		switch {
		case strings.HasPrefix(text, "if ") || caseOn.MatchString(text):
			depth++
		case text == "fi" || text == "esac" || strings.HasPrefix(text, "fi;") || strings.HasPrefix(text, "esac;"):
			if depth == 0 {
				return branches > 1 && strings.HasPrefix(text, closer)
			}
			depth--
		case depth == 0 && (text == "else" || strings.HasPrefix(text, "elif ") || strings.HasSuffix(text, ";;")):
			branches++
		}
	}
	return false
}

var (
	fileTest       = regexp.MustCompile(`^(?:if\s+)?(?:\[\[?|test)\s+(!\s+)?-[efrs]\s+"?([^\s"\]]+)"?`)
	literalEcho    = regexp.MustCompile(`^(?:echo|printf)\s+(?:"([^"$` + "`" + `\\]+)"|'([^']+)'|([^\s$"'` + "`" + `;|&><]+))\s*$`)
	orGroupDefault = regexp.MustCompile(`\|\|\s*\{\s*(.*?);?\s*(?:return\b[^}]*)?\}\s*$|\|\|\s*(echo\s.*|printf\s.*)$`)
)

// checkGetterDefault reports the literal a captured function prints when
// the file its test checks is missing: if [[ -f F ]]; then read F; else
// echo literal; fi, if [ ! -f F ]; then echo literal; return; fi, and
// [[ -r F ]] || { echo literal; return; }.
func checkGetterDefault(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	if src.Make {
		return nil
	}
	if src.Ctx.IsTestFile() {
		return nil // a test stub prints the answer it imitates
	}
	funcs := src.Functions()
	captured := capturedFunctions(src, funcs)
	var out []*core.Violation
	for name := range captured {
		for _, line := range missingFileLiterals(src.Body(funcs[name])) {
			out = appendReport(out, src.Report(r, line,
				name+" prints a literal when its file is missing, and the caller takes it for the value read from the file",
				"Fail when the file is missing (echo the error >&2; return 1) and let the caller choose what to do"))
		}
	}
	return out
}

// missingFileLiterals returns the lines of a body where the branch taken on
// a missing file prints a literal while another command of the body reads
// the file: a predicate (has_file && echo yes || echo no) reads nothing.
func missingFileLiterals(body []patternkit.ShellLine) []int {
	var lines []int
	for i := range body {
		segs := patternkit.Segments(body[i].Text)
		head := strings.TrimSpace(segs[0].Text)
		m := fileTest.FindStringSubmatch(head)
		if m == nil || !patternkit.ReadsFile(body, i, m[2]) {
			continue
		}
		if !strings.HasPrefix(head, "if") {
			if g := orGroupDefault.FindStringSubmatch(body[i].Text); g != nil {
				cmd := strings.TrimSpace(g[1] + g[2])
				if m[1] == "" && literalEcho.MatchString(strings.TrimSuffix(cmd, ";")) {
					lines = append(lines, body[i].LineAt(strings.Index(body[i].Text, cmd)))
				}
			}
			continue
		}
		branch := missingBranch(body, i, m[1] != "")
		if len(branch) == 0 {
			continue
		}
		first := branch[0]
		text := strings.TrimSpace(first.Text)
		if !literalEcho.MatchString(text) {
			continue
		}
		rest := branch[1:]
		if len(rest) > 1 || len(rest) == 1 && !strings.HasPrefix(strings.TrimSpace(rest[0].Text), "return") {
			continue
		}
		lines = append(lines, first.Nums[0])
	}
	return lines
}

// missingBranch returns the lines of the if statement at index i taken when
// the file is missing: the else branch of a positive test, the then branch
// of a negated one. Nested ifs are not followed.
func missingBranch(body []patternkit.ShellLine, i int, negated bool) []patternkit.ShellLine {
	var then, els []patternkit.ShellLine
	inElse := false
	for j := i + 1; j < len(body); j++ {
		text := strings.TrimSpace(body[j].Text)
		switch {
		case text == "fi":
			if negated {
				return then
			}
			return els
		case strings.HasPrefix(text, "if ") || strings.HasPrefix(text, "elif "):
			return nil
		case text == "else":
			inElse = true
		case inElse:
			els = append(els, body[j])
		default:
			then = append(then, body[j])
		}
	}
	return nil
}

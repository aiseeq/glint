package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
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
	for _, opt := range strings.Fields(m[1]) {
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
func checkJqNullValue(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	funcs := src.functions()
	captures := captureTargets(src, funcs)
	var out []*core.Violation
	report := func(line int, variable string) {
		out = appendReport(out, src.report(r, line,
			"jq -r prints null for a missing key and succeeds, and $"+variable+" picks a branch or builds a name without a check for null",
			"Make a missing key fail (jq -er) or give it a value (jq -r '.key // empty'), or check the result for \"null\""))
	}
	for name, fn := range funcs {
		for _, l := range src.body(fn) {
			for _, seg := range segments(l.text) {
				text := commandPrefix.ReplaceAllString(seg.trimmed(), "")
				if !strings.HasPrefix(text, "jq ") || !jqRawOutput(text) || !writesToStdout(text) {
					continue
				}
				for _, c := range captures[name] {
					if usedAsValue(c.scope, c.variable) {
						report(l.lineAt(seg.offset), c.variable)
						break
					}
				}
			}
		}
	}
	for i, l := range src.lines {
		for _, seg := range segments(l.text) {
			text := seg.trimmed()
			m := captureAssignment.FindStringSubmatch(text)
			if m == nil || !jqRawOutput(text) {
				continue
			}
			if usedAsValue(scopeOf(src, funcs, i), m[1]) {
				report(l.lineAt(seg.offset), m[1])
			}
		}
	}
	return out
}

// capture is a variable a command's output is captured into, with the lines
// where the variable lives.
type capture struct {
	variable string
	scope    []shellLine
}

// captureTargets returns, per command name, the variables its output is
// captured into: active=$(get_active_color).
func captureTargets(src *shellSource, funcs map[string]shellFunc) map[string][]capture {
	targets := make(map[string][]capture)
	for i, l := range src.lines {
		for _, seg := range segments(l.text) {
			text := seg.trimmed()
			m := captureAssignment.FindStringSubmatch(text)
			if m == nil {
				continue
			}
			if call := captureCall.FindStringSubmatch(text[len(m[0])-2:]); call != nil {
				targets[call[1]] = append(targets[call[1]], capture{variable: m[1], scope: scopeOf(src, funcs, i)})
			}
		}
	}
	return targets
}

// scopeOf returns the lines of the innermost function that holds the line,
// or the whole script for a line outside functions.
func scopeOf(src *shellSource, funcs map[string]shellFunc, index int) []shellLine {
	var inner *shellFunc
	for _, fn := range funcs {
		if fn.first > index || index > fn.last {
			continue
		}
		if inner == nil || fn.first > inner.first {
			inner = &fn
		}
	}
	if inner == nil {
		return src.lines
	}
	return src.body(*inner)
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
func usedAsValue(scope []shellLine, variable string) bool {
	ref := regexp.MustCompile(`\$(?:\{` + variable + `\}|` + variable + `\b)`)
	glued := regexp.MustCompile(`[\w./-]\$(?:\{` + variable + `\}|` + variable + `\b)|\$\{` + variable + `\}[\w./-]|\$` + variable + `[./-]`)
	used := false
	for i, l := range scope {
		if !ref.MatchString(l.text) {
			continue
		}
		if strings.Contains(l.text, "null") {
			return false
		}
		if captureAssignment.MatchString(strings.TrimSpace(l.text)) && !strings.Contains(l.text, ";") {
			continue // the assignment itself
		}
		switch {
		case glued.MatchString(l.text) && !messageCommand.MatchString(strings.TrimSpace(l.text)):
			used = true
		case ifTest.MatchString(l.text) || caseOn.MatchString(l.text):
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
func branchKinds(scope []shellLine, i int) (alternatives, validates bool) {
	if branchFailure.MatchString(scope[i].text) {
		return false, true
	}
	return workingAlternatives(scope, i), branchFails(scope, i)
}

// branchFails reports a failing or warning command inside the if or case
// statement at index i.
func branchFails(scope []shellLine, i int) bool {
	depth := 0
	for j := i + 1; j < len(scope); j++ {
		text := strings.TrimSpace(scope[j].text)
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
func workingAlternatives(scope []shellLine, i int) bool {
	closer := "fi"
	if caseOn.MatchString(scope[i].text) {
		closer = "esac"
	}
	depth, branches := 0, 1
	for j := i + 1; j < len(scope); j++ {
		text := strings.TrimSpace(scope[j].text)
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
func checkGetterDefault(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	if src.ctx.IsTestFile() || strings.HasSuffix(src.ctx.RelPath, "_test.sh") {
		return nil // a test stub prints the answer it imitates
	}
	funcs := src.functions()
	captured := capturedFunctions(src, funcs)
	var out []*core.Violation
	for name := range captured {
		for _, line := range missingFileLiterals(src.body(funcs[name])) {
			out = appendReport(out, src.report(r, line,
				name+" prints a literal when its file is missing, and the caller takes it for the value read from the file",
				"Fail when the file is missing (echo the error >&2; return 1) and let the caller choose what to do"))
		}
	}
	return out
}

// missingFileLiterals returns the lines of a body where the branch taken on
// a missing file prints a literal while another command of the body reads
// the file: a predicate (has_file && echo yes || echo no) reads nothing.
func missingFileLiterals(body []shellLine) []int {
	var lines []int
	for i := 0; i < len(body); i++ {
		segs := segments(body[i].text)
		head := strings.TrimSpace(segs[0].text)
		m := fileTest.FindStringSubmatch(head)
		if m == nil || !readsFile(body, i, m[2]) {
			continue
		}
		if !strings.HasPrefix(head, "if") {
			if g := orGroupDefault.FindStringSubmatch(body[i].text); g != nil {
				cmd := strings.TrimSpace(g[1] + g[2])
				if m[1] == "" && literalEcho.MatchString(strings.TrimSuffix(cmd, ";")) {
					lines = append(lines, body[i].lineAt(strings.Index(body[i].text, cmd)))
				}
			}
			continue
		}
		branch := missingBranch(body, i, m[1] != "")
		if len(branch) == 0 {
			continue
		}
		first := branch[0]
		text := strings.TrimSpace(first.text)
		if !literalEcho.MatchString(text) {
			continue
		}
		rest := branch[1:]
		if len(rest) > 1 || len(rest) == 1 && !strings.HasPrefix(strings.TrimSpace(rest[0].text), "return") {
			continue
		}
		lines = append(lines, first.nums[0])
	}
	return lines
}

// readsFile reports a command of the body, other than the test at index i,
// that names the tested file.
func readsFile(body []shellLine, test int, file string) bool {
	for j, l := range body {
		if j != test && strings.Contains(l.text, file) {
			return true
		}
	}
	return false
}

// missingBranch returns the lines of the if statement at index i taken when
// the file is missing: the else branch of a positive test, the then branch
// of a negated one. Nested ifs are not followed.
func missingBranch(body []shellLine, i int, negated bool) []shellLine {
	var then, els []shellLine
	inElse := false
	for j := i + 1; j < len(body); j++ {
		text := strings.TrimSpace(body[j].text)
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

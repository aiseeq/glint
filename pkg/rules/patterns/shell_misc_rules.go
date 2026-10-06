package patterns

import (
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	invents := &shellCaptureRule{}
	invents.shellRule = newShellRule("shell-case-default-invents-value",
		"Detects a function captured with $(...) that maps its argument through a case whose *) arm prints a made-up value instead of failing — an unknown or mistyped id passes as a real one",
		core.SeverityMedium, func(_ *shellRule, src *shellSource) []*core.Violation { return checkCaseDefaultInvents(invents, src) })
	invents.ResetState()
	rules.Register(invents)
	rules.Register(newShellRule("shell-grep-label-prefix-match",
		"Detects grep \"label: $name\" without -x, -w or an anchor after the name — a name that is the prefix of another (p1, p11) matches the other's lines too",
		core.SeverityMedium, checkGrepLabelPrefix))
	rules.Register(newShellRule("shell-ssh-double-quoted-argument",
		"Detects ssh host \"cmd \\\"$var\\\"\" with a value from the script's arguments — the remote shell expands $, backquotes and quotes inside the value",
		core.SeverityHigh, checkSSHQuotedArgument))
	rules.Register(newShellRule("shell-rm-rf-unvalidated-argument",
		"Detects rm -rf \"$base/$name\" where name comes from the script's arguments with no check for / and .. — an argument like ../.. removes something else",
		core.SeverityHigh, checkRmRfArgument))
	rules.Register(&goworkBuildRule{BaseRule: rules.NewBaseRule("shell-go-build-without-gowork-off", "patterns",
		"Detects a release go build (a pack or release script, -trimpath, output to dist/) without GOWORK=off in a module that a go.work with other modules includes — the binary is built against the neighbours' working trees, not the versions go.mod names",
		core.SeverityMedium)})
	drift := &shellCaseDriftRule{}
	drift.shellRule = newShellRule("shell-case-patterns-drift",
		"Detects a case arm whose id patterns another case of the project repeats with more patterns, none of which the first case knows — the ids it misses fall to its default arm",
		core.SeverityMedium, func(_ *shellRule, src *shellSource) []*core.Violation { return checkCaseDrift(drift, src) })
	drift.ResetState()
	rules.Register(drift)
	rules.Register(newShellRule("shell-command-in-comment",
		"Detects a command written after ; inside a trailing comment (; export $(...), ; x=$(cmd | ...)) — it reads as part of the line and never runs",
		core.SeverityHigh, checkCommandInComment))
	rules.Register(newShellRule("shell-git-path-relative",
		"Detects git -C dir rev-parse --git-path/--git-dir/--git-common-dir without --path-format=absolute, or one without -C whose path the script reads after a cd — the path is relative to the directory git ran in",
		core.SeverityMedium, checkGitPathRelative))
	rules.Register(newShellRule("shell-prefix-assignment-clears-env",
		"Detects NAME=${x:+...} before a command where the script never sets NAME itself — with x empty the prefix sets NAME to empty and wipes the value the caller exported",
		core.SeverityMedium, checkPrefixClearsEnv))
	sibling := &shellSiblingEnvRule{}
	sibling.shellRule = newShellRule("shell-sibling-path-variable-differs",
		"Detects a script that calls a sibling script while both take the same default path from different variables (${A:-path} and ${B:-path}) and the call does not pass B — an override of A moves half of the work",
		core.SeverityMedium, func(_ *shellRule, src *shellSource) []*core.Violation { return checkSiblingPathVariable(sibling, src) })
	sibling.ResetState()
	rules.Register(sibling)
	rules.Register(newShellRule("go-test-without-parallel-limit",
		"Detects go test ./... in a script or a make recipe without -p — the run takes every core, and two entry points at once overload the machine",
		core.SeverityLow, checkGoTestParallel))
	copyList := &shellCopyListRule{}
	copyList.shellRule = newShellRule("shell-copy-list-misses-sourced",
		"Detects cp of an explicit list of scripts where a listed script sources a sibling the list leaves out — the copied script fails where it is copied to",
		core.SeverityMedium, func(_ *shellRule, src *shellSource) []*core.Violation { return checkCopyListSourced(copyList, src) })
	copyList.ResetState()
	rules.Register(copyList)
	rules.Register(newShellRule("shell-docker-volume-id-path",
		"Detects a path into /var/lib/docker/volumes/<64-hex id> — the id of an anonymous volume changes when the container is recreated",
		core.SeverityHigh, checkDockerVolumeID))
	rules.Register(newShellRule("shell-docker-logs-since-without-tail",
		"Detects docker logs --since without --tail inside a loop or a function — each poll reads the whole window of the container's log",
		core.SeverityLow, checkDockerLogsSince))
}

// shellCaptureRule is a shell rule that knows the functions some script of
// the root captures with $(...).
type shellCaptureRule struct {
	*shellRule
	captured map[string]bool
}

// UseProjectFiles records the names captured with $(name ...) in the root's
// scripts.
func (r *shellCaptureRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	for _, ctx := range files {
		if !ctx.IsShellFile() {
			continue
		}
		for _, line := range ctx.Lines {
			for _, m := range captureCall.FindAllStringSubmatch(line, -1) {
				r.captured[m[1]] = true
			}
		}
	}
}

// ResetState drops the names.
func (r *shellCaptureRule) ResetState() { r.captured = make(map[string]bool) }

var (
	positionalCase = regexp.MustCompile(`\bcase\s+"?\$\{?[1-9][}"\s]`)
	caseArm        = regexp.MustCompile(`^\s*\(?([^()]+)\)\s*(.*)$`)
	failsArm       = regexp.MustCompile(`>&2|\b(?:exit|return)\s+[1-9]|\bfail\w*|\berror\b|\bdie\b`)
)

// caseArmText is one arm of a case: its patterns, its commands and the offset
// of the arm in the text it was cut from.
type caseArmText struct {
	patterns []string
	body     string
	offset   int
}

// caseArms splits the text between "in" and "esac" of the first case in a
// text into arms.
func caseArms(text string) []caseArmText {
	start := regexp.MustCompile(`\bcase\s+\S+\s+in\b`).FindStringIndex(text)
	if start == nil {
		return nil
	}
	body := text[start[1]:]
	if end := regexp.MustCompile(`\besac\b`).FindStringIndex(body); end != nil {
		body = body[:end[0]]
	}
	var arms []caseArmText
	offset := start[1]
	for _, piece := range strings.Split(body, ";;") {
		if m := caseArm.FindStringSubmatchIndex(piece); m != nil {
			var patterns []string
			for _, p := range strings.Split(piece[m[2]:m[3]], "|") {
				patterns = append(patterns, strings.Trim(strings.TrimSpace(p), `"'`))
			}
			arms = append(arms, caseArmText{patterns: patterns, body: strings.TrimSpace(piece[m[4]:m[5]]), offset: offset + m[2]})
		}
		offset += len(piece) + 2
	}
	return arms
}

// printedValue returns what an arm prints when it is a single echo or printf,
// "" for anything else.
func printedValue(body string) string {
	body = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(body), ";"))
	if segs := segments(body); len(segs) != 1 {
		return ""
	}
	word := commandWord(body)
	if word != "echo" && word != "printf" {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(body, word))
}

// passesInput reports a printed value that is the input itself: "$1".
var passesInput = regexp.MustCompile(`^"?\$\{?1\}?"?$`)

// checkCaseDefaultInvents reports the *) arm of a captured function's case
// over its argument that prints a value while the other arms map ids to
// values.
func checkCaseDefaultInvents(r *shellCaptureRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for name, fn := range src.functions() {
		if !r.captured[name] {
			continue
		}
		text, first := functionText(src, fn)
		if !positionalCase.MatchString(text) {
			continue
		}
		arms := caseArms(text)
		mapped := 0
		var fallback *caseArmText
		for i, arm := range arms {
			value := printedValue(arm.body)
			switch {
			case len(arm.patterns) == 1 && arm.patterns[0] == "*":
				if value != "" && !passesInput.MatchString(value) && !failsArm.MatchString(arm.body) {
					fallback = &arms[i]
				}
			case value != "":
				mapped++
			}
		}
		if fallback == nil || mapped < 2 {
			continue
		}
		out = appendReport(out, src.report(r, first+strings.Count(text[:fallback.offset], "\n"),
			name+" maps its argument with a case whose *) arm prints "+printedValue(fallback.body)+" — an unknown or mistyped id gets a made-up answer instead of an error",
			"Fail in the *) arm: *) echo \"unknown id: $1\" >&2; return 1;; and let the caller stop on it"))
	}
	return out
}

var grepLabelVar = regexp.MustCompile(`\bgrep\s+((?:-[A-Za-z]+\s+)*)"([^"$]*\p{L}[:=] ?)\$\{?[A-Za-z_][A-Za-z0-9_]*(?:[:]?[-+=?][^}"]*)?\}?"`)

// checkGrepLabelPrefix reports grep "label: $name" with no word or line
// match.
func checkGrepLabelPrefix(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		for _, m := range grepLabelVar.FindAllStringSubmatchIndex(l.text, -1) {
			if insideSingleQuotes(l.text, m[0]) || strings.ContainsAny(l.text[m[2]:m[3]], "xwF") && strings.ContainsAny(l.text[m[2]:m[3]], "xw") {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(m[0]),
				"grep \""+l.text[m[4]:m[5]]+"$...\" matches every name that starts with this one — p1 counts the lines of p11",
				"Match the whole word or line: grep -w, grep -x, or end the pattern after the name (\"...$name$\")"))
		}
	}
	return out
}

var positionalRef = regexp.MustCompile(`\$[1-9@*]|\$\{[1-9@*][}:#%/-]`)

// argumentVars returns the variables a script fills, outside its functions,
// from its own arguments or from such variables; mktemp output is the
// script's own. Validated variables, and those built from them, are clean.
func argumentVars(src *shellSource, validated map[string]bool) map[string]bool {
	inFunc := make(map[int]bool)
	for _, fn := range src.functions() {
		for i := fn.first; i <= fn.last; i++ {
			inFunc[i] = true
		}
	}
	reads := func(value string, tainted map[string]bool) bool {
		for _, m := range positionalRef.FindAllStringIndex(value, -1) {
			if !insideSingleQuotes(value, m[0]) && !validated[strings.Trim(value[m[0]+1:m[1]], "{}:#%/-")] {
				return true
			}
		}
		for _, m := range variableRef.FindAllStringSubmatch(value, -1) {
			if tainted[m[1]] {
				return true
			}
		}
		return false
	}
	tainted := make(map[string]bool)
	for pass := 0; pass < 2; pass++ {
		for i, l := range src.lines {
			if inFunc[i] {
				continue
			}
			if m := forInArgs.FindStringSubmatch(l.text); m != nil && !validated[m[1]] {
				tainted[m[1]] = true
			}
			for _, m := range assignStart.FindAllStringSubmatchIndex(l.text, -1) {
				name := l.text[m[2]:m[3]]
				value := shellValueAt(l.text, m[1])
				if insideQuotes(l.text, m[2]) || validated[name] || strings.Contains(value, "mktemp") {
					continue
				}
				if reads(value, tainted) {
					tainted[name] = true
				}
			}
		}
	}
	return tainted
}

var forInArgs = regexp.MustCompile(`^\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+"\$@"`)

// taintedRef reports a text that reads an argument or an argument variable.
func taintedRef(text string, tainted, validated map[string]bool) bool {
	for _, m := range positionalRef.FindAllStringIndex(text, -1) {
		if !validated[strings.Trim(text[m[0]+1:m[1]], "{}:#%/-")] {
			return true
		}
	}
	for _, m := range variableRef.FindAllStringSubmatch(text, -1) {
		if tainted[m[1]] {
			return true
		}
	}
	return false
}

var sshEscapedVar = regexp.MustCompile(`\\"(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)\\"`)

// checkSSHQuotedArgument reports ssh "... \"$var\" ..." with var from the
// arguments.
func checkSSHQuotedArgument(r *shellRule, src *shellSource) []*core.Violation {
	tainted := argumentVars(src, nil)
	var out []*core.Violation
	for _, s := range src.steps() {
		if commandWord(s.text) != "ssh" {
			continue
		}
		for _, m := range sshEscapedVar.FindAllStringSubmatchIndex(s.text, -1) {
			if quoteAt(s.text, m[0]) != '"' || !taintedRef(s.text[m[2]:m[3]], tainted, nil) {
				continue
			}
			out = appendReport(out, src.report(r, s.line,
				s.text[m[2]:m[3]]+" comes from the script's arguments and goes to the remote shell inside \\\"...\\\" — $, backquotes and quotes in it are expanded there",
				"Quote the value for the remote shell: ssh host \"cmd $(printf '%q' \"$var\")\", or pass it on stdin"))
			break
		}
	}
	return out
}

var (
	rmRecursive  = regexp.MustCompile(`^rm\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*\b`)
	validateCase = regexp.MustCompile(`\bcase\s+"?\$\{?([A-Za-z_][A-Za-z0-9_]*|[1-9])\}?"?\s+in\b(.*)`)
	validateTest = regexp.MustCompile(`\[\[\s*!?\s*"?\$\{?([A-Za-z_][A-Za-z0-9_]*|[1-9])\}?"?\s*(?:==|!=|=~)\s*(\S+)`)
)

// validatedVars returns the variables a script checks against / or .. (or
// a regular expression) in a case or a [[ ]] test.
func validatedVars(src *shellSource) map[string]bool {
	out := make(map[string]bool)
	for _, l := range src.lines {
		for _, re := range []*regexp.Regexp{validateCase, validateTest} {
			for _, m := range re.FindAllStringSubmatch(l.text, -1) {
				if strings.Contains(m[2], "/") || strings.Contains(m[2], "..") || re == validateTest && strings.Contains(l.text, "=~") {
					out[m[1]] = true
				}
			}
		}
	}
	return out
}

// checkRmRfArgument reports rm -r of a path under a base whose last part
// comes from the arguments.
func checkRmRfArgument(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	validated := validatedVars(src)
	tainted := argumentVars(src, validated)
	// A function's $1 is what its caller passes: only the script's own
	// lines take arguments.
	inFunc := make(map[int]bool)
	for _, fn := range src.functions() {
		for i := fn.first; i <= fn.last; i++ {
			for _, n := range src.lines[i].nums {
				inFunc[n] = true
			}
		}
	}
	values := make(map[string][]string)
	for _, l := range src.lines {
		if inFunc[l.nums[0]] {
			continue
		}
		for _, m := range assignStart.FindAllStringSubmatchIndex(l.text, -1) {
			if value := shellValueAt(l.text, m[1]); !insideQuotes(l.text, m[2]) && !strings.Contains(value, "mktemp") {
				values[l.text[m[2]:m[3]]] = append(values[l.text[m[2]:m[3]]], value)
			}
		}
	}
	var out []*core.Violation
	for _, s := range src.steps() {
		if inFunc[s.line] {
			continue
		}
		command := sudoPrefix.ReplaceAllString(commandPrefix.ReplaceAllString(s.text, ""), "")
		if !rmRecursive.MatchString(command) {
			continue
		}
		for _, arg := range strings.Fields(rmRecursive.ReplaceAllString(command, "")) {
			arg = strings.Trim(arg, `"'`)
			candidates := []string{arg}
			if m := regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$`).FindStringSubmatch(arg); m != nil {
				candidates = values[m[1]]
			}
			if underBase(candidates, tainted, validated) {
				out = appendReport(out, src.report(r, s.line,
					"rm -r removes a path whose last part comes from the script's arguments, with no check for / and .. — an argument like ../.. removes something else",
					"Check the argument before the removal: case \"$name\" in \"\"|*/*|*..*) echo \"bad name: $name\" >&2; exit 2;; esac"))
				break
			}
		}
	}
	return out
}

// underBase reports a path value that joins a base and, after a /, an
// argument.
func underBase(values []string, tainted, validated map[string]bool) bool {
	for _, value := range values {
		value = strings.Trim(value, `"'`)
		slash := strings.Index(value, "/")
		if slash <= 0 || !taintedRef(value[slash:], tainted, validated) {
			continue
		}
		return true
	}
	return false
}

var (
	goBuildStep   = regexp.MustCompile(`(?:^|[\s;(&])go\s+build\b`)
	releaseBuild  = regexp.MustCompile(`-trimpath\b|\bdist/`)
	releaseScript = regexp.MustCompile(`(?i)pack|release|dist|publish|ship|bundle`)
	goworkOff     = regexp.MustCompile(`\bGOWORK=off\b`)
	goworkUse     = regexp.MustCompile(`(?m)^\s*(?:use\s+)?(\.{1,2}(?:/[^\s)]*)?)\s*$`)
)

// workspaceModules returns the module directories the go.work that governs
// dir includes, nil when there is none.
func workspaceModules(dir string) []string {
	var modules []string
	for d := dir; ; d = filepath.Dir(d) {
		data, err := os.ReadFile(filepath.Join(d, "go.work"))
		if err == nil {
			for _, m := range goworkUse.FindAllStringSubmatch(string(data), -1) {
				modules = append(modules, filepath.Clean(filepath.Join(d, m[1])))
			}
			break
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return modules
}

// moduleDir returns the directory of the go.mod nearest above a file, "" when
// there is none.
func moduleDir(file string) string {
	for d := filepath.Dir(file); ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			return ""
		}
	}
}

// goworkBuildRule is the go build rule: it reads go.mod and go.work from the
// disk, so its findings depend on more than the script.
type goworkBuildRule struct{ *rules.BaseRule }

// AnalyzeFile reads a script or a make file as shell and checks it.
func (r *goworkBuildRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	src, ok := readShell(ctx)
	if !ok {
		return nil
	}
	return checkGoBuildWithoutGoworkOff(r, src)
}

// ReadsOtherFiles reports that the findings depend on go.mod and go.work.
func (r *goworkBuildRule) ReadsOtherFiles() bool { return true }

// checkGoBuildWithoutGoworkOff reports a release go build inside a go.work
// with other modules.
func checkGoBuildWithoutGoworkOff(r violationMaker, src *shellSource) []*core.Violation {
	whole := strings.Join(src.ctx.Lines, "\n")
	if !goBuildStep.MatchString(whole) || regexp.MustCompile(`(?m)^\s*export\s+GOWORK=`).MatchString(whole) {
		return nil
	}
	mod := moduleDir(src.ctx.Path)
	if mod == "" {
		return nil
	}
	modules := workspaceModules(mod)
	others := 0
	for _, m := range modules {
		if m != mod {
			others++
		}
	}
	if others == 0 {
		return nil
	}
	named := releaseScript.MatchString(path.Base(src.ctx.RelPath))
	var out []*core.Violation
	for _, l := range src.lines {
		if !goBuildStep.MatchString(l.text) || goworkOff.MatchString(l.text) || !named && !releaseBuild.MatchString(l.text) {
			continue
		}
		out = appendReport(out, src.report(r, l.lineAt(goBuildStep.FindStringIndex(l.text)[0]),
			"go build runs inside a go.work that includes other modules — the release is built against their working trees, not the versions go.mod names",
			"Build releases with GOWORK=off so go.mod decides the versions"))
	}
	return out
}

// shellCaseDriftRule is a shell rule that knows the case arms of the root's
// scripts.
type shellCaseDriftRule struct {
	*shellRule
	arms []projectCaseArm
}

// projectCaseArm is an arm of a case in a script of the root with the
// patterns of its whole case.
type projectCaseArm struct {
	path     string
	patterns map[string]bool
	all      map[string]bool
}

// UseProjectFiles indexes the case arms of the root's scripts.
func (r *shellCaseDriftRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	for _, ctx := range files {
		src, ok := readShell(ctx)
		if !ok || src.make {
			continue
		}
		for _, c := range idCases(src) {
			for _, arm := range c.arms {
				r.arms = append(r.arms, projectCaseArm{path: ctx.RelPath, patterns: arm.set, all: c.all})
			}
		}
	}
}

// ResetState drops the index.
func (r *shellCaseDriftRule) ResetState() { r.arms = nil }

// idCase is a case of a script with a default arm, the arms that list id
// patterns and every pattern it knows.
type idCase struct {
	arms []idArm
	all  map[string]bool
}

// idArm is an arm of three or more patterns, at least one of them a glob.
type idArm struct {
	set  map[string]bool
	line int
}

// idCases returns the cases of a script that classify ids.
func idCases(src *shellSource) []idCase {
	var out []idCase
	for _, l := range src.lines {
		if !strings.Contains(l.text, "case ") {
			continue
		}
		text := l.text
		arms := caseArms(text)
		hasDefault := false
		all := make(map[string]bool)
		for _, arm := range arms {
			for _, p := range arm.patterns {
				all[p] = true
				hasDefault = hasDefault || p == "*"
			}
		}
		if !hasDefault {
			continue
		}
		c := idCase{all: all}
		for _, arm := range arms {
			set := make(map[string]bool)
			glob := false
			for _, p := range arm.patterns {
				set[p] = true
				glob = glob || strings.ContainsAny(p, "*[")
			}
			if len(set) >= 3 && glob && !set["*"] {
				c.arms = append(c.arms, idArm{set: set, line: l.lineAt(arm.offset)})
			}
		}
		out = append(out, c)
	}
	return out
}

// checkCaseDrift reports an arm of a one-line case when an arm elsewhere
// shares three patterns with it and adds patterns its whole case lacks.
func checkCaseDrift(r *shellCaseDriftRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	var out []*core.Violation
	for _, c := range idCases(src) {
		for _, arm := range c.arms {
			for _, other := range r.arms {
				shared := 0
				var missing []string
				for p := range arm.set {
					if other.patterns[p] {
						shared++
					}
				}
				for p := range other.patterns {
					if !c.all[p] {
						missing = append(missing, p)
					}
				}
				if shared < 3 || len(missing) == 0 || equalSets(arm.set, other.patterns) {
					continue
				}
				out = appendReport(out, src.report(r, arm.line,
					"This case classifies the same ids as a case in "+other.path+", which also knows "+strings.Join(sortedStrings(missing), ", ")+" — those ids fall to the default arm here",
					"Keep one classification (a function in a sourced library) and call it from both scripts"))
				break
			}
		}
	}
	return out
}

// sortedStrings returns a sorted copy of a list.
func sortedStrings(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
}

func equalSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

var commentCommand = regexp.MustCompile(`;\s*(?:(?:export|eval|source|unset)\s+\S|[A-Za-z_][A-Za-z0-9_]*=\$\(|\S+.*\$\(.*\|)`)

// checkCommandInComment reports a trailing comment holding ; and a command.
func checkCommandInComment(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		code := withoutComment(l.text)
		if strings.TrimSpace(code) == "" || len(code) == len(l.text) {
			continue
		}
		comment := l.text[len(code):]
		if m := commentCommand.FindStringIndex(comment); m != nil {
			out = appendReport(out, src.report(r, l.lineAt(len(code)+m[0]),
				"A command follows ; inside the comment at the end of the line — it reads as part of the line and never runs",
				"Move the command to its own line, or end the comment before it"))
		}
	}
	return out
}

var gitPathQuery = regexp.MustCompile(`\bgit\s+((?:-C\s+\S+\s+)?)rev-parse\b[^)]*--(?:git-path|git-dir|git-common-dir)\b`)

// changeDir is a cd of the script itself, not of a ( subshell ).
var changeDir = regexp.MustCompile(`(?:^|[;&|]\s*|\b(?:then|do|else)\s+)cd\s`)

// readAfterCd reports a variable read after a later cd.
func readAfterCd(lines []shellLine, name string) bool {
	if name == "" {
		return false
	}
	read := regexp.MustCompile(`\$\{?` + name + `\b`)
	moved := false
	for _, l := range lines {
		if moved && read.MatchString(l.text) {
			return true
		}
		moved = moved || changeDir.MatchString(l.text)
	}
	return false
}

// checkGitPathRelative reports git rev-parse --git-path without an absolute
// path format, run with -C or followed by a cd.
func checkGitPathRelative(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for i, l := range src.lines {
		m := gitPathQuery.FindStringSubmatchIndex(l.text)
		if m == nil || strings.Contains(l.text, "--path-format=absolute") {
			continue
		}
		name := ""
		if open := strings.LastIndex(l.text[:m[0]], "$("); open >= 0 {
			name = capturedName(l.text, open)
		}
		if m[3] == m[2] && !readAfterCd(src.lines[i+1:], name) {
			continue
		}
		out = appendReport(out, src.report(r, l.lineAt(m[0]),
			"git rev-parse prints this path relative to the directory git ran in — the script uses it from another directory and looks at another file",
			"Ask for an absolute path: git rev-parse --path-format=absolute --git-path ..."))
	}
	return out
}

var alternatePrefix = regexp.MustCompile(`^([A-Z_][A-Z0-9_]*)=\$\{([A-Za-z_][A-Za-z0-9_]*):\+[^}]*\}$`)

// checkPrefixClearsEnv reports NAME=${x:+...} as a command prefix where
// the script never assigns NAME.
func checkPrefixClearsEnv(r *shellRule, src *shellSource) []*core.Violation {
	assigned := make(map[string]bool)
	steps := src.steps()
	for _, s := range steps {
		if prefix := envPrefix.FindString(s.text); prefix == "" || strings.TrimSpace(prefix) == strings.TrimSpace(s.text) {
			for _, m := range assignStart.FindAllStringSubmatchIndex(s.text, -1) {
				assigned[s.text[m[2]:m[3]]] = true
			}
		}
	}
	var out []*core.Violation
	for _, s := range steps {
		prefix := envPrefix.FindString(s.text)
		if prefix == "" || strings.TrimSpace(prefix) == strings.TrimSpace(s.text) {
			continue
		}
		for _, word := range strings.Fields(prefix) {
			m := alternatePrefix.FindStringSubmatch(strings.Trim(word, `"`))
			if m == nil || m[1] == m[2] || assigned[m[1]] {
				continue
			}
			out = appendReport(out, src.report(r, s.line,
				m[1]+"=${"+m[2]+":+...} is empty when "+m[2]+" is — the prefix then sets "+m[1]+" to empty and wipes the value the caller exported",
				"Pass the variable only when it has a value: ${"+m[2]+":+"+m[1]+"=...} through env, or build the prefix in an array"))
		}
	}
	return out
}

// shellSiblingEnvRule is a shell rule that knows the default paths each
// script of the root takes from its variables.
type shellSiblingEnvRule struct {
	*shellRule
	defaults map[string]map[string]string // script path -> default path -> variable
}

var pathDefault = regexp.MustCompile(`\$\{([A-Z_][A-Z0-9_]*):-([^}]*/[^}]*)\}`)

// scriptDefaults returns the default paths of a script with the variable
// that overrides each.
func scriptDefaults(lines []string) map[string]string {
	out := make(map[string]string)
	for _, line := range lines {
		for _, m := range pathDefault.FindAllStringSubmatch(line, -1) {
			out[strings.Trim(m[2], `"`)] = m[1]
		}
	}
	return out
}

// UseProjectFiles indexes the default paths of the root's scripts.
func (r *shellSiblingEnvRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	for _, ctx := range files {
		if ctx.IsShellFile() {
			r.defaults[ctx.RelPath] = scriptDefaults(ctx.Lines)
		}
	}
}

// ResetState drops the index.
func (r *shellSiblingEnvRule) ResetState() { r.defaults = make(map[string]map[string]string) }

// scriptWord returns the first word of a command after its environment
// prefix, a quoted path with a substitution kept whole.
func scriptWord(command string) string {
	command = envPrefix.ReplaceAllString(commandPrefix.ReplaceAllString(strings.TrimSpace(command), ""), "")
	return shellValueAt(command, 0)
}

// checkSiblingPathVariable reports a call of a sibling script that takes a
// default path of this script from another variable without passing it.
func checkSiblingPathVariable(r *shellSiblingEnvRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	own := scriptDefaults(src.ctx.Lines)
	if len(own) == 0 {
		return nil
	}
	whole := strings.Join(src.ctx.Lines, "\n")
	dir := path.Dir(src.ctx.RelPath)
	var out []*core.Violation
	for _, s := range src.steps() {
		word := strings.Trim(scriptWord(s.text), `"`)
		if !strings.HasSuffix(word, ".sh") {
			continue
		}
		child := r.defaults[path.Join(dir, path.Base(word))]
		for _, value := range slices.Sorted(maps.Keys(child)) {
			childVar := child[value]
			parentVar, ok := own[value]
			if !ok || parentVar == childVar || strings.Contains(s.text, childVar+"=") ||
				regexp.MustCompile(`\bexport\s+(?:[A-Za-z_]+\s+)*`+childVar+`\b`).MatchString(whole) {
				continue
			}
			out = appendReport(out, src.report(r, s.line,
				path.Base(word)+" takes "+value+" from "+childVar+" while this script takes it from "+parentVar+" — an override of "+parentVar+" does not reach the call",
				"Pass the path to the call ("+childVar+"=\"$...\" "+path.Base(word)+"), or let both scripts read one variable"))
			break
		}
	}
	return out
}

var (
	goTestAll     = regexp.MustCompile(`\bgo\s+test\b[^;&|]*\./\.\.\.`)
	goTestPackage = regexp.MustCompile(`\s-p(?:\s+|=)\S`)
)

// checkGoTestParallel reports go test ./... without -p.
func checkGoTestParallel(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, s := range src.steps() {
		m := goTestAll.FindStringIndex(s.text)
		if m == nil || insideQuotes(s.text, m[0]) || goTestPackage.MatchString(s.text[m[0]:m[1]]) || strings.Contains(s.text, "GOFLAGS") || strings.Contains(s.text, "flock") {
			continue
		}
		out = appendReport(out, src.report(r, s.line,
			"go test ./... runs as many packages at once as there are cores — two such runs at once overload the machine",
			"Limit the package parallelism: go test -p 4 ./..."))
	}
	return out
}

// shellCopyListRule is a shell rule that knows which siblings each script
// of the root sources.
type shellCopyListRule struct {
	*shellRule
	sources map[string][]string // script path -> sibling scripts it sources
}

var sourcedSibling = regexp.MustCompile(`^\s*(?:\.|source)\s+"?\$(?:\{?[A-Za-z_][A-Za-z0-9_]*\}?|\(dirname\s+"?\$\{?(?:0|BASH_SOURCE(?:\[0\])?)\}?"?\))/([A-Za-z0-9_.-]+\.sh)\b`)

// UseProjectFiles indexes the sourced siblings of the root's scripts.
func (r *shellCopyListRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	for _, ctx := range files {
		if !ctx.IsShellFile() {
			continue
		}
		for _, line := range ctx.Lines {
			if m := sourcedSibling.FindStringSubmatch(line); m != nil {
				r.sources[ctx.RelPath] = append(r.sources[ctx.RelPath], m[1])
			}
		}
	}
}

// ResetState drops the index.
func (r *shellCopyListRule) ResetState() { r.sources = make(map[string][]string) }

// checkCopyListSourced reports cp of a list of scripts that leaves out one
// they source.
func checkCopyListSourced(r *shellCopyListRule, src *shellSource) []*core.Violation {
	dir := path.Dir(src.ctx.RelPath)
	var out []*core.Violation
	for _, s := range src.steps() {
		for _, seg := range flatSegments(s.text) {
			if commandWord(seg.text) != "cp" {
				continue
			}
			if missing := missingSourced(r, dir, seg.text); len(missing) > 0 {
				out = appendReport(out, src.report(r, s.line,
					"The copied scripts source "+strings.Join(missing, ", ")+", and the list leaves it out — the copy fails where it runs",
					"Add the sourced files to the list, or copy the directory"))
			}
		}
	}
	return out
}

// missingSourced returns the siblings that the scripts a cp lists source
// and the list leaves out.
func missingSourced(r *shellCopyListRule, dir, command string) []string {
	listed := make(map[string]bool)
	for _, arg := range strings.Fields(command) {
		arg = strings.Trim(arg, `"'()`)
		if strings.HasSuffix(arg, ".sh") && !strings.ContainsAny(arg, "/$*") {
			listed[arg] = true
		}
	}
	if len(listed) < 2 {
		return nil
	}
	var missing []string
	for name := range listed {
		for _, sourced := range r.sources[path.Join(dir, name)] {
			if !listed[sourced] && !slices.Contains(missing, sourced) {
				missing = append(missing, sourced)
			}
		}
	}
	return sortedStrings(missing)
}

var dockerVolumeID = regexp.MustCompile(`/var/lib/docker/volumes/[0-9a-f]{64}\b`)

// checkDockerVolumeID reports a path into an anonymous docker volume by id.
func checkDockerVolumeID(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		if m := dockerVolumeID.FindStringIndex(withoutComment(l.text)); m != nil {
			out = appendReport(out, src.report(r, l.lineAt(m[0]),
				"The path names a docker volume by its generated id — a recreated container gets another volume, and the path leads nowhere",
				"Use a named volume and ask docker for its mountpoint: docker volume inspect -f '{{.Mountpoint}}' NAME"))
		}
	}
	return out
}

var (
	dockerLogsSince = regexp.MustCompile(`\bdocker\s+(?:container\s+)?logs\b[^|;&]*--since\b`)
	dockerLogsTail  = regexp.MustCompile(`--tail\b|\s-n\s*[0-9]`)
)

// checkDockerLogsSince reports docker logs --since without --tail in a loop
// or a function.
func checkDockerLogsSince(r *shellRule, src *shellSource) []*core.Violation {
	inFunc := make(map[int]bool)
	for _, fn := range src.functions() {
		for _, l := range src.body(fn) {
			for _, n := range l.nums {
				inFunc[n] = true
			}
		}
	}
	var out []*core.Violation
	depth := 0
	for _, s := range src.steps() {
		text := strings.TrimSpace(commandPrefix.ReplaceAllString(s.text, ""))
		switch {
		case shellLoopStart(s.text):
			depth++
		case loopEnd.MatchString(text):
			depth--
		}
		m := dockerLogsSince.FindStringIndex(s.text)
		if m == nil || dockerLogsTail.MatchString(s.text[m[0]:]) || depth <= 0 && !inFunc[s.line] {
			continue
		}
		out = appendReport(out, src.report(r, s.line,
			"docker logs --since reads the whole window of the log on every call — a chatty container makes each poll slow",
			"Bound the read: docker logs --since 6s --tail 200"))
	}
	return out
}

package shellrules

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(newShellRule("shell-read-status-of-substitution",
		"Detects read ... <<< \"$(cmd)\" whose status is tested (|| handler, if) — the status is read's, which succeeds on the newline the here-string adds, so a failed cmd goes on with empty fields",
		core.SeverityMedium, checkReadStatusOfSubstitution))
	rules.Register(newShellRule("shell-pipeline-or-true-hides-producer",
		"Detects cmd | grep ... || true under pipefail — meant to excuse grep's empty result, it also excuses a failure of cmd",
		core.SeverityMedium, checkPipelineOrTrue))
	rules.Register(newShellRule("shell-grep-filter-exits-on-empty",
		"Detects a pipeline ending in grep -v under set -e with no || — when every line is filtered out grep exits 1 and the script stops",
		core.SeverityMedium, checkGrepFilterExits))
	rules.Register(newShellRule("shell-saved-status-unread",
		"Detects a status saved with rc=$? that nothing reads (or that goes only into a file nothing reads) — the failure it records is never acted on",
		core.SeverityMedium, checkSavedStatusUnread))
	rules.Register(newShellRule("shell-loop-ignores-step-failure",
		"Detects, in a script without set -e, a loop step that runs a script or a service into a log with no check of its status — a failed step passes and the script reports the loop done",
		core.SeverityMedium, checkLoopIgnoresStepFailure))
	rules.Register(newShellRule("shell-check-output-discarded",
		"Detects, under set -e, a test, vet or build run with stdout sent to /dev/null and no || handler — a failure stops the script without a word of what failed",
		core.SeverityMedium, checkCheckOutputDiscarded))
	rules.Register(newShellRule("shell-test-and-last-status",
		"Detects [ ... ] && cmd as the last command of a function or of the script (or of the loop that ends it) — when the test is false the function or the script returns 1",
		core.SeverityMedium, checkTestAndLastStatus))
}

// isSiblingScript reports a command word that runs a script by its path:
// "$repo/tools/x.sh", ./x.sh.
func isSiblingScript(word string) bool {
	return strings.HasSuffix(strings.Trim(word, `"'`), ".sh")
}

// reportingCommand reports a command whose failure is a broken run rather
// than an answer: a service call, a container, a script or a function of the
// script.
func reportingCommand(command string, funcs map[string]patternkit.ShellFunc) bool {
	word := commandWord(command)
	if _, own := funcs[word]; own || remoteCommands[word] || isSiblingScript(word) {
		return true
	}
	return word == "docker" && dockerRun.MatchString(command)
}

var (
	dockerRun = regexp.MustCompile(`\bdocker\s+(?:exec|run)\b`)
	// literalFallback is || echo with a number, numbers or an empty string.
	literalFallback = regexp.MustCompile(`\|\|\s*echo\s+(?:-n\s+)?(?:"[0-9 .]*"|'[0-9 .]*'|[0-9.]+)\s*$`)
	orTrueEnd       = regexp.MustCompile(`\|\|\s*(?:true|:)\s*$`)
	grepOnly        = regexp.MustCompile(`\bgrep\s+(?:-[A-Za-z]*o[A-Za-z]*|--only-matching)\b`)
)

// substitutions returns the $(...) of a line outside single quotes, without
// arithmetic $((...)): the offset of each and its inner text.
func substitutions(text string) (offsets []int, inner []string) {
	for i := 0; i+1 < len(text); i++ {
		if text[i] != '$' || text[i+1] != '(' || (i+2 < len(text) && text[i+2] == '(') || insideSingleQuotes(text, i) {
			continue
		}
		value := shellValueAt(text, i)
		if !strings.HasSuffix(value, ")") {
			continue
		}
		offsets = append(offsets, i)
		inner = append(inner, strings.TrimSpace(value[2:len(value)-1]))
	}
	return offsets, inner
}

// fallbackInSubstitution reports $(cmd || true) and $(cmd || echo 0) where
// cmd is a run whose failure is not an answer, and a captured function that
// answers with || echo LITERAL.
func fallbackInSubstitution(r *shellRule, src *patternkit.ShellSource, funcs map[string]patternkit.ShellFunc) []*core.Violation {
	var out []*core.Violation
	for i, l := range src.Lines {
		offsets, inner := substitutions(l.Text)
		for k, text := range inner {
			// grep -o finds a number or nothing: a literal for nothing
			// stands in for a broken log, an empty || true is an answer.
			switch {
			case printsOnFailure(text, false):
				continue // curl -w '%{http_code}' answers 000 itself
			case orTrueEnd.MatchString(text) && reportingCommand(text, funcs):
			case literalFallback.MatchString(text) && (reportingCommand(text, funcs) || grepOnly.MatchString(text)):
			default:
				continue
			}
			if name := capturedName(l.Text, offsets[k]); name != "" && failsOnStandIn(src.Lines, i, offsets[k], name) {
				continue
			}
			out = appendReport(out, src.Report(r, l.LineAt(offsets[k]),
				"A failed "+commandWord(text)+" is turned into a value inside the capture — the failure is not seen and the stand-in passes for a real answer",
				"Fail when the command fails: x=$(cmd) || { echo 'cmd failed' >&2; exit 1; }, or report the run as invalid"))
		}
	}
	for name := range capturedFunctions(src, funcs) {
		text, first := functionText(src, funcs[name])
		segs := patternkit.Segments(text)
		for k := 0; k+1 < len(segs); k++ {
			if segs[k].Sep != "||" || !literalFallback.MatchString("|| "+patternkit.WithoutComment(segs[k+1].Trimmed())) || !reportingCommand(segs[k].Trimmed(), funcs) {
				continue
			}
			out = appendReport(out, src.Report(r, first+strings.Count(text[:segs[k+1].Offset], "\n"),
				name+" is captured with $(...) and answers a failed "+commandWord(segs[k].Trimmed())+" with a literal — the caller takes the stand-in for a real answer",
				"Let the function fail (return 1) and decide at the call what a failed probe means"))
		}
	}
	return out
}

var (
	captureName = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=$`)
	failureStep = regexp.MustCompile(`\b(?:exit|return)\s+[1-9]|\bfail\w*\b|\blog_error\b|\bFAIL\b|\bbreak\b|>&2`)
)

// capturedName returns the variable a substitution at offset is assigned
// to: name=$(...).
func capturedName(text string, offset int) string {
	m := captureName.FindStringSubmatch(text[:offset])
	if m == nil {
		return ""
	}
	return m[1]
}

// failsOnStandIn reports a variable that the lines after its capture test
// and answer with a failure, a retry or a break: the stand-in ends up as a
// failure after all.
func failsOnStandIn(lines []patternkit.ShellLine, i, offset int, name string) bool {
	read := regexp.MustCompile(`\$\{?` + name + `\b`)
	// A make recipe tests the value on the same logical line.
	if rest := lines[i].Text[offset:]; read.MatchString(rest) && failureStep.MatchString(rest) {
		return true
	}
	for j := i + 1; j < len(lines) && j <= i+6; j++ {
		if !read.MatchString(lines[j].Text) {
			continue
		}
		for k := j; k < len(lines) && k <= j+6; k++ {
			if failureStep.MatchString(patternkit.WithoutComment(lines[k].Text)) {
				return true
			}
		}
		return false
	}
	return false
}

// functionText returns the body of a function as one text, its physical
// lines joined so that a quoted script spanning lines stays one word, and
// the line the text starts on. The definition up to { and a comment after it
// are cut, and so is the closing }.
func functionText(src *patternkit.ShellSource, fn patternkit.ShellFunc) (string, int) {
	first := src.Lines[fn.First].Nums[0]
	lastLine := src.Lines[fn.Last]
	last := lastLine.Nums[len(lastLine.Nums)-1]
	lines := append([]string(nil), src.Ctx.Lines[first-1:last]...)
	if _, rest, ok := strings.Cut(lines[0], "{"); ok {
		lines[0] = patternkit.WithoutComment(rest)
	}
	n := len(lines) - 1
	lines[n] = strings.TrimSuffix(strings.TrimRight(lines[n], " \t;"), "}")
	return strings.Join(lines, "\n"), first
}

var hereStringRead = regexp.MustCompile(`^(?:(?:if|elif|while|until)\s+)?!?\s*read\b[^<]*<<<\s*"?\$\(`)

// checkReadStatusOfSubstitution reports read <<< "$(cmd)" whose status is
// taken for cmd's.
func checkReadStatusOfSubstitution(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.Lines {
		segs := patternkit.Segments(l.Text)
		for k, seg := range segs {
			text := seg.Trimmed()
			if !hereStringRead.MatchString(text) {
				continue
			}
			handled := seg.Sep == "||" && k+1 < len(segs) && !excuses(segs[k+1].Trimmed())
			asCondition := conditionStart.MatchString(text) && seg.Sep != "&&"
			if !handled && !asCondition {
				continue
			}
			out = appendReport(out, src.Report(r, l.LineAt(seg.Offset),
				"The status tested is read's, not the command's: the here-string ends in a newline, read succeeds, and a failed command goes on with empty fields",
				"Capture first and check: v=$(cmd) || { ...; }; then read -r a b <<< \"$v\""))
		}
	}
	return out
}

// excuses reports a handler that only ignores the status: true or :.
func excuses(handler string) bool {
	word := patternkit.FirstShellWord(patternkit.WithoutComment(handler))
	return word == "true" || word == ":"
}

// sourcePipefail reports pipefail in effect for the file.
func sourcePipefail(src *patternkit.ShellSource) bool {
	if src.Make {
		return pipefailSetting.MatchString(src.MakeFlags) || pipefailSetting.MatchString(src.MakeShell)
	}
	return scriptSetsPipefail(src)
}

// checkPipelineOrTrue reports cmd | grep ... || true under pipefail.
func checkPipelineOrTrue(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	if !sourcePipefail(src) {
		return nil
	}
	var out []*core.Violation
	steps := src.Steps()
	for i := 0; i+1 < len(steps); i++ {
		s := steps[i]
		if s.Sep != "||" || patternkit.FirstShellWord(steps[i+1].Text) != "true" && patternkit.FirstShellWord(steps[i+1].Text) != ":" {
			continue
		}
		elements := pipeElements(patternkit.CommandPrefix.ReplaceAllString(s.Text, ""))
		if len(elements) < 2 || commandWord(elements[len(elements)-1]) != "grep" || commandWord(elements[0]) == "grep" {
			continue
		}
		out = appendReport(out, src.Report(r, steps[i+1].Line,
			"Under pipefail || true excuses the whole pipeline — meant for grep's empty result, it also hides a failure of "+commandWord(elements[0]),
			"Excuse only the filter: cmd | { grep ... || true; }"))
	}
	return out
}

var invertedGrep = regexp.MustCompile(`^grep\s+(?:-[A-Za-z]*v[A-Za-z]*|--invert-match)\b`)

// checkGrepFilterExits reports a pipeline ending in grep -v under set -e,
// as a statement or as a plain capture.
func checkGrepFilterExits(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	if src.Make || !errexitSetting.MatchString(strings.Join(src.Ctx.Lines, "\n")) {
		return nil
	}
	var out []*core.Violation
	steps := src.Steps()
	for i, s := range steps {
		if s.Sep == "||" || s.Sep == "&&" || (i > 0 && (steps[i-1].Sep == "||" || steps[i-1].Sep == "&&")) {
			continue
		}
		if conditionStart.MatchString(s.Text) || strings.HasPrefix(s.Text, "!") {
			continue
		}
		text := patternkit.WithoutComment(patternkit.CommandPrefix.ReplaceAllString(s.Text, ""))
		if m := plainCapture.FindStringSubmatch(text); m != nil {
			if len(patternkit.Segments(m[2])) > 1 {
				continue // the capture handles grep's status itself: $(... | grep -v x || true)
			}
			text = m[2]
		}
		elements := pipeElements(text)
		if len(elements) < 2 || !invertedGrep.MatchString(sudoPrefix.ReplaceAllString(elements[len(elements)-1], "")) {
			continue
		}
		out = appendReport(out, src.Report(r, s.Line,
			"grep -v ends the pipeline under set -e — when every line is filtered out it exits 1 and the script stops",
			"Let the filter find nothing: ... | { grep -v ... || true; }"))
	}
	return out
}

var savedStatus = regexp.MustCompile(`(?:^|[\s;|&(])([A-Za-z_][A-Za-z0-9_]*)=\$\?`)

// checkSavedStatusUnread reports rc=$? whose variable is never read, or is
// read only to be written into a file that nothing reads.
func checkSavedStatusUnread(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	if src.Make {
		return nil
	}
	whole := strings.Join(src.Ctx.Lines, "\n")
	var out []*core.Violation
	for _, l := range src.Lines {
		for _, m := range savedStatus.FindAllStringSubmatchIndex(l.Text, -1) {
			if insideQuotes(l.Text, m[2]) {
				continue // "exit=$?" printed as text
			}
			name := l.Text[m[2]:m[3]]
			if savedStatusRead(src, name, whole) {
				continue
			}
			out = appendReport(out, src.Report(r, l.LineAt(m[2]),
				"The status saved in "+name+" is never acted on — nothing reads it, or it goes into a file nothing reads",
				"Check it where it is saved (fail, or mark the run invalid), or read the file it is written to"))
		}
	}
	return out
}

// savedStatusRead reports a read of the variable other than a write of it into a
// file nobody reads.
func savedStatusRead(src *patternkit.ShellSource, name, whole string) bool {
	read := regexp.MustCompile(`\$\{?` + name + `\b`)
	arithmetic := regexp.MustCompile(`\(\([^)]*\b` + name + `\b`)
	if arithmetic.MatchString(whole) {
		return true // (( rc > 1 )) reads it without $
	}
	for _, l := range src.Lines {
		for _, seg := range patternkit.Segments(l.Text) {
			text := seg.Trimmed()
			if !read.MatchString(text) {
				continue
			}
			suffix, written := writtenInto(text, read)
			if !written || suffix == "" || strings.Count(whole, suffix) > 1 {
				return true
			}
		}
	}
	return false
}

var echoInto = regexp.MustCompile(`^(?:echo|printf)\b[^>]*>{1,2}\s*"?([^"\s]+)"?\s*$`)

// writtenInto returns the literal end of the file a write of the variable
// goes into: ".rc" of "$tmp/$1.rc".
func writtenInto(text string, read *regexp.Regexp) (string, bool) {
	m := echoInto.FindStringSubmatch(text)
	if m == nil || read.MatchString(m[1]) {
		return "", false
	}
	target := m[1]
	if i := strings.LastIndexAny(target, "}$"); i >= 0 {
		rest := target[i+1:]
		// $1.rc: skip the name of the last variable.
		rest = strings.TrimLeft(rest, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
		if target[i] == '}' {
			rest = target[i+1:]
		}
		return rest, true
	}
	return target, true
}

var (
	logRedirect = regexp.MustCompile(`>{1,2}\s*"?[^\s&"]+"?\s+2>&1\b`)
	statusCheck = regexp.MustCompile(`\$\{?\?|PIPESTATUS`)
	echoStep    = regexp.MustCompile(`^(?:echo|printf|log\w*)\b`)
)

// checkLoopIgnoresStepFailure reports, in a script without set -e, a loop
// step that runs a script or a service into a log and checks nothing, when a
// message follows the loop.
func checkLoopIgnoresStepFailure(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	if src.Make || errexitSetting.MatchString(strings.Join(src.Ctx.Lines, "\n")) {
		return nil
	}
	funcs := src.Functions()
	steps := src.Steps()
	depth := 0
	var pending, found []int
	for i, s := range steps {
		text := strings.TrimSpace(patternkit.CommandPrefix.ReplaceAllString(s.Text, ""))
		switch {
		case shellLoopStart(s.Text):
			depth++
		case loopEnd.MatchString(text):
			depth--
			if depth == 0 {
				if completionFollows(steps[i+1:]) {
					found = append(found, pending...)
				}
				pending = nil
			}
		case depth > 0 && uncheckedStep(steps, i, text, funcs):
			pending = append(pending, i)
		}
	}
	return reportSteps(r, src, steps, found)
}

func reportSteps(r *shellRule, src *patternkit.ShellSource, steps []patternkit.ShellStep, indexes []int) []*core.Violation {
	var out []*core.Violation
	for _, i := range indexes {
		out = appendReport(out, src.Report(r, steps[i].Line,
			commandWord(steps[i].Text)+" runs into a log and nothing checks its status — without set -e a failed step passes and the loop is reported done",
			"Check the step: cmd > \"$log\" 2>&1 || { echo \"step failed, see $log\" >&2; fail=1; }, and exit with the failure"))
	}
	return out
}

// uncheckedStep reports a step that runs a script, a function or a service
// into a log, with no || or && around it and no $? read after it.
func uncheckedStep(steps []patternkit.ShellStep, i int, text string, funcs map[string]patternkit.ShellFunc) bool {
	if !logRedirect.MatchString(text) || !reportingCommand(text, funcs) {
		return false
	}
	if steps[i].Sep == "||" || steps[i].Sep == "&&" || steps[i].Sep == "&" || conditionStart.MatchString(steps[i].Text) {
		return false // a background job reports through wait
	}
	if i > 0 && (steps[i-1].Sep == "||" || steps[i-1].Sep == "&&") {
		return false
	}
	return i+1 >= len(steps) || !statusCheck.MatchString(steps[i+1].Text)
}

// completionFollows reports a message printed after the loop.
func completionFollows(rest []patternkit.ShellStep) bool {
	for _, s := range rest {
		if echoStep.MatchString(patternkit.CommandPrefix.ReplaceAllString(s.Text, "")) {
			return true
		}
	}
	return false
}

var (
	checkRun       = regexp.MustCompile(`^(?:go\s+(?:test|vet|build)|npm\s+(?:test|run)|pytest|cargo\s+(?:test|build|clippy)|make)\b`)
	stdoutDiscard  = regexp.MustCompile(`(?:^|\s)(?:1?>|&>)\s*/dev/null\b`)
	stdoutElsewise = regexp.MustCompile(`(?:^|\s)1?>\s*[^/&\s]`)
)

// checkCheckOutputDiscarded reports, under set -e, a test, vet or build run
// with stdout to /dev/null and no handler.
func checkCheckOutputDiscarded(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	if src.Make || !errexitSetting.MatchString(strings.Join(src.Ctx.Lines, "\n")) {
		return nil
	}
	var out []*core.Violation
	for _, s := range src.Steps() {
		if s.Sep == "||" || conditionStart.MatchString(s.Text) || strings.HasPrefix(s.Text, "!") {
			continue
		}
		text := envPrefix.ReplaceAllString(patternkit.CommandPrefix.ReplaceAllString(s.Text, ""), "")
		if !checkRun.MatchString(text) || !stdoutDiscard.MatchString(text) || stdoutElsewise.MatchString(stdoutDiscard.ReplaceAllString(text, " ")) {
			continue
		}
		out = appendReport(out, src.Report(r, s.Line,
			strings.Join(strings.Fields(text)[:2], " ")+" runs with its output thrown away under set -e — a failure stops the script without a word of what failed",
			"Keep the output in a log and show it on failure: cmd > \"$log\" 2>&1 || { tail -40 \"$log\" >&2; exit 1; }"))
	}
	return out
}

// checkTestAndLastStatus reports [ ... ] && cmd as the last command of a
// function or of the script.
func checkTestAndLastStatus(r *shellRule, src *patternkit.ShellSource) []*core.Violation {
	if src.Make || len(src.Lines) == 0 {
		return nil
	}
	var out []*core.Violation
	funcs := src.Functions()
	for _, fn := range funcs {
		if testedCall(src, fn.Name) {
			continue // a predicate: callers test its status
		}
		body := src.Body(fn)
		if len(body) == 0 {
			continue
		}
		last := body[len(body)-1]
		if strings.TrimSpace(last.Text) == "}" && len(body) > 1 {
			last = body[len(body)-2]
		}
		out = appendReport(out, testAndLast(r, src, last, "the function returns 1"))
	}
	last := len(src.Lines) - 1
	if strings.TrimSpace(src.Lines[last].Text) == "}" {
		return out // a function ends the file
	}
	if loopEnd.MatchString(strings.TrimSpace(src.Lines[last].Text)) && last > 0 {
		last--
	}
	return appendReport(out, testAndLast(r, src, src.Lines[last], "the script exits 1"))
}

// testedCall reports a function the script calls as a condition.
func testedCall(src *patternkit.ShellSource, name string) bool {
	call := regexp.MustCompile(`(?:\b(?:if|elif|while|until)\s+!?\s*|\|\|\s*|&&\s*|!\s+)` + regexp.QuoteMeta(name) + `\b|\b` + regexp.QuoteMeta(name) + `\b[^;|&]*(?:\|\||&&)`)
	for _, l := range src.Lines {
		if !patternkit.ShellFuncStart.MatchString(l.Text) && call.MatchString(l.Text) {
			return true
		}
	}
	return false
}

// testAndLast reports a line that ends in [ ... ] && cmd.
func testAndLast(r *shellRule, src *patternkit.ShellSource, l patternkit.ShellLine, outcome string) *core.Violation {
	segs := patternkit.Segments(l.Text)
	n := len(segs)
	if n < 2 || segs[n-2].Sep != "&&" || segs[n-1].Sep != "" {
		return nil
	}
	test := strings.TrimSpace(patternkit.CommandPrefix.ReplaceAllString(segs[n-2].Trimmed(), ""))
	if !testCommand.MatchString(test) || strings.HasPrefix(test, "!") || (n > 2 && segs[n-3].Sep != ";" && segs[n-3].Sep != "\n") {
		return nil
	}
	last := strings.TrimSpace(strings.TrimSuffix(patternkit.WithoutComment(strings.TrimSpace(segs[n-1].Text)), "}"))
	if last == "" || testCommand.MatchString(last) {
		return nil // [ a ] && [ b ]: the status is the answer
	}
	return src.Report(r, l.LineAt(segs[n-2].Offset),
		"[ ... ] && cmd is the last command here — when the test is false "+outcome+" though nothing failed",
		"Write it as if [ ... ]; then cmd; fi, or end with an explicit return 0 / exit 0")
}

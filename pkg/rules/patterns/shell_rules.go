package patterns

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// shellRule is a rule over shell scripts and make recipes: check gets the
// file read as shell.
type shellRule struct {
	*rules.BaseRule
	check func(r *shellRule, src *shellSource) []*core.Violation
}

func newShellRule(name, description string, severity core.Severity, check func(*shellRule, *shellSource) []*core.Violation) *shellRule {
	return &shellRule{BaseRule: rules.NewBaseRule(name, "patterns", description, severity), check: check}
}

// AnalyzeFile reads a script or a make file as shell and checks it.
func (r *shellRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	src, ok := readShell(ctx)
	if !ok {
		return nil
	}
	return r.check(r, src)
}

func init() {
	rules.Register(newShellRule("shell-status-of-pipe-tail",
		"Detects $? read after a pipeline that ends in tee, cat or another filter without pipefail — the status is the filter's, and a failed command passes",
		core.SeverityHigh, checkPipeTailStatus))
	rules.Register(newShellRule("shell-redirect-glued-to-word",
		"Detects a 2> or 1> redirection written right after a word (name-2>/dev/null) — the digit becomes part of the argument and stdout is redirected instead of stderr",
		core.SeverityMedium, checkGluedRedirect))
	rules.Register(newShellRule("make-variable-read-before-assignment",
		"Detects a recipe line that reads a shell variable before the same line assigns it — the test sees an empty value",
		core.SeverityHigh, checkReadBeforeAssignment))
	rules.Register(newShellRule("shell-captured-function-writes-logs",
		"Detects log output on stdout of a function whose stdout is captured with $(...) — the log lines end up in the captured value",
		core.SeverityHigh, checkCapturedFunctionOutput))
	rules.Register(newShellRule("shell-wait-ignores-job-status",
		"Detects a bare wait after background jobs — it returns 0 whatever the jobs returned, and a failed job is not seen",
		core.SeverityMedium, checkWaitStatus))
	rules.Register(newShellRule("shell-check-against-own-literal",
		"Detects a check comparing a variable with the literal it was just assigned — the check cannot fail",
		core.SeverityHigh, checkOwnLiteral))
	rules.Register(newShellRule("shell-check-failure-ignored",
		"Detects a security or quality check (gosec, npm audit, trivy, linters) whose failure is turned into success with || true or || (...; exit 0)",
		core.SeverityHigh, checkIgnoredCheckFailure))
	rules.Register(newShellRule("psql-script-without-on-error-stop",
		"Detects psql running a script (-f, a redirect or a pipe) without ON_ERROR_STOP — psql exits 0 when a statement fails",
		core.SeverityHigh, checkPsqlOnErrorStop))
	rules.Register(newShellRule("shell-failure-fallback-value",
		"Detects $(cmd || echo \"$other\") — a failed command is replaced by another value and the failure is not seen",
		core.SeverityMedium, checkFallbackValue))
	rules.Register(newShellRule("shell-poll-loop-falls-through",
		"Detects a bounded polling loop that breaks on success and is followed by no check — on timeout the script goes on as if the wait succeeded",
		core.SeverityHigh, checkPollFallsThrough))
	rules.Register(newShellRule("shell-build-skipped-when-binary-exists",
		"Detects go build guarded by a test that the binary is missing — a stale binary is used after the sources change",
		core.SeverityMedium, checkBuildIfMissing))
	rules.Register(newShellRule("shell-binary-copied-over-in-place",
		"Detects scp of a binary straight onto its installed path — a running binary or a reader sees a half-written file",
		core.SeverityMedium, checkBinaryInPlace))
	rules.Register(newShellRule("shell-local-env-copied-to-remote",
		"Detects scp or rsync of the local .env to a remote host — the deploy overwrites the server's own configuration and secrets with a developer's",
		core.SeverityHigh, checkEnvToRemote))
}

var (
	statusRead       = regexp.MustCompile(`\$\{?\?`)
	pipeFilters      = map[string]bool{"tee": true, "cat": true, "sed": true, "awk": true, "head": true, "tail": true, "sort": true, "uniq": true, "tr": true, "cut": true, "ts": true, "column": true, "fold": true, "nl": true}
	pipefailSetting  = regexp.MustCompile(`pipefail`)
	pipeStatusMarker = regexp.MustCompile(`PIPESTATUS`)
)

// checkPipeTailStatus reports $? read right after a pipeline whose last
// command is a filter, with no pipefail in effect.
func checkPipeTailStatus(r *shellRule, src *shellSource) []*core.Violation {
	if src.make && (pipefailSetting.MatchString(src.makeFlags) || pipefailSetting.MatchString(src.makeShell)) {
		return nil
	}
	var out []*core.Violation
	for _, unit := range src.units() {
		segs := segments(unit.text)
		for k := 1; k < len(segs); k++ {
			loc := statusRead.FindStringIndex(segs[k].text)
			if loc == nil {
				continue
			}
			prev := segs[k-1]
			if !pipeFilters[lastPipeCommand(prev.text)] || pipeStatusMarker.MatchString(prev.text) ||
				pipefailSetting.MatchString(unit.text[:prev.offset]) {
				continue
			}
			line := unit.lineAt(segs[k].offset + loc[0])
			out = appendReport(out, src.report(r, line,
				"$? read after a pipeline ending in "+lastPipeCommand(prev.text)+" — without pipefail it is the status of the filter, and a failed command passes",
				"Run the recipe or script with set -o pipefail (SHELL := bash, .SHELLFLAGS := -eo pipefail -c), or read ${PIPESTATUS[0]} under bash"))
		}
	}
	return append(out, capturedPipeTails(r, src)...)
}

// failingProducers are commands that fail with a status of their own (an
// unreadable file, a refused connection) besides finding nothing.
var failingProducers = map[string]bool{
	"grep": true, "psql": true, "curl": true, "ssh": true, "jq": true, "git": true,
	"docker": true, "kubectl": true, "mysql": true, "aws": true, "gcloud": true,
}

// capturedPipeTails reports a function captured with $(...) whose last
// command is a pipeline from a command that can fail into a filter, with no
// pipefail in the script: the function returns the filter's 0 and an empty
// value, and the caller takes a failure for an absent result.
func capturedPipeTails(r *shellRule, src *shellSource) []*core.Violation {
	if src.make || scriptSetsPipefail(src) {
		return nil
	}
	funcs := src.functions()
	captured := capturedFunctions(src, funcs)
	names := make([]string, 0, len(captured))
	for name := range captured {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []*core.Violation
	for _, name := range names {
		body := src.body(funcs[name])
		if len(body) == 0 {
			continue
		}
		last := body[len(body)-1]
		if strings.TrimSpace(last.text) == "}" && len(body) > 1 {
			last = body[len(body)-2]
		}
		segs := segments(last.text)
		if len(segs) == 0 {
			continue
		}
		tail := segs[len(segs)-1]
		filter := lastPipeCommand(tail.text)
		producer, _, _ := strings.Cut(commandPrefix.ReplaceAllString(tail.trimmed(), ""), " ")
		if !pipeFilters[filter] || !failingProducers[producer] || pipeStatusMarker.MatchString(tail.text) {
			continue
		}
		out = appendReport(out, src.report(r, last.lineAt(tail.offset),
			name+" is captured with $(...) and ends in "+producer+" | ... | "+filter+" — without pipefail a failed "+producer+" returns the filter's 0 and an empty value",
			"Set -o pipefail in the function or the script, or capture "+producer+" alone and check its status"))
	}
	return out
}

// scriptSetsPipefail reports pipefail set in the script itself, outside the
// heredocs it sends to other shells.
func scriptSetsPipefail(src *shellSource) bool {
	terminator := ""
	for _, line := range src.ctx.Lines {
		if terminator != "" {
			if strings.TrimSpace(line) == terminator {
				terminator = ""
			}
			continue
		}
		if m := heredocStart.FindStringSubmatch(line); m != nil {
			terminator = m[1]
		}
		if pipefailSetting.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			return true
		}
	}
	return false
}

var gluedRedirect = regexp.MustCompile(`[A-Za-z_.-]([12])>(?:&[0-9]|/dev/null|\s|$)`)

// checkGluedRedirect reports name-2>/dev/null: the 2 belongs to the word.
func checkGluedRedirect(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		for _, seg := range segments(l.text) {
			loc := gluedRedirect.FindStringSubmatchIndex(seg.text)
			if loc == nil || insideQuotes(seg.text, loc[2]) {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(seg.offset+loc[2]),
				"A "+seg.text[loc[2]:loc[3]]+"> redirection is glued to the word before it — the digit becomes part of the argument and stdout, not stderr, is redirected",
				"Put a space before the redirection: name 2>/dev/null"))
		}
	}
	return out
}

var (
	shellAssignment = regexp.MustCompile(`(?:^|[\s;&|(])(?:local\s+|export\s+)?([a-z_][a-z0-9_]*)=`)
	shellLoopVar    = regexp.MustCompile(`\b(?:for|read)\s+([a-z_][a-z0-9_]*)\b`)
	shellVarRead    = regexp.MustCompile(`\$\{?([a-z_][a-z0-9_]*)`)
)

// checkReadBeforeAssignment reports, in a make recipe, a variable a line
// reads before the same line first assigns it.
func checkReadBeforeAssignment(r *shellRule, src *shellSource) []*core.Violation {
	if !src.make {
		return nil
	}
	var out []*core.Violation
	for _, l := range src.lines {
		assigned := make(map[string]int)
		for _, re := range []*regexp.Regexp{shellAssignment, shellLoopVar} {
			for _, m := range re.FindAllStringSubmatchIndex(l.text, -1) {
				name := l.text[m[2]:m[3]]
				if at, ok := assigned[name]; !ok || m[2] < at {
					assigned[name] = m[2]
				}
			}
		}
		reported := make(map[string]bool)
		for _, m := range shellVarRead.FindAllStringSubmatchIndex(l.text, -1) {
			name := l.text[m[2]:m[3]]
			at, ok := assigned[name]
			if !ok || m[0] > at || reported[name] || insideSingleQuotes(l.text, m[0]) {
				continue
			}
			reported[name] = true
			out = appendReport(out, src.report(r, l.lineAt(m[0]),
				"$"+name+" is read before this recipe line assigns it — the shell sees an empty value there",
				"Move the read after the command that sets "+name+", or give it a value first"))
		}
	}
	return out
}

var (
	captureCall     = regexp.MustCompile(`\$\(\s*([A-Za-z_][A-Za-z0-9_]*)\b`)
	logFunctionName = regexp.MustCompile(`(?i)log|warn|info|error|success|debug|msg|print|step|notice|fail|say`)
	stdoutWrite     = regexp.MustCompile(`^(?:echo|printf)\b`)
	stderrRedirect  = regexp.MustCompile(`(?:^|\s)(?:1?>&2|>\s*/dev/stderr)`)
	fileRedirect    = regexp.MustCompile(`(?:^|[^0-9&])>{1,2}\s*[^&\s]`)
	commandPrefix   = regexp.MustCompile(`^(?:(?:if|elif|then|else|do|while|until|!)\s+)+`)
)

// capturedFunctions returns the functions of a script whose stdout some
// $(...) captures, with the capture segments of each.
func capturedFunctions(src *shellSource, funcs map[string]shellFunc) map[string][]shellSegment {
	captured := make(map[string][]shellSegment)
	for _, l := range src.lines {
		for _, seg := range segments(l.text) {
			for _, m := range captureCall.FindAllStringSubmatch(seg.text, -1) {
				if _, ok := funcs[m[1]]; ok {
					captured[m[1]] = append(captured[m[1]], seg)
				}
			}
		}
	}
	return captured
}

// checkCapturedFunctionOutput reports log functions writing to stdout that
// a captured function calls, and commands of a captured function that merge
// their stderr into its stdout.
func checkCapturedFunctionOutput(r *shellRule, src *shellSource) []*core.Violation {
	funcs := src.functions()
	captured := capturedFunctions(src, funcs)
	reported := make(map[int]bool)
	var out []*core.Violation
	add := func(line int, message, suggestion string) {
		if reported[line] {
			return
		}
		reported[line] = true
		out = appendReport(out, src.report(r, line, message, suggestion))
	}
	for name := range captured {
		for _, l := range src.body(funcs[name]) {
			for _, seg := range segments(l.text) {
				text := commandPrefix.ReplaceAllString(seg.trimmed(), "")
				callee, _, _ := strings.Cut(text, " ")
				logger, ok := funcs[callee]
				if ok && writesToStdout(text) && callee != name && logFunctionName.MatchString(callee) && len(captured[callee]) == 0 {
					for _, line := range src.stdoutWrites(logger) {
						add(line, callee+" writes to stdout, and "+name+" calls it while a caller captures $("+name+") — the log lines become part of the captured value",
							"Write log output to stderr: echo ... >&2")
					}
				}
				if strings.Contains(text, "2>&1") && !fileRedirect.MatchString(strings.ReplaceAll(text, "2>&1", "")) && !strings.Contains(text, "$(") {
					add(l.lineAt(seg.offset), "A command of "+name+" merges its stderr into stdout while a caller captures $("+name+") — its output becomes part of the captured value",
						"Send the command's output to stderr (>&2) or to a log file")
				}
			}
		}
		if src.ctx.IsTestFile() {
			continue // a test stub prints the output it imitates
		}
		for _, line := range src.ownMessages(funcs[name]) {
			add(line, name+" prints a message on the stdout that carries its data while a caller captures $("+name+") — the message becomes part of the captured value",
				"Write the message to stderr: printf '...' >&2")
		}
	}
	for _, line := range stderrCapturesComparedExactly(src) {
		add(line, "The command's stderr is merged into a captured value that is then compared exactly — a warning the command prints makes the value match nothing",
			"Capture stdout only and keep stderr for the error message (2>err.log), or compare after taking the last line")
	}
	return out
}

var (
	// stderrCapture is NAME=$(... 2>&1) with the merge at the end of the
	// substitution.
	stderrCapture = regexp.MustCompile(`(?:^|[\s;&(])([A-Za-z_][A-Za-z0-9_]*)=\$\(.*2>&1\s*\)`)
)

// stderrCapturesComparedExactly returns the lines that capture a command
// with its stderr merged into a variable that a later case or [ x = y ]
// compares with a literal.
func stderrCapturesComparedExactly(src *shellSource) []int {
	var lines []int
	for i, l := range src.lines {
		m := stderrCapture.FindStringSubmatch(l.text)
		if m == nil {
			continue
		}
		exact := regexp.MustCompile(`case\s+"?\$\{?` + m[1] + `\}?"?\s+in\b|\[\[?\s+"?\$\{?` + m[1] + `\}?"?\s+==?\s+['"]?\w`)
		for _, later := range src.lines[i+1:] {
			if exact.MatchString(later.text) {
				lines = append(lines, l.lineAt(0))
				break
			}
		}
	}
	return lines
}

// writesToStdout reports a command whose output is not redirected.
func writesToStdout(command string) bool {
	return !stderrRedirect.MatchString(command) && !fileRedirect.MatchString(command)
}

// stdoutWrites returns the lines where a function echoes to stdout.
func (src *shellSource) stdoutWrites(fn shellFunc) []int {
	var lines []int
	for _, l := range src.body(fn) {
		for _, seg := range segments(l.text) {
			if write := seg.trimmed(); stdoutWrite.MatchString(write) && writesToStdout(write) {
				lines = append(lines, l.lineAt(seg.offset))
			}
		}
	}
	return lines
}

var bareWait = regexp.MustCompile(`^wait\s*$`)

// checkWaitStatus reports a bare wait after background jobs. A wait for
// named PIDs whose failure is discarded is not reported: the jobs may pass
// their outcome through files.
func checkWaitStatus(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, unit := range src.units() {
		background := false
		for _, seg := range flatSegments(unit.text) {
			if bareWait.MatchString(strings.Trim(seg.trimmed(), "(){} \t")) && background {
				out = appendReport(out, src.report(r, unit.lineAt(seg.offset),
					"A bare wait after background jobs returns 0 whatever the jobs returned — a failed job is not seen",
					"Keep each job's PID ($!) and wait for each: wait \"$pid\" || failed=1"))
			}
			if seg.sep == "&" {
				background = true
			}
		}
	}
	return out
}

var (
	literalAssignment = regexp.MustCompile(`^\s*(?:local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=(["']?)([A-Za-z0-9_.:/-]+)["']?\s*(?:#.*)?$`)
	literalCheck      = regexp.MustCompile(`\[\[?\s*"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?\s*(!=|-ne)\s*["']?([A-Za-z0-9_.:/-]+)["']?\s*\]\]?`)
	anyAssignment     = regexp.MustCompile(`(?:^|[\s;&|(])(?:local\s+|export\s+|readonly\s+|declare\s+(?:-\w+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)=|\b(?:read|for|getopts\s+\S+)\s+(?:-\w+\s+)*([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*):?=`)
)

// checkOwnLiteral reports a test of a variable against the literal that is
// the only value the script ever gives it.
func checkOwnLiteral(r *shellRule, src *shellSource) []*core.Violation {
	assignments := make(map[string]int)
	for _, l := range src.lines {
		for _, m := range anyAssignment.FindAllStringSubmatch(l.text, -1) {
			assignments[m[1]+m[2]+m[3]]++
		}
	}
	var out []*core.Violation
	values := make(map[string]string)
	for _, l := range src.lines {
		if m := literalAssignment.FindStringSubmatch(l.text); m != nil {
			if assignments[m[1]] == 1 {
				values[m[1]] = m[3]
			}
			continue
		}
		for _, m := range literalCheck.FindAllStringSubmatchIndex(l.text, -1) {
			name, literal := l.text[m[2]:m[3]], l.text[m[6]:m[7]]
			if value, ok := values[name]; ok && value == literal {
				out = appendReport(out, src.report(r, l.lineAt(m[0]),
					"$"+name+" is compared with "+literal+", the literal it is assigned above and nowhere else — the check cannot fail",
					"Read the value from the system being checked, or delete the check"))
			}
		}
	}
	return out
}

var (
	checkTool      = regexp.MustCompile(`\b(?:gosec|govulncheck|nancy|trivy|grype|snyk|semgrep|golangci-lint|staticcheck|shellcheck|hadolint|eslint|(?:npm|yarn|pnpm)\s+audit|go\s+vet)\b`)
	swallowFailure = regexp.MustCompile(`^(?:true|:|\(.*\bexit\s+0\s*\)?|(?:echo|printf)\b[^;]*)\s*$`)
)

// checkIgnoredCheckFailure reports a check whose failure || true, || (...;
// exit 0) or || echo turns into success, and a make line with the - prefix
// that runs one.
func checkIgnoredCheckFailure(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		if src.make {
			raw := strings.TrimLeft(src.ctx.Lines[l.nums[0]-1], "\t @+")
			if strings.HasPrefix(raw, "-") && checkTool.MatchString(l.text) {
				out = appendReport(out, src.report(r, l.nums[0],
					"The - prefix makes make ignore the failure of this check — the target passes when the check finds problems",
					"Drop the - prefix; let a separate target run the check as advisory if it must not block"))
				continue
			}
		}
		segs := segments(l.text)
		for k := 0; k+1 < len(segs); k++ {
			if segs[k].sep != "||" || !checkTool.MatchString(segs[k].text) {
				continue
			}
			fallback := segs[k+1].trimmed()
			if !swallowFailure.MatchString(fallback) || regexp.MustCompile(`\bexit\s+[1-9]`).MatchString(fallback) {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(segs[k].offset),
				"The failure of "+checkTool.FindString(segs[k].text)+" is turned into success — the target passes when the check finds problems",
				"Let the check fail the target; run it separately if it must only warn"))
		}
	}
	return out
}

var (
	psqlScriptInput   = regexp.MustCompile(`\s(?:-f|--file)[\s=]|\s<{1,2}\s*\S`)
	psqlCommand       = regexp.MustCompile(`(?:^|[\s|;&("'])psql(?:\s|$)`)
	psqlArgsExpansion = regexp.MustCompile(`^[\s|;&("']?psql\s+"?\$\{?[A-Za-z_]`)
)

// checkPsqlOnErrorStop reports psql reading a script without ON_ERROR_STOP.
func checkPsqlOnErrorStop(r *shellRule, src *shellSource) []*core.Violation {
	setsOnErrorStop := strings.Contains(strings.Join(src.ctx.Lines, "\n"), "ON_ERROR_STOP")
	commandVars := psqlCommandVariables(src)
	reportedVars := make(map[string]bool)
	var out []*core.Violation
	for _, l := range src.lines {
		if strings.Contains(l.text, "ON_ERROR_STOP") {
			continue
		}
		for _, seg := range segments(l.text) {
			if name := expandedCommand(seg.trimmed()); commandVars[name] > 0 && psqlScriptInput.MatchString(seg.text) {
				if !reportedVars[name] {
					reportedVars[name] = true
					out = appendReport(out, src.report(r, commandVars[name],
						name+" holds a psql command without ON_ERROR_STOP, and $"+name+" runs a script — it goes on after a failed statement and exits 0",
						"Add -v ON_ERROR_STOP=1 to the command in "+name))
				}
				continue
			}
			at := psqlCommand.FindStringIndex(seg.text)
			if at == nil {
				continue
			}
			rest := seg.text[at[0]:]
			if setsOnErrorStop && psqlArgsExpansion.MatchString(rest) {
				continue // the arguments come from a variable the script fills with ON_ERROR_STOP
			}
			piped := strings.Contains(strings.ReplaceAll(seg.text[:at[0]], "||", ""), "|")
			if !piped && !psqlScriptInput.MatchString(rest) {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(seg.offset+at[0]),
				"psql runs a script without ON_ERROR_STOP — it goes on after a failed statement and exits 0",
				"Pass -v ON_ERROR_STOP=1 (and --single-transaction to apply all or nothing)"))
		}
	}
	return out
}

var fallbackValue = regexp.MustCompile(`\$\((?:[^()]|\([^()]*\))*\|\|\s*echo\s+"?\$\{?[A-Za-z_]`)

// checkFallbackValue reports $(cmd || echo "$other").
func checkFallbackValue(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	funcs := src.functions()
	for _, l := range src.lines {
		segs := segments(l.text)
		for k := 0; k+1 < len(segs); k++ {
			if segs[k].sep == "||" && droppedStatus(segs[k].trimmed(), segs[k+1].trimmed(), funcs) {
				out = appendReport(out, src.report(r, l.lineAt(segs[k].offset),
					"The status of the captured command is dropped with || true — a failed call goes on as an empty value",
					"Fail when the command fails: x=$(cmd) || { echo 'cmd failed' >&2; exit 1; }"))
			}
		}
		for _, loc := range fallbackValue.FindAllStringIndex(l.text, -1) {
			out = appendReport(out, src.report(r, l.lineAt(loc[0]),
				"A failed command is replaced by another variable's value — the failure is not seen and the old value passes for the new",
				"Fail when the command fails: x=$(cmd) || { echo 'cmd failed' >&2; exit 1; }"))
		}
	}
	return out
}

var (
	boundedLoop = regexp.MustCompile(`^(?:for\s+\w+\s+in\s+(?:\$\(seq\b|\{\d+\.\.\d+\})|for\s*\(\(|while\s+\[\[?\s*"?\$\{?\w+\}?"?\s+-l[te]\b)`)
	loopStart   = regexp.MustCompile(`^(?:for|while|until)\b`)
	loopEnd     = regexp.MustCompile(`^done\b`)
	breakCmd    = regexp.MustCompile(`(?:^|\s)break\b`)
	// timeoutBranch is the loop's own handling of the last attempt: it
	// fails, or tests the counter against the bound.
	timeoutBranch = regexp.MustCompile(`(?:^|[\s;])(?:exit|return)\b|\s-(?:eq|ge|gt)\s`)
	afterCheck    = regexp.MustCompile(`^(?:if\b|\[|test\b|!|exit\b|return\b|case\b)`)
)

// checkPollFallsThrough reports a bounded loop with sleep that breaks on
// success and whose end is not followed by a check.
func checkPollFallsThrough(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, unit := range src.units() {
		segs := segments(unit.text)
		var open []pollLoop
		for j, seg := range segs {
			t := strings.TrimSpace(strings.TrimPrefix(seg.trimmed(), "do "))
			switch {
			case loopStart.MatchString(t):
				open = append(open, pollLoop{start: j, bounded: boundedLoop.MatchString(t)})
				continue
			case len(open) == 0:
				continue
			}
			top := &open[len(open)-1]
			top.hasBreak = top.hasBreak || breakCmd.MatchString(t)
			top.handled = top.handled || timeoutBranch.MatchString(t)
			top.hasSleep = top.hasSleep || strings.HasPrefix(t, "sleep") || strings.Contains(t, " sleep ")
			if !loopEnd.MatchString(t) {
				continue
			}
			loop := *top
			open = open[:len(open)-1]
			if len(open) > 0 { // an inner loop's sleep and failure count for the outer one
				open[len(open)-1].hasSleep = open[len(open)-1].hasSleep || loop.hasSleep
				open[len(open)-1].handled = open[len(open)-1].handled || loop.handled
			}
			if !loop.fallsThrough(segs, j) {
				continue
			}
			out = appendReport(out, src.report(r, unit.lineAt(segs[loop.start].offset),
				"The polling loop breaks on success but nothing checks the outcome after it — on timeout the script goes on as if the wait had succeeded",
				"Fail after the loop when the condition still does not hold: if ! <check>; then exit 1; fi"))
		}
	}
	return out
}

// pollLoop is a loop of checkPollFallsThrough while its body is read.
type pollLoop struct {
	start                       int // index of its header segment
	bounded                     bool
	hasBreak, hasSleep, handled bool
}

// fallsThrough reports a bounded polling loop, ending at segment end, that
// breaks on success and leaves the timeout to no check.
func (l pollLoop) fallsThrough(segs []shellSegment, end int) bool {
	if !l.bounded || !l.hasBreak || !l.hasSleep || l.handled {
		return false
	}
	if segs[end].sep == "||" || segs[end].sep == "&&" {
		return false
	}
	return end+1 >= len(segs) || !afterCheck.MatchString(segs[end+1].trimmed())
}

var (
	missingBinaryTest = regexp.MustCompile(`\[\[?\s*!\s+-[xfe]\s+"?([^\s"\]]+)"?\s*\]\]?`)
	staleCheck        = regexp.MustCompile(`\s-nt\s|-newer|(?i)hash|sum\b|\s!=\s`)
	goBuildOutput     = regexp.MustCompile(`\bgo\s+build\b[^;&|]*?\s-o\s+"?([^\s";]+)`)
)

// checkBuildIfMissing reports go build guarded by a test that the output
// binary does not exist.
func checkBuildIfMissing(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, unit := range src.units() {
		if staleCheck.MatchString(unit.text) {
			continue // the build also runs when the sources are newer or their hash changed
		}
		builds := make(map[string]bool)
		for _, m := range goBuildOutput.FindAllStringSubmatch(unit.text, -1) {
			builds[path.Base(m[1])] = true
		}
		for _, m := range missingBinaryTest.FindAllStringSubmatchIndex(unit.text, -1) {
			if !builds[path.Base(unit.text[m[2]:m[3]])] {
				continue
			}
			out = appendReport(out, src.report(r, unit.lineAt(m[0]),
				"go build runs only when the binary is missing — after the sources change the stale binary keeps being used",
				"Build every time (go build is incremental), or compare the binary's age with the sources"))
		}
	}
	return out
}

var (
	binaryCopy   = regexp.MustCompile(`\b(?:scp|rsync)\b[^;&|]*\s(\S*(?:BIN\b|BIN\)|_BIN\}|bin/)\S*)\s+(\S+):(\S+)`)
	stagingPath  = regexp.MustCompile(`(?i)(?:\.new|\.tmp|\.part|\.next|-new|tmp|/tmp/|\.\$\$)`)
	remoteRename = regexp.MustCompile(`\bmv\b|\binstall\b`)
)

// checkBinaryInPlace reports scp of a binary straight onto its remote path,
// with no rename after it in the same unit.
func checkBinaryInPlace(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, unit := range src.units() {
		segs := segments(unit.text)
		for k, seg := range segs {
			m := binaryCopy.FindStringSubmatchIndex(seg.text)
			if m == nil || stagingPath.MatchString(seg.text[m[6]:m[7]]) || strings.HasSuffix(seg.text[m[6]:m[7]], "/") {
				continue
			}
			renamed := false
			for _, later := range segs[k+1:] {
				renamed = renamed || remoteRename.MatchString(later.text)
			}
			if renamed {
				continue
			}
			out = appendReport(out, src.report(r, unit.lineAt(seg.offset),
				"The binary is copied straight onto its installed path — a running process or a reader sees a half-written file, and a failed copy leaves it broken",
				"Copy to a temporary name next to it and rename it into place (mv is atomic on one filesystem)"))
		}
	}
	return out
}

// envCopy is a copy of the local .env onto the server's .env or into its directory;
// a copy under another name (.env.new) is merged on the server.
var envCopy = regexp.MustCompile(`\b(?:scp|rsync)\b[^;&|]*\s"?(?:\./)?\.env(?:\.(?:prod|production|local))?"?\s+"?[^\s:"]+:(?:[^\s"]*/(?:\.env)?)?"?(?:\s|$)`)

// checkEnvToRemote reports scp or rsync of the local .env to a remote host.
func checkEnvToRemote(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		for _, seg := range segments(l.text) {
			if envCopy.MatchString(seg.text) {
				out = appendReport(out, src.report(r, l.lineAt(seg.offset),
					"The local .env is copied to a remote host — the deploy overwrites the server's configuration and secrets with the developer's",
					"Keep the server's .env on the server and change it on purpose; deploy only code and versioned config"))
			}
		}
	}
	return out
}

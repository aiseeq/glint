package patterns

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(newShellRule("shell-file-name-from-time-of-day",
		"Detects a file name built from $(date) with the time of day only (%H%M%S, no date, no $$), or a name stamp taken twice for files that belong together — parallel runs collide, and two stamps of one run differ by a second",
		core.SeverityMedium, checkTimeOfDayNames))
	rules.Register(newShellRule("shell-pgrep-matches-own-wrapper",
		"Detects pgrep -f PATTERN inside a script passed to bash -c, sh -c or ssh — the wrapper carries the pattern on its own command line, and pgrep finds it",
		core.SeverityMedium, checkPgrepOwnWrapper))
	rules.Register(newShellRule("shell-background-job-without-trap",
		"Detects a background job the script kills only at the end of its normal path, with no trap — an error, a timeout or Ctrl-C leaves the job running",
		core.SeverityMedium, checkBackgroundWithoutTrap))
	rules.Register(newShellRule("shell-trap-in-loop",
		"Detects trap ... EXIT set inside a loop — each iteration replaces the trap of the previous one, and only the last cleanup runs",
		core.SeverityMedium, checkTrapInLoop))
	rules.Register(newShellRule("shell-trap-removes-results",
		"Detects trap 'rm -rf \"$dir\"' EXIT while the results are copied out of $dir only at the end of the normal path, after an exit on failure — the log of a failed run is removed with the directory",
		core.SeverityMedium, checkTrapRemovesResults))
	rules.Register(newShellRule("shell-lock-inherited-by-background",
		"Detects flock without -o (or a lock descriptor left open) in a script that starts a background job — the job inherits the lock and holds it after the script is done",
		core.SeverityMedium, checkLockInherited))
	rules.Register(newShellRule("shell-self-relaunch-outside-lock",
		"Detects a script serialized with flock that restarts itself in the background — the background run goes on without the lock while the next caller takes it",
		core.SeverityMedium, checkSelfRelaunch))
	rules.Register(newShellRule("shell-lock-failure-ignored",
		"Detects flock (or a function taking it) followed by || true — after the timeout the script goes on without the lock as if it held it",
		core.SeverityHigh, checkLockFailureIgnored))
	rules.Register(newShellRule("shell-shared-worktree-without-lock",
		"Detects git checkout -B, rebase, reset --hard or branch -D in a fixed directory taken from an environment default, with no lock — two runs rewrite the same worktree under each other",
		core.SeverityMedium, checkSharedWorktree))
	rules.Register(newShellRule("shell-cmdline-pattern-with-space",
		"Detects grep for a pattern with a space in /proc/<pid>/cmdline — the arguments there are separated by NUL, so the pattern never matches",
		core.SeverityHigh, checkCmdlineSpace))
	rules.Register(newShellRule("shell-poll-loop-relaunches",
		"Detects a polling loop that starts a process whenever a check does not see it yet, with no counter or time limiting the starts — a slow start is answered with another copy every iteration",
		core.SeverityMedium, checkPollRelaunches))
	rules.Register(newShellRule("shell-fixed-sleep-after-start",
		"Detects a fixed sleep of seconds right after starting a process, a container or a service — a slow start breaks the next step, a fast one wastes the wait",
		core.SeverityLow, checkFixedSleepAfterStart))
}

var (
	workerVariable = regexp.MustCompile(`(?im)^\s*(?:local\s+|export\s+)?\w*worker\w*=|\bxargs\b[^|;]*\s-P\s*\d|(?:^|[|;&]\s*)parallel\s`)
	mktempDir      = regexp.MustCompile(`(?m)^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)=\$\(mktemp\b`)
	workerRef      = regexp.MustCompile(`(?i)\$\{?\w*worker`)
	scriptsCopy    = regexp.MustCompile(`\bscp\b[^;&|]*\s\S*\*\.sh"?\s+"?[^\s":]+:([^\s"]*)"?`)
	stagingDir     = regexp.MustCompile(`(?i)incoming|staging|\.new|tmp|\.part`)
)

// builtByWorkers reports go build -o onto a shared path in a script that runs
// as one of several workers: a worker starts a binary another one writes.
func builtByWorkers(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	code := make([]string, len(src.lines))
	for i, l := range src.lines {
		code[i] = withoutComment(l.text)
	}
	whole := strings.Join(code, "\n")
	if !workerVariable.MatchString(whole) || strings.Contains(whole, "flock") {
		return nil
	}
	perRun := map[string]bool{}
	for _, m := range mktempDir.FindAllStringSubmatch(whole, -1) {
		perRun[m[1]] = true
	}
	var out []*core.Violation
	for _, l := range src.lines {
		m := goBuildOutput.FindStringSubmatchIndex(l.text)
		if m == nil {
			continue
		}
		target := l.text[m[2]:m[3]]
		if stagingPath.MatchString(target) || workerRef.MatchString(target) || perRun[rootVariable(target)] {
			continue
		}
		out = appendReport(out, src.report(r, l.lineAt(m[2]),
			"Parallel workers build straight onto "+target+" — a worker starts or copies the binary while another one writes it",
			"Build to a temporary name and rename it into place (go build -o \"$out.new\" && mv -f \"$out.new\" \"$out\"), under a lock if workers share it"))
	}
	return out
}

// rootVariable returns the variable a path starts with: built of
// "$built/x/y".
func rootVariable(path string) string {
	path = strings.TrimPrefix(strings.Trim(path, `"`), "$")
	path = strings.TrimPrefix(path, "{")
	end := strings.IndexFunc(path, func(c rune) bool { return !isIdentChar(byte(c)) })
	if end < 0 {
		return path
	}
	return path[:end]
}

// scriptsOverRunning reports scp of *.sh straight into the directory a host
// runs them from: bash reads a script while it runs it.
func scriptsOverRunning(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		m := scriptsCopy.FindStringSubmatchIndex(l.text)
		if m == nil || stagingDir.MatchString(l.text[m[2]:m[3]]) {
			continue
		}
		out = appendReport(out, src.report(r, l.lineAt(m[0]),
			"Scripts are copied over the copies the host runs — bash reads a script while it runs it, and a running one reads a half-written file",
			"Copy into a staging directory and rename each file into place on the host (mv is atomic on one filesystem)"))
	}
	return out
}

var (
	dateStamp  = regexp.MustCompile(`\$\(date\s+['"]?\+([^)'"]+)['"]?\)`)
	stampVar   = regexp.MustCompile(`^(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)=\$\(date\s+['"]?\+([^)'"]+)['"]?\)$`)
	pathValue  = regexp.MustCompile(`^(?:local\s+)?[A-Za-z_][A-Za-z0-9_]*="?([^"]*)"?$`)
	uniquePart = regexp.MustCompile(`\$\$|\$\{?RANDOM|\$\{?BASHPID|mktemp|%N`)
	timeToken  = regexp.MustCompile(`%[HMSTRIlkp]`)
	dateToken  = regexp.MustCompile(`%[YymdFDjseBbhCGgVUWu]`)
)

// timeOfDayOnly reports a date format with a time and no date.
func timeOfDayOnly(format string) bool {
	return timeToken.MatchString(format) && !dateToken.MatchString(format) && !strings.Contains(format, "%N")
}

// checkTimeOfDayNames reports file names stamped with the time of day only,
// and a stamp taken twice for names of one run.
func checkTimeOfDayNames(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	stamps := map[string]bool{}
	taken := map[string]int{}
	reported := map[int]bool{}
	var out []*core.Violation
	report := func(line int, message string) {
		if reported[line] {
			return
		}
		reported[line] = true
		out = appendReport(out, src.report(r, line, message,
			"Take the stamp once per run and make it unique: ts=$(date +%Y%m%d-%H%M%S)-$$, and build every name of the run from it"))
	}
	for _, l := range src.lines {
		text := withoutComment(strings.TrimSpace(l.text))
		if m := stampVar.FindStringSubmatch(text); m != nil {
			stamps[m[1]] = timeOfDayOnly(m[2])
			continue
		}
		m := pathValue.FindStringSubmatch(text)
		if m == nil || !looksLikePath(m[1]) {
			continue
		}
		unique := uniquePart.MatchString(m[1])
		for _, d := range dateStamp.FindAllStringSubmatch(m[1], -1) {
			taken[d[1]]++
			if taken[d[1]] > 1 {
				report(l.lineAt(0), "The name stamp is taken again here — the files of one run get stamps a second apart and no longer match by it")
			}
			if timeOfDayOnly(d[1]) && !unique {
				report(l.lineAt(0), "The file name is unique only by the time of day — parallel runs within one second (or runs on two days) get the same name")
			}
		}
		for name, timeOnly := range stamps {
			if timeOnly && !unique && regexp.MustCompile(`\$\{?`+name+`\b`).MatchString(m[1]) {
				report(l.lineAt(0), "The file name is unique only by the time of day ($"+name+") — parallel runs within one second (or runs on two days) get the same name")
			}
		}
	}
	return out
}

// looksLikePath reports a value with a directory or an extension.
func looksLikePath(value string) bool {
	return strings.Contains(value, "/") || regexp.MustCompile(`\.[A-Za-z][A-Za-z0-9]{1,9}$`).MatchString(value)
}

var pgrepPattern = regexp.MustCompile(`\bpgrep\s+(?:-[A-Za-z]+\s+)*?-[A-Za-z]*f[A-Za-z]*\s+`)

// checkPgrepOwnWrapper reports pgrep -f inside a quoted script run by
// another shell.
func checkPgrepOwnWrapper(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		for _, loc := range pgrepPattern.FindAllStringIndex(l.text, -1) {
			if !insideQuotes(l.text, loc[0]) {
				continue
			}
			pattern := l.text[loc[1]:]
			if end := strings.IndexAny(pattern, "|);"); end >= 0 {
				pattern = pattern[:end]
			}
			if strings.Contains(pattern, "[") || strings.HasPrefix(strings.TrimLeft(pattern, `"'`), "^") {
				continue // [x] or an anchor keeps the pattern off the wrapper's command line
			}
			out = appendReport(out, src.report(r, l.lineAt(loc[0]),
				"pgrep -f runs inside a script passed to another shell, whose command line carries the same pattern — pgrep finds the wrapper",
				"Write one character of the pattern as a class (pgrep -f '[s]ession.sh'), or match the process name exactly (pgrep -x)"))
		}
	}
	return out
}

var (
	savedPid = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=\$!$`)
	trapLine = regexp.MustCompile(`(?m)^\s*trap\s+.*\b(?:EXIT|INT|TERM|0)\b`)
	detached = regexp.MustCompile(`^(?:nohup|setsid|disown)\b`)
)

// checkBackgroundWithoutTrap reports a background job in a script with no
// trap, which the script kills only at the end of its normal path or leaves
// behind on an exit for failure.
func checkBackgroundWithoutTrap(r *shellRule, src *shellSource) []*core.Violation {
	whole := strings.Join(src.ctx.Lines, "\n")
	if src.make || trapLine.MatchString(whole) || regexp.MustCompile(`(?m)^\s*wait\b`).MatchString(whole) {
		return nil
	}
	var out []*core.Violation
	steps := src.steps()
	for i, s := range steps {
		if s.sep != "&" || detached.MatchString(commandPrefix.ReplaceAllString(s.text, "")) {
			continue
		}
		killedLater := false
		if i+1 < len(steps) {
			if m := savedPid.FindStringSubmatch(withoutComment(steps[i+1].text)); m != nil {
				killedLater = regexp.MustCompile(`\bkill\b[^;|&]*\$\{?` + m[1] + `\b`).MatchString(whole)
			}
		}
		failsLater := false
		for _, later := range steps[i+1:] {
			failsLater = failsLater || failExit.MatchString(later.text) || regexp.MustCompile(`\breturn\s+[1-9]`).MatchString(later.text)
		}
		if !killedLater && !failsLater {
			continue
		}
		out = appendReport(out, src.report(r, s.line,
			"The background job is stopped only on the normal path, and nothing stops it on an error, a timeout or Ctrl-C — it is left running",
			"Save its pid and kill it from a trap: pid=$!; trap 'kill \"$pid\" 2>/dev/null || true' EXIT INT TERM"))
	}
	return out
}

var trapExit = regexp.MustCompile(`^trap\s+.*\b(?:EXIT|0)\b`)

// checkTrapInLoop reports trap ... EXIT set inside a loop.
func checkTrapInLoop(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
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
		case depth > 0 && trapExit.MatchString(text):
			out = appendReport(out, src.report(r, s.line,
				"trap ... EXIT inside a loop replaces the trap of the previous iteration — only the last cleanup runs",
				"Set one trap before the loop that cleans up everything the loop made (collect the paths in an array), or clean up at the end of each iteration"))
		}
	}
	return out
}

var (
	trapRemove = regexp.MustCompile(`^\s*trap\s+(['"])(.*?)['"]\s+.*\b(?:EXIT|0)\b`)
	removedDir = regexp.MustCompile(`\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?`)
	failExit   = regexp.MustCompile(`\bexit\s+(?:[1-9]|"?\$)`)
)

// checkTrapRemovesResults reports trap 'rm -rf "$dir"' EXIT when the results
// are copied out of dir only after an exit on failure.
func checkTrapRemovesResults(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	errexit := errexitSetting.MatchString(strings.Join(src.ctx.Lines, "\n"))
	var out []*core.Violation
	for i, l := range src.lines {
		m := trapRemove.FindStringSubmatch(l.text)
		if m == nil || regexp.MustCompile(`\b(?:cp|mv|rsync|tar)\b`).MatchString(m[2]) {
			continue
		}
		dir := removedDir.FindStringSubmatch(m[2])
		if dir == nil {
			continue
		}
		// A copy out takes its source from the directory; a copy into it
		// (cp "$bin" "$work/") does not count.
		copyOut := regexp.MustCompile(`\b(?:cp|mv)\s+(?:-\S+\s+)*"?\$\{?` + dir[1] + `\}?/`)
		failed := errexit
		for _, later := range src.lines[i+1:] {
			if copyOut.MatchString(later.text) {
				if failed {
					out = appendReport(out, src.report(r, l.lineAt(0),
						"The trap removes $"+dir[1]+" on exit, and a failed run exits before the results are copied out of it — the log of the failure is removed with the directory",
						"Copy the results out in the trap before removing the directory, or copy them before any exit on failure"))
				}
				break
			}
			failed = failed || failExit.MatchString(later.text)
		}
	}
	return out
}

var (
	flockCommand = regexp.MustCompile(`\bflock\b((?:\s+-[A-Za-z-]+(?:\s+(?:\d+|"[^"]*"|\$\S+))?)*)\s+"?[^\s"]+"?\s+\S`)
	flockFd      = regexp.MustCompile(`\bflock\b(?:\s+-[A-Za-z-]+(?:\s+(?:\d+|"[^"]*"|\$\S+))?)*\s+(\d+)\s*(?:$|[;&|)])`)
	lockClose    = regexp.MustCompile(`(?:^|\s)-o\b|--close\b`)
)

// checkLockInherited reports flock that a background job of the script
// inherits.
func checkLockInherited(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	steps := src.steps()
	var out []*core.Violation
	for _, l := range src.lines {
		text := withoutComment(l.text)
		if loc := regexp.MustCompile(`\bflock\b`).FindStringIndex(text); loc == nil || insideQuotes(text, loc[0]) {
			continue // a lock taken by a remote or nested shell
		}
		if fd := flockFd.FindStringSubmatch(text); fd != nil {
			// A descriptor opened for a subshell, ( flock 9; ... ) 9>file,
			// ends with it; exec 9>file keeps it for the whole script.
			if !opensForScript(src, fd[1]) {
				continue
			}
			if backgroundKeeps(steps, l.lineAt(0), regexp.MustCompile(`\b`+fd[1]+`>&-`)) {
				out = appendReport(out, src.report(r, l.lineAt(0),
					"The lock descriptor "+fd[1]+" stays open in a background job the script starts — the job holds the lock after the script is done",
					"Close it for the job: cmd "+fd[1]+">&- &"))
			}
			continue
		}
		m := flockCommand.FindStringSubmatch(text)
		if m == nil || lockClose.MatchString(m[1]) || !backgroundKeeps(steps, l.lineAt(0), nil) {
			continue
		}
		out = appendReport(out, src.report(r, l.lineAt(0),
			"flock runs the command with the lock descriptor open, and a background job the script starts inherits it — the lock is held after the script is done",
			"Pass -o (--close) so the command does not keep the lock descriptor, or close it for the job (cmd 9>&- &)"))
	}
	return out
}

// opensForScript reports exec N>file outside quotes: a descriptor the
// script keeps open from there on.
func opensForScript(src *shellSource, fd string) bool {
	open := regexp.MustCompile(`\bexec\s+` + fd + `>`)
	for _, l := range src.lines {
		for _, loc := range open.FindAllStringIndex(l.text, -1) {
			if !insideQuotes(l.text, loc[0]) {
				return true
			}
		}
	}
	return false
}

// backgroundKeeps reports a background job after the lock that does not
// close the lock descriptor (closed matches its closing redirection; nil: none closes it).
func backgroundKeeps(steps []shellStep, after int, closed *regexp.Regexp) bool {
	for _, s := range steps {
		if s.line > after && s.sep == "&" && (closed == nil || !closed.MatchString(s.text)) {
			return true
		}
	}
	return false
}

var (
	selfLock       = regexp.MustCompile(`\bflock\b[^;|&]*\s"?\$0"?`)
	selfBackground = regexp.MustCompile(`(?:^|\s)(?:nohup\s+|setsid\s+)?"?\$0"?\s`)
)

// checkSelfRelaunch reports a script serialized with flock that starts
// itself in the background.
func checkSelfRelaunch(r *shellRule, src *shellSource) []*core.Violation {
	code := make([]string, len(src.lines))
	for i, l := range src.lines {
		code[i] = withoutComment(l.text)
	}
	whole := strings.Join(code, "\n")
	if src.make || !selfLock.MatchString(whole) || len(regexp.MustCompile(`\bflock\b`).FindAllString(whole, -1)) > 1 {
		return nil // a second flock: the background branch takes a lock of its own
	}
	var out []*core.Violation
	for _, s := range src.steps() {
		if s.sep != "&" || selfLock.MatchString(s.text) || !selfBackground.MatchString(" "+s.text) {
			continue
		}
		out = appendReport(out, src.report(r, s.line,
			"The script runs under flock but restarts itself in the background — that run goes on without the lock while the next caller takes it",
			"Take the lock in the background branch too (flock on the same file before it touches shared state)"))
	}
	return out
}

// checkLockFailureIgnored reports flock, or a function taking it, followed
// by || true.
func checkLockFailureIgnored(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	funcs := src.functions()
	locking := map[string]bool{}
	for name, fn := range funcs {
		for _, l := range src.body(fn) {
			if regexp.MustCompile(`\bflock\b`).MatchString(l.text) {
				locking[name] = true
			}
		}
	}
	var out []*core.Violation
	steps := src.steps()
	for i := 0; i+1 < len(steps); i++ {
		word := commandWord(steps[i].text)
		if steps[i].sep != "||" || !excuses(steps[i+1].text) || (word != "flock" && !locking[word]) {
			continue
		}
		out = appendReport(out, src.report(r, steps[i].line,
			"A failure to take the lock is excused with || true — after the timeout the script goes on without the lock as if it held it",
			"Stop (or skip the work) when the lock is not taken: flock -w 30 9 || { echo 'busy' >&2; exit 1; }"))
	}
	return out
}

var (
	envDefault = regexp.MustCompile(`^(?:local\s+|export\s+)?([A-Za-z_][A-Za-z0-9_]*)=\$\{[A-Za-z_][A-Za-z0-9_]*:-[^}]+\}$`)
	gitRewrite = regexp.MustCompile(`\bgit\s+(?:-C\s+\S+\s+)?(?:checkout\s+(?:-q\s+)?-[bB]\b|rebase\b|reset\s+--hard\b|branch\s+-D\b)`)
	// A script lock: flock, or a lock directory. A mention of git's own
	// index.lock is no lock of the script.
	lockPresent = regexp.MustCompile(`\bflock\b|mkdir\s+[^;|&]*lock`)
)

// checkSharedWorktree reports git rewriting a fixed worktree from an
// environment default with no lock in the script.
func checkSharedWorktree(r *shellRule, src *shellSource) []*core.Violation {
	if src.make || lockPresent.MatchString(strings.Join(src.ctx.Lines, "\n")) {
		return nil
	}
	shared := map[string]bool{}
	inShared := false
	var out []*core.Violation
	for _, l := range src.lines {
		text := withoutComment(strings.TrimSpace(l.text))
		if m := envDefault.FindStringSubmatch(text); m != nil && !strings.Contains(text, "mktemp") {
			shared[m[1]] = true
		}
		for name := range shared {
			if regexp.MustCompile(`(?:^|[;&|]\s*)cd\s+"?\$\{?` + name + `\b`).MatchString(text) {
				inShared = true
			}
		}
		if inShared && gitRewrite.MatchString(text) {
			out = appendReport(out, src.report(r, l.lineAt(0),
				"git rewrites a fixed worktree taken from an environment default, with no lock — two runs check out and rebase under each other",
				"Take a lock on the worktree first (exec 9>\"$wt.lock\"; flock -n 9 || exit 1), or make a worktree per run"))
			return out
		}
	}
	return out
}

var cmdlineGrep = regexp.MustCompile(`\bgrep\b[^|;]*?(["'])([^"']*\s[^"']*)["'][^|;]*?/proc/\S*cmdline`)

// checkCmdlineSpace reports grep for a pattern with a space in a cmdline
// file read as is.
func checkCmdlineSpace(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		for _, seg := range segments(l.text) {
			loc := cmdlineGrep.FindStringIndex(seg.text)
			if loc == nil || strings.Contains(seg.text, "tr ") {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(seg.offset+loc[0]),
				"The pattern has a space, and /proc/<pid>/cmdline separates arguments with NUL — it never matches",
				"Turn the NULs into spaces first: tr '\\0' ' ' < /proc/$p/cmdline | grep -q -- \"...\""))
		}
	}
	return out
}

var (
	launchWord   = regexp.MustCompile(`(?i)^(?:launch|start|spawn|restart|run)(?:_|$)|_(?:launch|start|spawn|restart)$`)
	counterGuard = regexp.MustCompile(`\s-(?:ge|gt|le|lt|eq)\s|\$\(\(|SECONDS|date\s+\+%s`)
	notRunning   = regexp.MustCompile(`\[\[?\s*-z\s|^!|^if\s+!|^if\s+\[\[?\s*-z\s`)
)

// checkPollRelaunches reports a polling loop that starts a process whenever
// a check does not see it, with no limit on the starts.
func checkPollRelaunches(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	steps := src.steps()
	var out []*core.Violation
	var open []int
	for i, s := range steps {
		text := strings.TrimSpace(commandPrefix.ReplaceAllString(s.text, ""))
		switch {
		case shellLoopStart(s.text):
			open = append(open, i)
			continue
		case loopEnd.MatchString(text) && len(open) > 0:
			start := open[len(open)-1]
			open = open[:len(open)-1]
			out = append(out, relaunches(r, src, steps[start:i+1])...)
		}
	}
	return out
}

// relaunches reports the starts in one loop body guarded by a check that the
// process is not there and by nothing that counts.
func relaunches(r *shellRule, src *shellSource, body []shellStep) []*core.Violation {
	sleeps := false
	for _, s := range body {
		sleeps = sleeps || strings.HasPrefix(commandPrefix.ReplaceAllString(s.text, ""), "sleep")
	}
	if !sleeps {
		return nil
	}
	var out []*core.Violation
	for k := 1; k < len(body); k++ {
		launch := body[k]
		word := commandWord(launch.text)
		if !launchWord.MatchString(word) && launch.sep != "&" {
			continue
		}
		guard := body[k-1]
		guarded := guard.sep == "&&" || guard.sep == "||" || strings.HasPrefix(guard.text, "if ") || strings.HasPrefix(guard.text, "elif ")
		if !guarded || !notRunning.MatchString(strings.TrimSpace(guard.text)) && guard.sep != "||" || counterGuard.MatchString(guard.text) {
			continue
		}
		out = appendReport(out, src.report(r, launch.line,
			word+" is started on every iteration the check does not see the process yet — a slow start gets another copy each time",
			"Start once and wait, or remember when it was started and start again only after a timeout (last=$i; [ $((i - last)) -ge 20 ])"))
	}
	return out
}

var (
	sleepSeconds = regexp.MustCompile(`^sleep\s+(\d+)\s*$`)
	startStep    = regexp.MustCompile(`\bdocker\s+(?:compose\s+[^;|&]*\bup\b[^;|&]*\s-d\b|run\s+[^;|&]*-d\b|start\b)|\bsystemctl\s+(?:re)?start\b|\bservice\s+\S+\s+(?:re)?start\b|^nohup\b`)
)

// afterStart reports a step i that follows a start: a background job, a
// container or service start, a start_* function, or a polling wait for the
// thing to appear (and its check) - its insides are still coming up.
func afterStart(steps []shellStep, i int) bool {
	prev := steps[i-1]
	text := commandPrefix.ReplaceAllString(prev.text, "")
	if prev.sep == "&" || startStep.MatchString(text) || launchWord.MatchString(commandWord(text)) {
		return true
	}
	// A wait for the thing to appear, checked: [ -n "$c" ] || { ...; return 1; }.
	j := i - 1
	if j < 2 || !strings.HasPrefix(steps[j].text, "{") || steps[j-1].sep != "||" || !testCommand.MatchString(steps[j-1].text) {
		return false
	}
	return loopEnd.MatchString(strings.TrimSpace(steps[j-2].text))
}

// checkFixedSleepAfterStart reports sleep N (N >= 3) right after a start,
// outside loops.
func checkFixedSleepAfterStart(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	steps := src.steps()
	var out []*core.Violation
	depth := 0
	for i, s := range steps {
		text := withoutComment(strings.TrimSpace(commandPrefix.ReplaceAllString(s.text, "")))
		switch {
		case shellLoopStart(s.text):
			depth++
			continue
		case loopEnd.MatchString(text):
			depth--
			continue
		}
		m := sleepSeconds.FindStringSubmatch(text)
		if m == nil || depth > 0 || i == 0 {
			continue
		}
		if n, err := strconv.Atoi(m[1]); err != nil || n < 3 {
			continue
		}
		if !afterStart(steps, i) {
			continue
		}
		out = appendReport(out, src.report(r, s.line,
			"A fixed sleep waits for what was just started — a slow start breaks the next step, a fast one wastes the wait",
			"Poll for readiness with a deadline: for i in $(seq 1 30); do ready && break; sleep 1; done; ready || exit 1"))
	}
	return out
}

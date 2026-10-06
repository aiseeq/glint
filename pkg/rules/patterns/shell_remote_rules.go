package patterns

import (
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(newShellRule("remote-multiline-script-without-errexit",
		"Detects a multi-line script passed to ssh or bash -c without set -e — every line runs whatever the one before returned, and the caller sees the status of the last line only",
		core.SeverityMedium, checkRemoteScriptErrexit))
	rules.Register(newShellRule("shell-fallback-echo-duplicates-command-output",
		"Detects $(cmd || echo LITERAL) where cmd prints its answer even when it exits non-zero (grep -c, systemctl is-active, curl -w '%{http_code}') — the capture holds both lines",
		core.SeverityMedium, checkFallbackEchoDuplicates))
	rules.Register(newShellRule("shell-eval-output-overwrites-script-variable",
		"Detects eval of a captured NAME=value report whose names are also the script's own variables — the report overwrites the script's settings",
		core.SeverityHigh, checkEvalOverwrites))
	rules.Register(newShellRule("pg-hba-rule-appended-after-catch-all",
		"Detects a host or local rule appended to pg_hba.conf with >> or tee -a — the default file ends in catch-all rules, the first matching line wins, and the appended one is never used",
		core.SeverityHigh, checkPgHbaAppend))
	rules.Register(newShellRule("deploy-overwrites-config-edited-by-certbot",
		"Detects a script that rewrites an nginx site file on every run and also runs certbot --nginx, which edits that file in place — the next deploy drops the TLS server block",
		core.SeverityHigh, checkCertbotConfigOverwrite))
	rules.Register(newShellRule("shell-set-e-exits-before-failure-handler",
		"Detects, under set -e, VAR=$(cmd) followed by a test of VAR where cmd exits non-zero for the very value tested (systemctl is-active, grep, curl -f) — the script stops before the handler runs",
		core.SeverityHigh, checkSetEBeforeHandler))

	smoke := &shellSourceTextRule{}
	smoke.shellRule = newShellRule("smoke-check-greps-renamed-ui-text",
		"Detects a smoke check that greps a page for a literal text no template or source file of the application contains — the text was renamed, and the check fails on a working page",
		core.SeverityMedium, func(_ *shellRule, src *shellSource) []*core.Violation { return checkSmokeGrepText(smoke, src) })
	smoke.ResetState()
	rules.Register(smoke)

	unitEnv := &unitEnvRule{}
	unitEnv.shellRule = newShellRule("oneoff-command-env-differs-from-service-unit",
		"Detects a command that sources the environment file of a systemd unit written by the project while the unit also reads another EnvironmentFile — the command runs without what the service gets from the other file",
		core.SeverityHigh, func(_ *shellRule, src *shellSource) []*core.Violation { return checkUnitEnvSource(unitEnv, src) })
	unitEnv.ResetState()
	rules.Register(unitEnv)
}

// heredocOpen is the start of a heredoc (<<EOF, <<-'EOF'), not of a here
// string (<<<).
var heredocOpen = regexp.MustCompile(`(?:^|[^<])<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// blankedScript returns the lines of a script as one text in which comment
// lines, heredoc bodies and heredoc terminators are blanked with spaces, so
// that offsets keep their place and apostrophes in prose open no quote; and
// the offset where each line starts.
func blankedScript(lines []string) (string, []int) {
	var b strings.Builder
	starts := make([]int, 0, len(lines))
	terminator := ""
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		starts = append(starts, b.Len())
		trimmed := strings.TrimSpace(line)
		switch {
		case terminator != "":
			if word := strings.TrimRight(trimmed, `"')`); word == terminator {
				terminator = ""
				line = strings.Replace(line, word, strings.Repeat(" ", len(word)), 1)
			} else {
				line = strings.Repeat(" ", len(line))
			}
		case strings.HasPrefix(trimmed, "#"):
			line = strings.Repeat(" ", len(line))
		default:
			if m := heredocOpen.FindStringSubmatch(line); m != nil {
				terminator = m[1]
			}
		}
		b.WriteString(line)
	}
	return b.String(), starts
}

// lineOf returns the 1-based line of an offset of a blankedScript text.
func lineOf(starts []int, offset int) int {
	return sort.Search(len(starts), func(i int) bool { return starts[i] > offset })
}

// quotedSpan is a quoted string of a text: the offsets of its two quotes.
type quotedSpan struct{ open, close int }

// quotedSpans returns the outermost quoted strings of a text.
func quotedSpans(text string) []quotedSpan {
	var out []quotedSpan
	var q quoteScanner
	open := -1
	for i := 0; i < len(text); {
		before := q.quote
		n := q.step(text, i)
		if n == 0 {
			i++
			continue
		}
		switch {
		case before == 0 && q.quote != 0:
			open = i
		case before != 0 && q.quote == 0:
			out = append(out, quotedSpan{open: open, close: i})
		}
		i += n
	}
	return out
}

var (
	remoteRunner  = regexp.MustCompile(`^(?:ssh|ssh_\w+|\w+_ssh\w*|\w*remote\w*)$`)
	cShellBefore  = regexp.MustCompile(`(?:^|[\s;&|(])(?:bash|sh)\s+(?:-[a-z]+\s+)*-c\s*$`)
	blockKeywords = map[string]bool{"then": true, "else": true, "elif": true, "fi": true, "do": true, "done": true, "esac": true, "{": true, "}": true, ";;": true}
)

// invokedCommand returns the command whose argument starts where prefix
// ends: the command word of the last command of prefix, inside a $( too.
func invokedCommand(prefix string) string {
	segs := segments(prefix)
	last := segs[len(segs)-1].text
	if i := strings.LastIndex(last, "$("); i >= 0 {
		last = last[i+2:]
	}
	return commandWord(last)
}

// checkRemoteScriptErrexit reports a quoted multi-line argument of ssh, of a
// wrapper of it or of bash -c holding two or more independent commands and
// no set -e.
func checkRemoteScriptErrexit(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	text, starts := blankedScript(src.ctx.Lines)
	var out []*core.Violation
	for _, sp := range quotedSpans(text) {
		lineStart := strings.LastIndexByte(text[:sp.open], '\n') + 1
		prefix := text[lineStart:sp.open]
		runner := invokedCommand(prefix)
		if !cShellBefore.MatchString(prefix) && !remoteRunner.MatchString(runner) {
			continue
		}
		open, body := sp.open, text[sp.open+1:sp.close]
		if text[sp.open] == '"' {
			body = unescapeDoubleQuoted(body)
		}
		// ssh host 'sudo bash -c "..."': the script is the inner string.
		if inner := innerCScript(body); inner != nil {
			open, body = sp.open+1+inner.open, body[inner.open+1:inner.close]
		}
		if !strings.Contains(strings.TrimSpace(body), "\n") || !independentCommands(body) {
			continue
		}
		if cShellBefore.MatchString(prefix) {
			runner = "bash -c"
		}
		out = appendReport(out, src.report(r, lineOf(starts, open),
			"The multi-line script passed to "+runner+" has no set -e — a failed line does not stop the next ones, and the caller sees the status of the last line only",
			"Start the script with set -e (set -euo pipefail), or join the steps with &&"))
	}
	return out
}

// unescapeDoubleQuoted returns the text a double-quoted string stands for,
// each escape padded with a blank so that offsets keep their place: \" is a
// quote of the inner script, not one of the string.
func unescapeDoubleQuoted(text string) string {
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] == '\\' && i+1 < len(text) && strings.IndexByte("\"\\$`", text[i+1]) >= 0 {
			b.WriteByte(' ')
			b.WriteByte(text[i+1])
			i++
			continue
		}
		b.WriteByte(text[i])
	}
	return b.String()
}

// innerCScript returns the script string of a body that is one bash -c
// call: its first quoted string follows bash -c, with no command before.
func innerCScript(body string) *quotedSpan {
	spans := quotedSpans(body)
	if len(spans) == 0 {
		return nil
	}
	sp := spans[0]
	before := body[:sp.open]
	if !cShellBefore.MatchString(before) || strings.Contains(strings.TrimSpace(before), "\n") {
		return nil
	}
	return &sp
}

// independentCommands reports a script of two or more commands not joined by
// && or || and not starting with set -e.
func independentCommands(body string) bool {
	count, joined := 0, false
	for _, seg := range segments(body) {
		text := seg.trimmed()
		if text == "" {
			continue
		}
		if errexitSetting.MatchString(text) {
			return false
		}
		if !joined && !blockKeywords[firstShellWord(text)] {
			count++
		}
		joined = seg.sep == "&&" || seg.sep == "||"
	}
	return count >= 2
}

var (
	fallbackEchoLiteral = regexp.MustCompile(`\|\|\s*echo\s+("[^"$` + "`" + `]*"|'[^']*'|[A-Za-z0-9_.:-]+)\s*"?\)`)
	// answerPrinter is a command that prints its answer also when it exits
	// non-zero: a count of zero, an inactive state, the 000 of a failed
	// request, a false or null value.
	answerPrinter = regexp.MustCompile(`\bgrep\s+(?:-\S+\s+)*-[A-Za-z]*c[A-Za-z]*\b|\bgrep\b[^|]*--count\b|\bsystemctl\s+(?:--\S+\s+)*is-(?:active|enabled|failed)\b|(?:\s-w|--write-out)\s*['"]?[^'"]*%\{(?:http_code|response_code)\}|\bjq\s+(?:-\S+\s+)*(?:-[A-Za-z]*e[A-Za-z]*|--exit-status)\b`)
	quietGrep     = regexp.MustCompile(`\bgrep\s+(?:-\S+\s+)*-[A-Za-z]*q`)
)

// checkFallbackEchoDuplicates reports $(cmd || echo LITERAL) where cmd ends
// in a command that prints its answer when it fails.
func checkFallbackEchoDuplicates(r *shellRule, src *shellSource) []*core.Violation {
	pipefail := !src.make && scriptSetsPipefail(src)
	var out []*core.Violation
	for _, l := range src.lines {
		for _, m := range fallbackEchoLiteral.FindAllStringSubmatchIndex(l.text, -1) {
			if strings.Trim(l.text[m[2]:m[3]], `"'`) == "" {
				continue // an empty echo leaves nothing after the capture
			}
			left := captureBefore(l.text, m[0])
			if left == "" || !printsOnFailure(left, pipefail) {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(m[0]),
				"The command prints its answer also when it exits non-zero, and || echo adds a second line — the captured value is two lines and matches neither",
				"Assign the fallback outside the capture: x=$(cmd) || x=LITERAL, or drop the echo when the command always prints"))
		}
	}
	return out
}

// captureBefore returns the command of the $( that encloses offset, from
// its last && or ; up to offset; "" outside a capture.
func captureBefore(text string, offset int) string {
	depth := 0
	for i := offset - 1; i > 0; i-- {
		switch text[i] {
		case ')':
			depth++
		case '(':
			if depth > 0 {
				depth--
				continue
			}
			if text[i-1] != '$' {
				return ""
			}
			left := text[i+1 : offset]
			for _, sep := range []string{"&&", ";", "||"} {
				if j := strings.LastIndex(left, sep); j >= 0 {
					left = left[j+len(sep):]
				}
			}
			return left
		}
	}
	return ""
}

// printsOnFailure reports a command (a pipeline) whose status is that of an
// answer printer: its last element, or any element under pipefail.
func printsOnFailure(command string, pipefail bool) bool {
	elements := pipeElements(command)
	if !pipefail {
		elements = elements[len(elements)-1:]
	}
	for _, e := range elements {
		if answerPrinter.MatchString(e) && !quietGrep.MatchString(e) {
			return true
		}
	}
	return false
}

var (
	evalVariable  = regexp.MustCompile(`^eval\s+"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?$`)
	reportedName  = regexp.MustCompile(`\b(?:echo|printf)\s+(?:-[a-z]+\s+)?["']?([A-Za-z_][A-Za-z0-9_]*)=`)
	assignmentRef = `(?:^|[\s;(])(?:(?:local|readonly|export|declare)\s+(?:-\w+\s+)?)?`
)

// checkEvalOverwrites reports eval "$VAR" where VAR captures a report of
// NAME=value lines and a NAME is also assigned by the script.
func checkEvalOverwrites(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	funcs := src.functions()
	var out []*core.Violation
	for i, l := range src.lines {
		for _, seg := range segments(l.text) {
			m := evalVariable.FindStringSubmatch(seg.trimmed())
			if m == nil {
				continue
			}
			producer := evalProducer(src, funcs, i, m[1])
			if len(producer) == 0 {
				continue
			}
			names := overwrittenNames(src.ctx.Lines, producer, m[1])
			if len(names) == 0 {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(seg.offset),
				"eval runs the report captured in $"+m[1]+", which assigns "+strings.Join(names, ", ")+" — the script's own variables of those names are overwritten",
				"Read the report into names of its own (a prefix, or read -r with a while loop over KEY=VALUE lines) instead of eval"))
		}
	}
	return out
}

// evalProducer returns the physical lines (1-based) of what fills the
// variable an eval at logical line i runs: from its last capture assignment
// to the eval (a heredoc fed to the captured command), and the body of the
// function the capture calls.
func evalProducer(src *shellSource, funcs map[string]shellFunc, i int, name string) map[int]bool {
	assign := regexp.MustCompile(assignmentRef + name + `=\$\(\s*([A-Za-z_][A-Za-z0-9_]*)?`)
	lines := make(map[int]bool)
	for j := i - 1; j >= 0; j-- {
		m := assign.FindStringSubmatch(src.lines[j].text)
		if m == nil {
			continue
		}
		for n := src.lines[j].nums[0]; n < src.lines[i].nums[0]; n++ {
			lines[n] = true
		}
		if fn, ok := funcs[m[1]]; ok {
			for n := src.lines[fn.first].nums[0]; n <= src.lines[fn.last].nums[0]; n++ {
				lines[n] = true
			}
		}
		break
	}
	return lines
}

// overwrittenNames returns the names a report printed on the producer lines
// assigns that the script also assigns elsewhere.
func overwrittenNames(lines []string, producer map[int]bool, variable string) []string {
	printed := make(map[string]bool)
	for n := range producer {
		for _, m := range reportedName.FindAllStringSubmatch(lines[n-1], -1) {
			if m[1] != variable {
				printed[m[1]] = true
			}
		}
	}
	var names []string
	for name := range printed {
		assign := regexp.MustCompile(assignmentRef + name + `=`)
		for n, line := range lines {
			if producer[n+1] {
				continue
			}
			if loc := assign.FindStringIndex(line); loc != nil && !insideQuotes(line, loc[1]-1) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	return names
}

var (
	hbaSource = regexp.MustCompile(`\bhba_file\b|pg_hba\.conf\b`)
	hbaEntry  = regexp.MustCompile(`^(?:echo|printf)\s+(?:-[a-z]+\s+)?["']?(?:local|host|hostssl|hostnossl|hostgssenc|hostnogssenc)\s`)
	hbaAppend = regexp.MustCompile(`(?:>>|\btee\s+(?:-\w+\s+)*(?:-a|--append)\s+(?:-\w+\s+)*)\s*["']?(?:\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|[^\s"';|&]*pg_hba\.conf\b)`)
)

// checkPgHbaAppend reports echo "host ..." >> the pg_hba.conf file: a path
// ending in pg_hba.conf, or a variable holding one or SHOW hba_file.
func checkPgHbaAppend(r *shellRule, src *shellSource) []*core.Violation {
	hbaVars := make(map[string]bool)
	for _, l := range src.lines {
		for _, m := range assignStart.FindAllStringSubmatchIndex(l.text, -1) {
			if hbaSource.MatchString(shellValueAt(l.text, m[1])) {
				hbaVars[l.text[m[2]:m[3]]] = true
			}
		}
	}
	var out []*core.Violation
	for _, l := range src.lines {
		for _, seg := range segments(l.text) {
			text := commandPrefix.ReplaceAllString(seg.trimmed(), "")
			if !hbaEntry.MatchString(text) {
				continue
			}
			m := hbaAppend.FindStringSubmatch(text)
			if m == nil || m[1] != "" && !hbaVars[m[1]] {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(seg.offset),
				"The rule is appended to the end of pg_hba.conf, after the catch-all rules of the default file — PostgreSQL uses the first matching line, and this one never applies",
				"Insert the rule before the first catch-all line (sed -i \"/^host.*all.*all/i <rule>\"), and reload PostgreSQL"))
		}
	}
	return out
}

var (
	certbotNginx = regexp.MustCompile(`\bcertbot\b[^\n]*\s--nginx\b`)
	certbotOnly  = regexp.MustCompile(`\bcertbot\s+(?:-\S+\s+)*(?:certonly|renew)\b`)
	ownTLS       = regexp.MustCompile(`\bssl_certificate\s`)
	nginxPath    = regexp.MustCompile(`^/etc/nginx/\S+`)
	nginxWrite   = regexp.MustCompile(`\b(?:cat\s*>|tee\s+(?:-[b-z]\w*\s+)*)\s*["']?(\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|/etc/nginx/[^\s"';|&]+)`)
)

// checkCertbotConfigOverwrite reports cat > (or tee) of an nginx file in a
// script that runs certbot --nginx in its installing mode, never tests
// whether the file exists and writes no TLS directives of its own.
func checkCertbotConfigOverwrite(r *shellRule, src *shellSource) []*core.Violation {
	if src.make || !installsWithCertbot(src.ctx.Lines) || ownTLS.MatchString(strings.Join(src.ctx.Lines, "\n")) {
		return nil
	}
	nginxVars := make(map[string]bool)
	for _, l := range src.lines {
		for _, m := range assignStart.FindAllStringSubmatchIndex(l.text, -1) {
			if nginxPath.MatchString(strings.Trim(shellValueAt(l.text, m[1]), `"'`)) {
				nginxVars[l.text[m[2]:m[3]]] = true
			}
		}
	}
	var out []*core.Violation
	for _, l := range src.lines {
		for _, m := range nginxWrite.FindAllStringSubmatchIndex(l.text, -1) {
			target := l.text[m[2]:m[3]]
			if m[4] >= 0 {
				if !nginxVars[l.text[m[4]:m[5]]] {
					continue
				}
				target = l.text[m[4]:m[5]]
			}
			if fileTested(src.ctx.Lines, target) {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(m[0]),
				"The nginx file is rewritten on every run, and certbot --nginx edits that same file in place — the next deploy drops the TLS server block certbot added",
				"Write the file only when it does not exist yet ([ -f file ] || ...), or keep the TLS directives in the template itself"))
		}
	}
	return out
}

// installsWithCertbot reports a certbot --nginx call that edits the nginx
// files: not certonly or renew.
func installsWithCertbot(lines []string) bool {
	for _, line := range lines {
		if certbotNginx.MatchString(line) && !certbotOnly.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			return true
		}
	}
	return false
}

// fileTested reports a test of whether the file (a variable name or a path)
// exists somewhere in the script.
func fileTested(lines []string, target string) bool {
	ref := regexp.QuoteMeta(target)
	if !strings.HasPrefix(target, "/") {
		ref = `\$\{?` + ref + `\b`
	}
	test := regexp.MustCompile(`-[efs]\s+["']?` + ref)
	for _, line := range lines {
		if test.MatchString(line) {
			return true
		}
	}
	return false
}

var (
	errexitOff     = regexp.MustCompile(`^set\s+\+[a-zA-Z]*e\b|^set\s+\+o\s+errexit\b`)
	plainCapture   = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=\$\((.*)\)$`)
	failingAnswer  = regexp.MustCompile(`\bsystemctl\s+(?:--\S+\s+)*is-(?:active|enabled|failed)\b|\bgrep\b|\bcurl\b[^|]*(?:\s-[A-Za-z]*f[A-Za-z]*\b|--fail\b)`)
	valueTestStart = regexp.MustCompile(`^(?:if|elif|\[\[?|test|case)\b`)
)

// checkSetEBeforeHandler reports, under set -e, VAR=$(cmd) whose cmd fails
// for the value the next lines test VAR for.
func checkSetEBeforeHandler(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	pipefail := scriptSetsPipefail(src)
	funcs := src.functions()
	var out []*core.Violation
	errexit := false
	for i, l := range src.lines {
		text := withoutComment(strings.TrimSpace(l.text))
		switch {
		case errexitSetting.MatchString(text):
			errexit = true
		case errexitOff.MatchString(text):
			errexit = false
		}
		m := plainCapture.FindStringSubmatch(text)
		if !errexit || m == nil || strings.Contains(m[2], "||") || len(segments(text)) > 1 {
			continue
		}
		if !failsOnAnswer(m[2], pipefail) || conditionalCaller(src, funcs, i) {
			continue
		}
		message := "Under set -e the capture stops the script when the command fails, and it fails for the very value the next lines test " + m[1] + " for — the handler never runs"
		switch {
		case testedNext(src.lines, i, m[1]):
		case iteratedNext(src.lines, i, m[1]):
			message = "Under set -e and pipefail the capture stops the script when grep finds nothing, though the next lines iterate over " + m[1] + " and an empty list is a valid answer"
		default:
			continue
		}
		out = appendReport(out, src.report(r, l.lineAt(0), message,
			"Keep the status from stopping the script: "+m[1]+"=$(cmd) || true, or test the command itself: if ! cmd; then ..."))
	}
	return out
}

// failsOnAnswer reports a pipeline whose status is that of a command that
// exits non-zero for a negative answer.
func failsOnAnswer(command string, pipefail bool) bool {
	elements := pipeElements(command)
	if !pipefail {
		elements = elements[len(elements)-1:]
	}
	for _, e := range elements {
		if failingAnswer.MatchString(e) {
			return true
		}
	}
	return false
}

// testedNext reports a test of $name among the three logical lines after i.
func testedNext(lines []shellLine, i int, name string) bool {
	read := regexp.MustCompile(`\$\{?` + name + `\b`)
	for j := i + 1; j < len(lines) && j <= i+3; j++ {
		text := strings.TrimSpace(lines[j].text)
		if valueTestStart.MatchString(text) && read.MatchString(text) {
			return true
		}
	}
	return false
}

// iteratedNext reports a loop over $name among the three logical lines
// after i.
func iteratedNext(lines []shellLine, i int, name string) bool {
	loop := regexp.MustCompile(`\bfor\s+\w+\s+in\s+[^;]*\$\{?` + name + `\b`)
	for j := i + 1; j < len(lines) && j <= i+3; j++ {
		if loop.MatchString(lines[j].text) {
			return true
		}
	}
	return false
}

// conditionalCaller reports a line inside a function the script calls as a
// condition: set -e is off in such a call.
func conditionalCaller(src *shellSource, funcs map[string]shellFunc, i int) bool {
	for name, fn := range funcs {
		if i < fn.first || i > fn.last {
			continue
		}
		call := regexp.MustCompile(`(?:\b(?:if|elif|while|until)\s+!?\s*|\|\|\s*|&&\s*|!\s+)` + name + `\b|\b` + name + `\b[^;|&]*(?:\|\||&&)`)
		for _, l := range src.lines {
			if call.MatchString(l.text) {
				return true
			}
		}
	}
	return false
}

// shellSourceTextRule is a shell rule that knows the text of the
// application's source files: templates, Go and front-end code.
type shellSourceTextRule struct {
	*shellRule
	sources []string
}

// appSourceExt are the extensions of files an application renders text from.
var appSourceExt = map[string]bool{".go": true, ".html": true, ".tmpl": true, ".gohtml": true, ".ts": true, ".tsx": true, ".js": true, ".jsx": true}

// UseProjectFiles records the text of the root's non-test source files.
func (r *shellSourceTextRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	for _, ctx := range files {
		if appSourceExt[path.Ext(ctx.RelPath)] && !ctx.IsTestFile() {
			r.sources = append(r.sources, string(ctx.Content))
		}
	}
}

// ResetState drops the sources.
func (r *shellSourceTextRule) ResetState() { r.sources = nil }

// contains reports a text found in a source file.
func (r *shellSourceTextRule) contains(text string, foldCase bool) bool {
	for _, source := range r.sources {
		if strings.Contains(source, text) || foldCase && strings.Contains(strings.ToLower(source), strings.ToLower(text)) {
			return true
		}
	}
	return false
}

var (
	grepLiteral   = regexp.MustCompile(`\bgrep\s+((?:-[A-Za-z]+\s+)*)(?:'([^']+)'|"([^"]+)")`)
	pipedPage     = regexp.MustCompile(`(?:\b(?:echo|printf\s+['"]%s[^'"]*['"])\s+"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?|\bcurl\b[^|]*)\s*\|\s*$`)
	hereStringVar = regexp.MustCompile(`^\s*<<<\s*"?\$\{?([A-Za-z_][A-Za-z0-9_]*)`)
	pageName      = regexp.MustCompile(`(?i)body|html|page|resp`)
	uiText        = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} .,!&'_-]*$`)
	uiLetter      = regexp.MustCompile(`\p{L}{3}`)
)

// checkSmokeGrepText reports grep 'text' over a fetched page or response
// body whose text no source file of the application contains.
func checkSmokeGrepText(r *shellSourceTextRule, src *shellSource) []*core.Violation {
	if len(r.sources) == 0 {
		return nil
	}
	pageVars := make(map[string]bool)
	for _, l := range src.lines {
		for _, m := range assignStart.FindAllStringSubmatchIndex(l.text, -1) {
			if value := shellValueAt(l.text, m[1]); strings.HasPrefix(strings.TrimLeft(value, `"`), "$(curl") {
				pageVars[l.text[m[2]:m[3]]] = true
			}
		}
	}
	var out []*core.Violation
	for _, l := range src.lines {
		for _, m := range grepLiteral.FindAllStringSubmatchIndex(l.text, -1) {
			literal := ""
			for _, g := range []int{4, 6} {
				if m[g] >= 0 {
					literal = l.text[m[g]:m[g+1]]
				}
			}
			// Text a person reads: words with a capital or a blank. A single
			// lowercase word is a marker of the tooling (a library, a class).
			if !uiText.MatchString(literal) || !uiLetter.MatchString(literal) || !strings.ContainsAny(literal, " ") && literal == strings.ToLower(literal) {
				continue
			}
			if !grepsPage(l.text[:m[0]], l.text[m[1]:], pageVars) {
				continue
			}
			if r.contains(literal, strings.Contains(l.text[m[2]:m[3]], "i")) {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(m[0]),
				"The check looks for '"+literal+"' in the page, and no template or source file of the application contains that text — the page does not show it, and the check fails on a working page",
				"Look for a text the application renders now, or for a marker that does not change with the wording (an id, a data attribute)"))
		}
	}
	return out
}

// grepsPage reports a grep whose input is a fetched page: piped from curl or
// from echo of a page variable, or a here string of one.
func grepsPage(before, after string, pageVars map[string]bool) bool {
	isPage := func(name string) bool { return pageVars[name] || pageName.MatchString(name) }
	if m := pipedPage.FindStringSubmatch(before); m != nil {
		return m[1] == "" || isPage(m[1])
	}
	if m := hereStringVar.FindStringSubmatch(after); m != nil {
		return isPage(m[1])
	}
	return false
}

// unitEnvRule is a shell rule that knows the systemd units the project's
// scripts write and the literal values of their variables.
type unitEnvRule struct {
	*shellRule
	// unitFiles holds, per script that writes unit text, its EnvironmentFile
	// paths; loaders the programs of its ExecStartPre lines.
	unitFiles [][]string
	loaders   []string
	values    map[string][]string
}

var (
	unitEnvFile  = regexp.MustCompile(`(?:^|["'\s])EnvironmentFile=-?([^\s"']+)`)
	unitPreStart = regexp.MustCompile(`(?:^|["'\s])ExecStartPre=[-+!@:]*([^\s"']+)`)
	literalValue = regexp.MustCompile(`^\s*(?:(?:export|readonly|local|declare)\s+(?:-\w+\s+)?)?([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;]+)\s*(?:#.*)?$`)
	defaultValue = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:?-([^}]*)\}$`)
	variableRef  = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
)

// UseProjectFiles indexes the units and the variables of the root's scripts.
func (r *unitEnvRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	var envLines [][]string
	for _, ctx := range files {
		if !ctx.IsShellFile() || ctx.IsTestFile() {
			continue
		}
		var envFiles []string
		for _, line := range ctx.Lines {
			if m := literalValue.FindStringSubmatch(line); m != nil {
				value := strings.Trim(m[2], `"'`)
				if d := defaultValue.FindStringSubmatch(value); d != nil {
					value = d[1]
				}
				r.values[m[1]] = append(r.values[m[1]], value)
			}
			if m := unitEnvFile.FindStringSubmatch(line); m != nil {
				envFiles = append(envFiles, m[1])
			}
			if m := unitPreStart.FindStringSubmatch(line); m != nil {
				r.loaders = append(r.loaders, m[1])
			}
		}
		if len(envFiles) > 0 {
			envLines = append(envLines, envFiles)
		}
	}
	for _, envFiles := range envLines {
		var resolved []string
		for _, f := range envFiles {
			for _, v := range r.resolve(f, 0) {
				if !slices.Contains(resolved, v) {
					resolved = append(resolved, v)
				}
			}
		}
		if len(resolved) > 1 {
			r.unitFiles = append(r.unitFiles, resolved)
		}
	}
}

// ResetState drops the index.
func (r *unitEnvRule) ResetState() {
	r.unitFiles, r.loaders, r.values = nil, nil, make(map[string][]string)
}

// resolve returns the literal values a word can stand for: the word itself
// when it holds no variable, each literal value of its variables otherwise.
func (r *unitEnvRule) resolve(word string, depth int) []string {
	word = strings.Trim(word, `"'`)
	m := variableRef.FindStringSubmatchIndex(word)
	if m == nil {
		return []string{word}
	}
	if depth > 3 {
		return nil
	}
	var out []string
	for _, value := range r.values[word[m[2]:m[3]]] {
		for _, rest := range r.resolve(word[m[1]:], depth+1) {
			for _, v := range r.resolve(value, depth+1) {
				out = append(out, word[:m[0]]+v+rest)
			}
		}
	}
	return out
}

// mentions reports a context that names one of the paths, literally or
// through a variable holding it.
func (r *unitEnvRule) mentions(context string, paths []string) bool {
	for _, p := range paths {
		if strings.Contains(context, p) {
			return true
		}
	}
	for _, m := range variableRef.FindAllStringSubmatch(context, -1) {
		for _, value := range r.values[m[1]] {
			for _, v := range r.resolve(value, 0) {
				for _, p := range paths {
					if v == p {
						return true
					}
				}
			}
		}
	}
	return false
}

var sourceCommand = regexp.MustCompile(`(?:^|[\s;'"(&|])(?:source|\.)\s+['"]?([^\s'";|&)]+)`)

// checkUnitEnvSource reports a source of a unit's EnvironmentFile in a
// command that reads none of the unit's other environment files and does
// not run its ExecStartPre loader either.
func checkUnitEnvSource(r *unitEnvRule, src *shellSource) []*core.Violation {
	if src.make || len(r.unitFiles) == 0 || src.ctx.IsTestFile() {
		return nil
	}
	raw := strings.Join(src.ctx.Lines, "\n")
	blanked, starts := blankedScript(src.ctx.Lines)
	spans := quotedSpans(blanked)
	var out []*core.Violation
	for _, m := range sourceCommand.FindAllStringSubmatchIndex(raw, -1) {
		targets := r.resolve(raw[m[2]:m[3]], 0)
		context := enclosingText(raw, spans, m[2])
		for _, unit := range r.unitFiles {
			others := missingOthers(unit, targets)
			if others == nil || r.mentions(context, others) || r.mentions(context, r.loaders) {
				continue
			}
			out = appendReport(out, src.report(r, lineOf(starts, m[2]),
				"The command sources "+raw[m[2]:m[3]]+" only, and the service unit also reads "+strings.Join(others, ", ")+" — the command runs without what the service gets from there",
				"Load the same environment as the unit (every EnvironmentFile, and what ExecStartPre provides) through one shared helper"))
			break
		}
	}
	return out
}

// missingOthers returns the unit's environment files other than the
// sourced one, nil when the source is none of them.
func missingOthers(unit, targets []string) []string {
	var others []string
	found := false
	for _, f := range unit {
		matched := false
		for _, t := range targets {
			if f == t {
				matched = true
			}
		}
		if matched {
			found = true
		} else {
			others = append(others, f)
		}
	}
	if !found {
		return nil
	}
	return others
}

// enclosingText returns the quoted string around an offset, or its line.
func enclosingText(text string, spans []quotedSpan, offset int) string {
	for _, sp := range spans {
		if sp.open < offset && offset < sp.close {
			return text[sp.open+1 : sp.close]
		}
	}
	start := strings.LastIndexByte(text[:offset], '\n') + 1
	end := strings.IndexByte(text[offset:], '\n')
	if end < 0 {
		return text[start:]
	}
	return text[start : offset+end]
}

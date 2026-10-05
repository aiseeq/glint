package patterns

import (
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(newShellRule("shell-and-list-failure-passes",
		"Detects a && list followed by a success message in a script under set -e — a failure before the last && does not stop the script, and the success is printed anyway",
		core.SeverityMedium, checkAndListFailurePasses))
	rules.Register(newShellRule("shell-health-check-without-wait",
		"Detects a single health request right after a container or service is started — a cold start fails it and aborts the operation that needed the service",
		core.SeverityMedium, checkHealthWithoutWait))
	rules.Register(newShellRule("make-variable-in-single-quotes",
		"Detects a free-text make variable (a body, a message, a comment) pasted inside single quotes of a recipe — an apostrophe in the value breaks the shell word",
		core.SeverityMedium, checkMakeVariableInSingleQuotes))
	rules.Register(newShellRule("shell-export-masks-substitution-status",
		"Detects export, local, declare or readonly NAME=$(command) with no check of NAME — the status is the builtin's, and a failed command leaves an empty value",
		core.SeverityMedium, checkExportMasksStatus))
	rules.Register(newShellRule("shell-payload-as-argument",
		"Detects a request body passed whole as one argument (curl --data \"$body\") or as one variable of a remote command line — a large body fails with 'Argument list too long'",
		core.SeverityMedium, checkPayloadAsArgument))
	rules.Register(newShellRule("shell-pipe-producer-stderr-discarded",
		"Detects a service call with 2>/dev/null whose output feeds a pipe — the consumer gets an empty input and the reason of the failure is thrown away",
		core.SeverityMedium, checkPipeProducerStderr))
	rules.Register(newShellRule("shell-variable-unset-under-nounset",
		"Detects, under set -u, a variable assigned only in a case arm and read after it while its siblings are initialized first — input without that key stops the script with 'unbound variable'",
		core.SeverityMedium, checkUnsetUnderNounset))
	rules.Register(newShellRule("shell-c-script-split-by-quote",
		"Detects a single quote inside bash -c '...' that closes the script early — the rest of the command becomes extra arguments of bash and never runs",
		core.SeverityHigh, checkCScriptSplit))
	rules.Register(newShellRuleIn("security", "secret-in-command-argument",
		"Detects a secret placed in a command's arguments (a token header of curl, a password in psql -c) — it is visible in ps to every user of the host while the command runs",
		core.SeverityMedium, checkSecretInArgument))
	rules.Register(newShellRuleIn("security", "generated-secret-used-before-saved",
		"Detects a generated secret applied to a database or a service before the script writes it anywhere — a run that stops in between loses it, and a rerun makes another",
		core.SeverityMedium, checkSecretUsedBeforeSaved))
}

// newShellRuleIn is newShellRule for a rule of another category.
func newShellRuleIn(category, name, description string, severity core.Severity, check func(*shellRule, *shellSource) []*core.Violation) *shellRule {
	return &shellRule{BaseRule: rules.NewBaseRule(name, category, description, severity), check: check}
}

// shellStep is one command of a script or a recipe with the physical line it
// starts on and the list operator after it.
type shellStep struct {
	text  string
	sep   string
	line  int
	block int
}

// steps returns the commands of a file in order: every segment of every
// logical line, the last one of a line ended by a newline.
func (src *shellSource) steps() []shellStep {
	var out []shellStep
	for _, l := range src.lines {
		for _, seg := range segments(l.text) {
			if seg.trimmed() == "" {
				continue
			}
			sep := seg.sep
			if sep == "" {
				sep = "\n"
			}
			out = append(out, shellStep{text: seg.trimmed(), sep: sep, line: l.lineAt(seg.offset), block: l.block})
		}
	}
	return out
}

// errexitSetting is set -e in any spelling.
var errexitSetting = regexp.MustCompile(`(?m)^\s*set\s+(?:-[a-zA-Z]*e[a-zA-Z]*\b|-o\s+errexit\b)`)

var (
	successMessage = regexp.MustCompile(`(?i)^(?:log_?(?:success|ok|done)\b|(?:echo|printf)\b.*\b(?:success|succeeded|switched|done|completed|ready|ok)\b)`)
	testCommand    = regexp.MustCompile(`^(?:\[\[?|test\b|!)`)
	blockEnd       = regexp.MustCompile(`^(?:\}|fi\b|done\b|esac\b|;;)`)
	conditionStart = regexp.MustCompile(`^(?:if|elif|while|until)\b`)
)

// checkAndListFailurePasses reports, in a script under set -e, a && list of
// commands ended by a newline or ; and followed by a success message.
func checkAndListFailurePasses(r *shellRule, src *shellSource) []*core.Violation {
	if src.make || !errexitSetting.MatchString(strings.Join(src.ctx.Lines, "\n")) {
		return nil
	}
	var out []*core.Violation
	steps := src.steps()
	for start := 0; start < len(steps); start++ {
		if start > 0 && steps[start-1].sep != "\n" && steps[start-1].sep != ";" {
			continue
		}
		end := start
		for end < len(steps) && steps[end].sep == "&&" {
			end++
		}
		if end == start || end+1 >= len(steps) || (steps[end].sep != "\n" && steps[end].sep != ";") {
			continue
		}
		first := steps[start].text
		if testCommand.MatchString(first) || conditionStart.MatchString(first) || blockEnd.MatchString(first) {
			continue
		}
		next := commandPrefix.ReplaceAllString(steps[end+1].text, "")
		if !successMessage.MatchString(next) {
			continue
		}
		out = appendReport(out, src.report(r, steps[start].line,
			"A failure of a command before the last && does not stop a script under set -e, and the success message after the list is printed anyway",
			"Run the commands as separate statements, or check the list: if ! a || ! b; then log_error ...; exit 1; fi"))
	}
	return out
}

var (
	serviceStart = regexp.MustCompile(`\b(?:docker\s+start\b|docker\s+run\b.*\s(?:-d|--detach)\b|docker[ -]compose\b.*\bup\b.*\s(?:-d|--detach)\b|systemctl\s+(?:re)?start\b|service\s+\S+\s+(?:re)?start\b)`)
	healthCurl   = regexp.MustCompile(`\bcurl\b.*/(?:api/)?(?:health|healthz|ready|readyz|livez|ping)\b`)
	curlFails    = regexp.MustCompile(`\s(?:-[a-zA-Z]*f[a-zA-Z]*|--fail)\b`)
	waitStep     = regexp.MustCompile(`^(?:sleep|wait|timeout)\b|\buntil\b`)
)

// checkHealthWithoutWait reports a curl of a health endpoint, used as a
// gate, within a few commands after a container or a service starts, with
// no loop, retry or sleep between.
func checkHealthWithoutWait(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	steps := src.steps()
	depth, started, block := 0, -1, -1
	for i, s := range steps {
		if s.block != block {
			block, started, depth = s.block, -1, 0
		}
		t := strings.TrimSpace(strings.TrimPrefix(s.text, "do "))
		switch {
		case loopStart.MatchString(t):
			depth++
			started = -1
			continue
		case loopEnd.MatchString(t):
			depth--
			continue
		case waitStep.MatchString(t):
			started = -1
			continue
		case serviceStart.MatchString(t):
			started = i
			continue
		}
		if started < 0 || depth > 0 || i-started > 8 || !healthCurl.MatchString(t) || strings.Contains(t, "--retry") {
			continue
		}
		gate := curlFails.MatchString(t) || conditionStart.MatchString(t) || strings.HasPrefix(t, "!") || s.sep == "||" || s.sep == "&&"
		if !gate {
			continue
		}
		started = -1
		out = appendReport(out, src.report(r, s.line,
			"A single health request right after the service starts — a cold start fails it and aborts the operation",
			"Poll the endpoint with a bound (for i in $(seq 1 30); do curl -fs ... && break; sleep 2; done) and fail after the loop, or use curl --retry"))
	}
	return out
}

var (
	makeVariableRef = regexp.MustCompile(`\$[({]([A-Z][A-Z0-9_]*)[)}]`)
	// makeFixedValue is NAME := text the makefile sets itself, with no quote
	// and no reference a caller could fill.
	makeFixedValue = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)\s*(?::{0,2}=)\s*[^'"$]*$`)
	freeTextName   = regexp.MustCompile(`(?:^|_)(?:BODY|MESSAGE|MSG|COMMENT|TEXT|NOTE|REASON|DESCRIPTION|TITLE|JSON|PAYLOAD|SQL)(?:_|$)`)
)

// checkMakeVariableInSingleQuotes reports $(NAME) of a free-text make
// variable inside single quotes of a recipe line.
func checkMakeVariableInSingleQuotes(r *shellRule, src *shellSource) []*core.Violation {
	if !src.make {
		return nil
	}
	fixed := make(map[string]bool)
	for _, line := range src.ctx.Lines {
		if m := makeFixedValue.FindStringSubmatch(line); m != nil {
			fixed[m[1]] = true
		}
	}
	var out []*core.Violation
	for _, l := range src.lines {
		for _, m := range makeVariableRef.FindAllStringSubmatchIndex(l.text, -1) {
			name := l.text[m[2]:m[3]]
			if !freeTextName.MatchString(name) || fixed[name] || !insideSingleQuotes(l.text, m[0]) {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(m[0]),
				"$("+name+") is pasted inside single quotes — an apostrophe in the value closes the quote and breaks or changes the command",
				"Pass the value through the environment (export "+name+"_ENV = $("+name+")) and read \"$$"+name+"_ENV\" in double quotes"))
		}
	}
	return out
}

var (
	builtinCapture = regexp.MustCompile(`^(export|local|declare(?:\s+-\w+)*|readonly|typeset)\s+([A-Za-z_][A-Za-z0-9_]*)="?\$\(\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*([^\s)"]+)`)
	// trivialCommands rarely fail in a way the script must handle.
	trivialCommands = wordSet("date", "dirname", "basename", "pwd", "cd", "printf", "echo", "cat", "realpath", "readlink",
		"mktemp", "id", "whoami", "hostname", "uname", "tput", "nproc", "seq", "wc", "tr", "sed", "awk", "cut", "head",
		"tail", "sort", "uniq", "grep", "jq", "git", "ls", "find", "expr", "command", "type", "which", "stat", "du", "df")
)

// checkExportMasksStatus reports NAME=$(command) behind a builtin when the
// command can fail and nothing checks NAME after it. An exported value goes
// to the children, so it counts as used; a local one must be read.
func checkExportMasksStatus(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	funcs := src.functions()
	for _, unit := range src.units() {
		for _, seg := range segments(unit.text) {
			m := builtinCapture.FindStringSubmatch(commandPrefix.ReplaceAllString(seg.trimmed(), ""))
			if m == nil {
				continue
			}
			name, command := m[2], m[3]
			if trivialCommands[command] {
				continue
			}
			_, ownFunction := funcs[command]
			if !remoteCommands[command] && !ownFunction && !strings.Contains(command, "/") && !runtimeCommand.MatchString(command) {
				continue
			}
			// A capture with its own fallback decides on a failure itself; one
			// ending in a filter has the filter's status, not the command's.
			capture := strings.TrimSuffix(strings.TrimPrefix(captureText(seg.trimmed()), "$("), ")")
			if strings.Contains(capture, "||") {
				continue
			}
			if elements := pipeElements(capture); len(elements) > 1 && trivialCommands[commandWord(elements[len(elements)-1])] {
				continue
			}
			rest := unit.text[seg.offset+len(seg.text):]
			if valueChecked(rest, name) || (m[1] != "export" && !valueUsed(rest, name)) {
				continue
			}
			out = appendReport(out, src.report(r, unit.lineAt(seg.offset),
				m[1]+" "+name+"=$("+command+" ...) returns the status of "+m[1]+" — a failed "+command+" goes on with an empty "+name,
				"Declare and assign apart (local "+name+"; "+name+"=$(...) || exit 1), or check it: [ -n \"$"+name+"\" ] || exit 1"))
		}
	}
	return out
}

// runtimeCommand runs a program whose failure is the script's concern.
var runtimeCommand = regexp.MustCompile(`^(?:python3?|node|go|ruby|perl|php|java|npx|npm|yarn|pnpm|make|docker|terraform|openssl|gpg|vault|op)$`)

// valueChecked reports a test of NAME in the text: [ -z "$NAME" ], -n,
// ${NAME:?}, a comparison, a read in a condition.
func valueChecked(text, name string) bool {
	ref := `"?\$\{?` + name + `\b\}?"?`
	return regexp.MustCompile(`-[zn]\s+` + ref + `|\$\{` + name + `:?\?` +
		`|` + ref + `\s*(?:==?|!=|=~|-eq|-ne|-gt|-lt|-ge|-le)\s` +
		`|\s(?:==?|!=|-eq|-ne|-gt|-lt|-ge|-le)\s*` + ref +
		`|(?m)^\s*(?:if|elif|while|until|case)\b[^\n]*\$\{?` + name + `\b`).MatchString(text)
}

// shownOnly matches a line that only shows a value inside a message.
var shownOnly = regexp.MustCompile(`^(?:log\w*|info|warn\w*|error)\b|^(?:echo|printf)\b[^"]*"[^"$]*[\p{L}][^"$]*\$`)

// valueUsed reports a read of NAME in the text other than inside a message.
func valueUsed(text, name string) bool {
	read := regexp.MustCompile(`\$\{?` + name + `\b`)
	for _, line := range strings.Split(text, "\n") {
		if read.MatchString(line) && !shownOnly.MatchString(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}

// captureText returns the text of the first $( ... ) of a command.
func captureText(command string) string {
	start := strings.Index(command, "$(")
	if start < 0 {
		return ""
	}
	return shellValueAt(command, start)
}

var (
	curlDataVariable = regexp.MustCompile(`(?:--data(?:-binary|-raw|-urlencode)?|\s-d)\s+"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?(?:\s|\)|$)`)
	remoteVariable   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*='\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?'`)
	assignStart      = regexp.MustCompile(`(?:^|[\s;(])([A-Za-z_][A-Za-z0-9_]*)=`)
	positionalValue  = regexp.MustCompile(`^"?\$\{?[0-9@]`)
	forwardedCapture = regexp.MustCompile(`\bbase64\s+(?:-d|--decode)\b|\$\(\s*cat\s*-?\s*\)|\b(?:curl|wget|ssh)\b`)
	encodedCapture   = regexp.MustCompile(`\bbase64\b`)
	curlWord         = regexp.MustCompile(`\bcurl\b`)
)

// checkPayloadAsArgument reports curl --data "$V" where V holds forwarded
// data (a function's argument, decoded input, another call's output), and a
// remote command line carrying V='$encoded' where V holds base64 of a body.
func checkPayloadAsArgument(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	forwarded, encoded := payloadVariables(src)
	var out []*core.Violation
	for _, s := range src.steps() {
		if m := curlDataVariable.FindStringSubmatchIndex(s.text); m != nil && forwarded[s.text[m[2]:m[3]]] && (curlWord.MatchString(s.text[:m[0]]) || curlArgsHolder.MatchString(s.text)) {
			name := s.text[m[2]:m[3]]
			out = appendReport(out, src.report(r, s.line,
				"The body $"+name+" is passed to curl as one argument — a body over the per-argument limit (128 KB) fails with 'Argument list too long'",
				"Write the body to a file and pass --data-binary @file, or pipe it: printf '%s' \"$body\" | curl --data-binary @- ..."))
			continue
		}
		if !strings.HasPrefix(commandPrefix.ReplaceAllString(s.text, ""), "ssh ") {
			continue
		}
		for _, m := range remoteVariable.FindAllStringSubmatch(s.text, -1) {
			if encoded[m[1]] {
				out = appendReport(out, src.report(r, s.line,
					"The encoded body $"+m[1]+" travels on the remote command line — a large body exceeds the argument limit there",
					"Send the body on the remote command's stdin (ssh host 'cmd' < file) instead of the command line"))
				break
			}
		}
	}
	return out
}

// payloadVariables returns the variables of a script holding forwarded data
// and those holding base64 of something.
func payloadVariables(src *shellSource) (forwarded, encoded map[string]bool) {
	forwarded, encoded = make(map[string]bool), make(map[string]bool)
	funcs := src.functions()
	for _, s := range src.steps() {
		for _, m := range assignStart.FindAllStringSubmatchIndex(s.text, -1) {
			name := s.text[m[2]:m[3]]
			value := shellValueAt(s.text, m[1])
			switch {
			case positionalValue.MatchString(value):
				forwarded[name] = true
			case strings.HasPrefix(strings.TrimPrefix(value, `"`), "$("):
				if forwardedCapture.MatchString(value) && !strings.Contains(value, "base64 -w") || callsOwnFunction(value, funcs) {
					forwarded[name] = true
				}
				if encodedCapture.MatchString(value) && !strings.Contains(value, "-d") && !strings.Contains(value, "--decode") {
					encoded[name] = true
				}
			}
		}
	}
	return forwarded, encoded
}

// callsOwnFunction reports a capture $(fn ...) of a function of the script.
func callsOwnFunction(value string, funcs map[string]shellFunc) bool {
	m := captureCall.FindStringSubmatch(value)
	if m == nil {
		return false
	}
	_, ok := funcs[m[1]]
	return ok
}

// shellValueAt returns the shell word starting at offset: a quoted string,
// a balanced $(...) or the text up to a blank.
func shellValueAt(text string, offset int) string {
	var q quoteScanner
	depth := 0
	i := offset
	for i < len(text) {
		if n := q.step(text, i); n > 0 {
			i += n
			continue
		}
		switch c := text[i]; {
		case c == '(':
			depth++
		case c == ')':
			if depth == 0 {
				return text[offset:i]
			}
			depth--
		case (c == ' ' || c == '\t' || c == ';') && depth == 0:
			return text[offset:i]
		}
		i++
	}
	return text[offset:]
}

var devNullStderr = regexp.MustCompile(`(?:^|\s)2>\s*/dev/null\b`)

// checkPipeProducerStderr reports a service call (or make) with 2>/dev/null
// that is the first command of a pipeline, directly or as the output of a
// function the pipeline starts with.
func checkPipeProducerStderr(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	funcs := src.functions()
	piped := make(map[string]bool)
	for _, s := range src.steps() {
		elements := pipeElements(s.text)
		// A pipeline tested by a condition or followed by a fallback has its
		// failure handled where it is used.
		if len(elements) < 2 || s.sep == "||" || conditionStart.MatchString(s.text) || strings.HasPrefix(s.text, "!") {
			continue
		}
		head := commandWord(elements[0])
		if _, ok := funcs[head]; ok {
			piped[head] = true
			continue
		}
		if quietServiceCall(elements[0]) {
			out = appendReport(out, src.report(r, s.line,
				head+" feeds a pipe with its stderr thrown away — on failure the consumer reads an empty input and the reason is lost",
				"Keep stderr (drop 2>/dev/null), or capture the output, check the status and fail with the error before parsing"))
		}
	}
	for name := range piped {
		for _, l := range src.body(funcs[name]) {
			for _, seg := range segments(l.text) {
				text := seg.trimmed()
				if strings.Contains(text, "|") || strings.Contains(text, "$(") || !quietServiceCall(text) {
					continue
				}
				out = appendReport(out, src.report(r, l.lineAt(seg.offset),
					name+" answers a pipe with the output of "+commandWord(text)+" and throws its stderr away — on failure the consumer reads an empty input and the reason is lost",
					"Keep stderr (drop 2>/dev/null), or capture the output, check the status and fail with the error before parsing"))
			}
		}
	}
	return out
}

// quietServiceCall reports a call of a service or of make with stderr sent
// to /dev/null and stdout left to the caller.
func quietServiceCall(command string) bool {
	word := commandWord(command)
	if !remoteCommands[word] && word != "make" {
		return false
	}
	loc := devNullStderr.FindStringIndex(command)
	return loc != nil && !insideQuotes(command, loc[0]+1) && !fileRedirect.MatchString(devNullStderr.ReplaceAllString(command, " "))
}

var sudoPrefix = regexp.MustCompile(`^sudo\s+(?:-[ugCDhpRrT]\s+\S+\s+|-\S+\s+)*`)

var envPrefix = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)\s+)+`)

// commandWord returns the command a step runs, after if/!/then and
// environment assignments.
func commandWord(command string) string {
	command = commandPrefix.ReplaceAllString(strings.TrimSpace(command), "")
	command = envPrefix.ReplaceAllString(command, "")
	command = sudoPrefix.ReplaceAllString(command, "")
	word, _, _ := strings.Cut(strings.TrimSpace(command), " ")
	return strings.Trim(word, "({")
}

// pipeElements splits a command at its unquoted pipes outside groups and
// substitutions.
func pipeElements(text string) []string {
	var out []string
	var q quoteScanner
	depth, start := 0, 0
	for i := 0; i < len(text); {
		if n := q.step(text, i); n > 0 {
			i += n
			continue
		}
		switch c := text[i]; {
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '|' && depth == 0:
			if i+1 < len(text) && text[i+1] == '|' {
				i += 2
				continue
			}
			if i > 0 && text[i-1] == '>' {
				break
			}
			out = append(out, strings.TrimSpace(text[start:i]))
			start = i + 1
		}
		i++
	}
	return append(out, strings.TrimSpace(text[start:]))
}

var (
	nounsetSetting = regexp.MustCompile(`(?m)^\s*set\s+(?:-[a-zA-Z]*u[a-zA-Z]*\b|-o\s+nounset\b)`)
	caseStart      = regexp.MustCompile(`^case\b.*\bin$`)
	caseArmAssign  = regexp.MustCompile(`\)\s*([a-z_][a-z0-9_]*)=`)
)

// checkUnsetUnderNounset reports, under set -u, a plain read of a variable
// that a case statement assigns only in one of its arms while two or more of
// the arms' variables are initialized before the case.
func checkUnsetUnderNounset(r *shellRule, src *shellSource) []*core.Violation {
	if src.make || !nounsetSetting.MatchString(strings.Join(src.ctx.Lines, "\n")) {
		return nil
	}
	var out []*core.Violation
	initialized := make(map[string]bool)
	for i, l := range src.lines {
		text := strings.TrimSpace(l.text)
		if caseStart.MatchString(text) {
			out = append(out, unsetAfterCase(r, src, i, initialized)...)
		}
		for _, m := range anyLineAssign.FindAllStringSubmatch(text, -1) {
			initialized[m[1]] = true
		}
	}
	return out
}

// anyLineAssign is every NAME= of a line: a=0 b="" sets both.
var anyLineAssign = regexp.MustCompile(`(?:^|[\s;(])([a-z_][a-z0-9_]*)=`)

// unsetAfterCase checks the case statement starting at line i: the arms'
// variables left out of the initialization their siblings got before it.
func unsetAfterCase(r *shellRule, src *shellSource, i int, initialized map[string]bool) []*core.Violation {
	var armVars []string
	depth, end := 1, i+1
	for ; end < len(src.lines); end++ {
		text := strings.TrimSpace(src.lines[end].text)
		if caseStart.MatchString(text) {
			depth++
		}
		if strings.HasPrefix(text, "esac") {
			if depth--; depth == 0 {
				break
			}
		}
		if depth == 1 {
			for _, m := range caseArmAssign.FindAllStringSubmatch(text, -1) {
				armVars = append(armVars, m[1])
			}
		}
	}
	known := 0
	for _, name := range armVars {
		if initialized[name] {
			known++
		}
	}
	if known < 2 || end >= len(src.lines) {
		return nil
	}
	var out []*core.Violation
	reported := make(map[int]bool)
	for _, name := range armVars {
		if initialized[name] {
			continue
		}
		if line := plainRead(src.lines[end:], name); line > 0 && !reported[line] {
			reported[line] = true
			out = appendReport(out, src.report(r, line,
				"$"+name+" is assigned only in a case arm, unlike its siblings initialized above — under set -u input without that key stops the script with 'unbound variable'",
				"Initialize "+name+"=\"\" with the other variables before the loop, or read it as ${"+name+":-}"))
		}
	}
	return out
}

// plainRead returns the line of the first $name or ${name} read without a
// default in the lines, 0 when there is none.
func plainRead(lines []shellLine, name string) int {
	read := regexp.MustCompile(`\$(?:` + name + `\b|\{` + name + `\})`)
	for _, l := range lines {
		if loc := read.FindStringIndex(l.text); loc != nil && !insideSingleQuotes(l.text, loc[0]) {
			return l.lineAt(loc[0])
		}
	}
	return 0
}

var cScriptStart = regexp.MustCompile(`(?:^|[\s;&|(])(?:bash|sh)\s+-c\s+'`)

// checkCScriptSplit reports bash -c '...' whose first shell word ends in
// unquoted text: a quote inside the script closed it, and what follows the
// blank becomes arguments of bash.
func checkCScriptSplit(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		for _, loc := range cScriptStart.FindAllStringIndex(l.text, -1) {
			quote := loc[1] - 1
			if insideQuotes(l.text, quote) {
				continue
			}
			end, unquotedTail := shellWordEnd(l.text, quote)
			if !unquotedTail || strings.TrimSpace(l.text[end:]) == "" {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(loc[0]),
				"A single quote inside bash -c '...' closes the script early — the rest of the command becomes arguments of bash and never runs",
				"Use double quotes inside the script, or write a quote as '\\'' (or '\"'\"')"))
		}
	}
	return append(out, checkCScriptWrappers(r, src)...)
}

// argsInCScript is '$*', '$@' or '$1' pasted into the quotes of a bash -c.
var argsInCScript = regexp.MustCompile(`(?:bash|sh)\s+-c\s+'\$(?:\*|@|\{?1\}?)'`)

// checkCScriptWrappers reports a function that pastes its arguments into the
// single quotes of a bash -c inside a double-quoted command line
//
//	remote_sudo() { remote "sudo bash -c '$*'"; }
//	remote_sudo "grep DSN $ENV | sed 's/x/y/'"
//
// when a caller of it passes a single quote: the quotes come from the
// caller's text, and its first ' closes the script on the far side.
func checkCScriptWrappers(r *shellRule, src *shellSource) []*core.Violation {
	funcs := src.functions()
	names := make([]string, 0, len(funcs))
	for name := range funcs {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []*core.Violation
	for _, name := range names {
		pasted := 0
		for _, l := range src.body(funcs[name]) {
			if loc := argsInCScript.FindStringIndex(l.text); loc != nil && quoteAt(l.text, loc[0]) == '"' {
				pasted = l.lineAt(loc[0])
				break
			}
		}
		if pasted == 0 {
			continue
		}
		for _, l := range src.lines {
			if callsWithQuote(l.text, name) {
				out = appendReport(out, src.report(r, pasted,
					name+" pastes its arguments into bash -c '...', and a caller passes a single quote — the quote closes the script early and the rest runs as arguments of bash",
					"Quote the arguments with printf '%q', or pass the script on stdin (bash -s)"))
				break
			}
		}
	}
	return out
}

// callsWithQuote reports a call of the function whose double-quoted argument
// holds a single quote.
func callsWithQuote(line, name string) bool {
	for at := strings.Index(line, name+" "); at >= 0; {
		before := strings.TrimRight(line[:at], " \t")
		if before == "" || strings.HasSuffix(before, "$(") || strings.HasSuffix(before, ";") || strings.HasSuffix(before, "&&") {
			rest := strings.TrimSpace(line[at+len(name):])
			if strings.HasPrefix(rest, `"`) && strings.Contains(rest, "'") {
				return true
			}
		}
		next := strings.Index(line[at+1:], name+" ")
		if next < 0 {
			break
		}
		at += next + 1
	}
	return false
}

// shellWordEnd returns where the shell word starting at offset ends and
// whether its last part is unquoted text.
func shellWordEnd(text string, offset int) (int, bool) {
	unquoted := false
	for i := offset; i < len(text); {
		switch c := text[i]; c {
		case '\'':
			close := strings.IndexByte(text[i+1:], '\'')
			if close < 0 {
				return len(text), false
			}
			i += close + 2
			unquoted = false
		case '"':
			j := i + 1
			for j < len(text) && text[j] != '"' {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			i = j + 1
			unquoted = false
		case '\\':
			i += 2
			unquoted = false
		case ' ', '\t', '\n', ';', '|', '&', '>', '<':
			return i, unquoted
		default:
			i++
			unquoted = true
		}
	}
	return len(text), unquoted
}

var (
	secretHeader   = regexp.MustCompile(`-H\s+"([^"@][^"]*)"`)
	headerSecret   = regexp.MustCompile(`(?i)^\s*(?:authorization|cookie|x-api-key|api-key|x-auth-token|x-access-token|[\w-]*token)\s*:`)
	headerVariable = regexp.MustCompile(`\$\{?\(?([A-Za-z_][A-Za-z0-9_]*)`)
	shellSecretVar = regexp.MustCompile(`(?i)(?:^|_)(?:password|passwd|pass|secret|token|jwt|apikey|api_key|private_key|access_key)(?:_|$)`)
	notSecretVar   = regexp.MustCompile(`(?i)_(?:file|path|dir|name|id|len|length|url|header|env|var)$`)
	sqlPassword    = regexp.MustCompile(`(?i)\bPASSWORD\s+'?\$\{?\(?([A-Za-z_][A-Za-z0-9_]*)`)
	curlArgsHolder = regexp.MustCompile(`^(?:local\s+|declare\s+(?:-\w+\s+)*)?[A-Za-z_]*(?:curl|args|headers|opts)[A-Za-z_]*\+?=\(`)
	secretIDVar    = regexp.MustCompile(`(?i)(?:^|_)secret_id$`)
	interpreterRun = regexp.MustCompile(`(?:^|[\s(;|&])(?:python[0-9.]*|node|perl|ruby|php)\s`)
	shellVarRef    = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)`)
	curlDataArg    = regexp.MustCompile(`\s(?:-d|--data(?:-binary|-raw|-urlencode)?)(?:\s+|=)("(?:[^"\\]|\\.)*"|[^\s"']+)`)
)

// secretVarName reports a variable name that holds a secret: a secret word
// in it and no suffix naming a file, a path or another non-secret about it.
// SECRET_ID is the secret half of an AppRole pair, not an id of a secret.
func secretVarName(name string) bool {
	return shellSecretVar.MatchString(name) && (!notSecretVar.MatchString(name) || secretIDVar.MatchString(name))
}

// interpreterSecretArg returns a secret variable passed as an argument to an
// interpreter (python3 -c '...' "$secret", node sign.js --key "$KEY") in the
// command: its argv is in ps for every user of the host. Variables in the
// environment prefix and in single-quoted code are not arguments.
func interpreterSecretArg(text string) string {
	loc := interpreterRun.FindStringIndex(text)
	if loc == nil || insideQuotes(text, loc[0]) {
		return ""
	}
	end := len(text)
	var q quoteScanner
	for i := loc[1]; i < len(text); {
		if n := q.step(text, i); n > 0 {
			i += n
			continue
		}
		if strings.IndexByte("|;&)", text[i]) >= 0 {
			end = i
			break
		}
		i++
	}
	for _, m := range shellVarRef.FindAllStringSubmatchIndex(text[:end], -1) {
		if m[0] >= loc[1] && !insideSingleQuotes(text, m[0]) && secretVarName(text[m[2]:m[3]]) {
			return text[m[2]:m[3]]
		}
	}
	return ""
}

// checkSecretInArgument reports a secret in a token header of curl (in the
// command or in an argument array) and a password in psql -c or mysql -c.
func checkSecretInArgument(r *shellRule, src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, s := range src.steps() {
		text := commandPrefix.ReplaceAllString(s.text, "")
		word := commandWord(text)
		if word == "echo" || word == "printf" {
			continue
		}
		if strings.Contains(text, "curl") || curlArgsHolder.MatchString(text) {
			for _, h := range secretHeader.FindAllStringSubmatch(text, -1) {
				v := headerVariable.FindStringSubmatch(h[1])
				// A token header is a secret whatever its variable is called.
				if v == nil || (!headerSecret.MatchString(h[1]) && !secretVarName(v[1])) {
					continue
				}
				out = appendReport(out, src.report(r, s.line,
					"$"+v[1]+" goes into a curl header on the command line — the secret is visible in ps to every user of the host",
					"Write the header to a 0600 file and pass -H @file, or give curl a --config file"))
				break
			}
			for _, d := range curlDataArg.FindAllStringSubmatch(text, -1) {
				if strings.HasPrefix(strings.TrimPrefix(d[1], `"`), "@") {
					continue
				}
				if v := secretInRefs(d[1]); v != "" {
					out = appendReport(out, src.report(r, s.line,
						"$"+v+" goes into a curl request body on the command line — the secret is visible in ps to every user of the host",
						"Feed the body on stdin (--data-binary @-) or from a 0600 file (--data-binary @file)"))
					break
				}
			}
		}
		if v := interpreterSecretArg(text); v != "" {
			out = appendReport(out, src.report(r, s.line,
				"$"+v+" is passed to an interpreter as an argument — the secret is visible in ps to every user of the host",
				"Pass it through the environment (NAME=\"$value\" python3 ...) or on stdin"))
		}
		if (word == "psql" || word == "mysql" || strings.Contains(text, " psql ")) && strings.Contains(text, "-c") {
			if m := sqlPassword.FindStringSubmatch(text); m != nil {
				out = appendReport(out, src.report(r, s.line,
					"The password $"+m[1]+" is part of the SQL in the command line — it is visible in ps and lands in the server log",
					"Feed the statement on stdin (a heredoc) so it never appears among the arguments"))
			}
		}
	}
	return out
}

// secretInRefs returns the first secret variable a shell word expands.
func secretInRefs(word string) string {
	for _, m := range shellVarRef.FindAllStringSubmatch(word, -1) {
		if secretVarName(m[1]) {
			return m[1]
		}
	}
	return ""
}

var (
	generatedSecret = regexp.MustCompile(`^(?:export\s+|local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=.*\$\(\s*(?:openssl\s+rand|head\s+-c\s*[0-9]+\s+/dev/urandom|tr\s+-dc[^)]*/dev/urandom|pwgen|uuidgen)`)
	heredocStart    = regexp.MustCompile(`<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)
	appliesSecret   = wordSet("psql", "mysql", "curl", "ssh", "docker", "kubectl", "htpasswd", "useradd", "chpasswd", "vault", "aws", "gcloud", "redis-cli", "rabbitmqctl", "mongosh")
)

// checkSecretUsedBeforeSaved reports the first command applying a generated
// secret to a service when no write of it to a file comes before.
func checkSecretUsedBeforeSaved(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	var out []*core.Violation
	lines := src.ctx.Lines
	for i, raw := range lines {
		m := generatedSecret.FindStringSubmatch(strings.TrimSpace(raw))
		if m == nil {
			continue
		}
		if line := secretUseBeforeSave(lines[i+1:], m[1]); line > 0 {
			out = appendReport(out, src.report(r, i+1+line,
				"The generated $"+m[1]+" is applied here before the script writes it anywhere — a run that stops in between loses it, and a rerun generates another",
				"Write the secret to its 0600 file first (and reuse it on a rerun), then apply it"))
		}
	}
	return out
}

// secretUseBeforeSave returns the 1-based offset in lines of the first
// command handing name to a service, 0 when a write to a file comes first.
func secretUseBeforeSave(lines []string, name string) int {
	read := regexp.MustCompile(`\$\{?` + name + `\b`)
	heredoc, heredocToFile := "", false
	for i, raw := range lines {
		text := strings.TrimSpace(raw)
		if heredoc != "" {
			if text == heredoc {
				heredoc = ""
				continue
			}
			if read.MatchString(text) {
				if heredocToFile {
					return 0
				}
				return i + 1
			}
			continue
		}
		if strings.HasPrefix(text, "#") {
			continue
		}
		if m := heredocStart.FindStringSubmatch(text); m != nil {
			heredoc, heredocToFile = m[1], fileRedirect.MatchString(heredocStart.ReplaceAllString(text, ""))
			if !heredocToFile && appliesSecret[commandWord(text)] && read.MatchString(text) {
				return i + 1
			}
			continue
		}
		if !read.MatchString(text) {
			continue
		}
		if fileRedirect.MatchString(text) || strings.Contains(text, "tee ") {
			return 0
		}
		if appliesSecret[commandWord(text)] {
			return i + 1
		}
	}
	return 0
}

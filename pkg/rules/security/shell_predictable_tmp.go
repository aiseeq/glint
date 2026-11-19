package security

import (
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/akit/shellcmd"
	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewShellPredictableTmpRule())
}

// ShellPredictableTmpRule detects a shell script that hands sudo a file at a
// predictable path under /tmp:
//
//	scp "$0" "$HOST:/tmp/diagnose.sh"
//	ssh "$HOST" "sudo bash /tmp/diagnose.sh"
//	REMOTE_TMP="/tmp/release-$$.tar.gz"
//	ssh "$HOST" "sudo mv $REMOTE_TMP /opt/app/bin/app"
//
// /tmp is writable by every user of the host. One who creates the file first,
// or a symlink in its place, gets root to run or install their content. A
// fixed name and $$ are both guessable; mktemp names are not. Uses without
// sudo, redirections (the calling shell opens them) and sudo -u <user> are
// left alone: they run with the rights of a user who owns the risk.
type ShellPredictableTmpRule struct {
	*rules.BaseRule
}

// NewShellPredictableTmpRule creates the rule
func NewShellPredictableTmpRule() *ShellPredictableTmpRule {
	return &ShellPredictableTmpRule{BaseRule: rules.NewBaseRule(
		"shell-predictable-tmp-under-sudo",
		"security",
		"Detects a shell script passing sudo a file at a predictable /tmp path (a fixed name or $$) — another user plants the file or a symlink first",
		core.SeverityHigh,
	)}
}

var (
	predictableTmpPath = regexp.MustCompile(`/tmp/[A-Za-z0-9_.${}-]+`)
	shellTmpAssignment = regexp.MustCompile(`^\s*(?:local\s+|export\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=["']?(/tmp/[A-Za-z0-9_.${}-]+)`)
	sudoCommand        = regexp.MustCompile(`(?:^|[\s;&|"'(])sudo\s+`)
	sudoOtherUser      = regexp.MustCompile(`^-u\s+(\S+)`)
	shellRedirect      = regexp.MustCompile(`\d*[<>]+&?\s*\S+`)
)

// AnalyzeFile reports sudo lines that use a predictable /tmp path.
func (r *ShellPredictableTmpRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsShellFile() {
		return nil
	}
	lines := strings.Split(string(ctx.Content), "\n")
	tmpVars := make(map[string]bool)
	for _, line := range lines {
		if m := shellTmpAssignment.FindStringSubmatch(line); m != nil {
			tmpVars[m[1]] = true
		}
	}
	calls, parsed := parseShellCalls(string(ctx.Content))
	if !parsed {
		return r.analyzeFileFallback(ctx, lines, tmpVars)
	}
	return r.analyzeCalls(ctx, lines, tmpVars, calls)
}

func parseShellCalls(text string) ([]shellcmd.Call, bool) {
	calls, err := shellcmd.Calls(text)
	return calls, err == nil
}

func (r *ShellPredictableTmpRule) analyzeCalls(
	ctx *core.FileContext,
	lines []string,
	tmpVars map[string]bool,
	calls []shellcmd.Call,
) []*core.Violation {
	var violations []*core.Violation
	reported := make(map[int]bool)
	for i := range calls {
		call := &calls[i]
		if call.Line < 1 || call.Line > len(lines) || reported[call.Line] || !runsAsRoot(call, calls) {
			continue
		}
		args := strings.Join(call.Args, " ")
		if !usesPredictableTmp(args, tmpVars) {
			continue
		}
		if ctx.IsSuppressed(call.Line, r.Name()) {
			continue
		}
		code := strings.TrimSpace(lines[call.Line-1])
		if strings.HasPrefix(code, "#") {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, call.Line, "sudo uses a file at a predictable /tmp path — another user of the host creates it, or a symlink, first and root runs their content")
		v.WithCode(code)
		v.WithSuggestion("Create the file with mktemp (remote: tmp=$(ssh host mktemp)) and pass that name")
		violations = append(violations, v)
		reported[call.Line] = true
	}
	return violations
}

func (r *ShellPredictableTmpRule) analyzeFileFallback(ctx *core.FileContext, lines []string, tmpVars map[string]bool) []*core.Violation {
	var violations []*core.Violation
	for i, line := range lines {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") {
			continue
		}
		command, ok := rootCommand(code)
		if !ok || !usesPredictableTmp(command, tmpVars) || ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, "sudo uses a file at a predictable /tmp path — another user of the host creates it, or a symlink, first and root runs their content")
		v.WithCode(code)
		v.WithSuggestion("Create the file with mktemp (remote: tmp=$(ssh host mktemp)) and pass that name")
		violations = append(violations, v)
	}
	return violations
}

// runsAsRoot reports whether a target call executes as root on the host that
// ran sudo. Calls that only launch sudo or hand a script to a context-changing
// wrapper are not target calls themselves.
func runsAsRoot(call *shellcmd.Call, calls []shellcmd.Call) bool {
	if call.Name == "sudo" || call.Name == "su" || call.Name == "runuser" || call.Name == "ssh" {
		return false
	}
	if (call.Name == "docker" || call.Name == "podman") && firstSubcommand(call.Args) == "exec" {
		return false
	}
	if call.Name == "kubectl" && hasSubcommand(call.Args, "exec") {
		return false
	}
	sudoIndex := lastVia(call.Via, "sudo")
	if sudoIndex < 0 || !sudoRunsAsRootForCall(call, calls, sudoIndex) {
		return false
	}
	return !leavesHostRoot(call, calls, sudoIndex)
}

func sudoRunsAsRootForCall(call *shellcmd.Call, calls []shellcmd.Call, viaIndex int) bool {
	if candidate := findWrappedCall(call, calls, "sudo", call.Via[:viaIndex]); candidate != nil {
		return sudoRunsAsRoot(candidate.Args)
	}
	// env and nohup can hide sudo's option-bearing call while retaining its
	// command line in their Args.
	if viaIndex > 0 {
		wrapper := call.Via[viaIndex-1]
		if candidate := findWrappedCall(call, calls, wrapper, call.Via[:viaIndex-1]); candidate != nil {
			if root, found := wrappedSudoRunsAsRoot(candidate.Args); found {
				return root
			}
		}
	}
	return true
}

func leavesHostRoot(call *shellcmd.Call, calls []shellcmd.Call, sudoIndex int) bool {
	for i := sudoIndex + 1; i < len(call.Via); i++ {
		wrapper := call.Via[i]
		switch wrapper {
		case "ssh":
			return true
		case "su", "runuser":
			candidate := findWrappedCall(call, calls, wrapper, call.Via[:i])
			if candidate == nil || switchesToNonRoot(wrapper, candidate.Args) {
				return true
			}
		case "docker", "podman":
			// shellcmd records docker/podman in Via only after peeling an exec
			// invocation; its target runs in the container's /tmp namespace.
			return true
		case "kubectl":
			if candidate := findWrappedCall(call, calls, wrapper, call.Via[:i]); candidate != nil && hasSubcommand(candidate.Args, "exec") {
				return true
			}
		case "exec":
			// shellcmd may expose kubectl's exec wrapper with or without its
			// kubectl name in Via. A plain shell exec remains host-root.
			if candidate := findWrappedCall(call, calls, "kubectl", call.Via[:i]); candidate != nil && hasSubcommand(candidate.Args, "exec") {
				return true
			}
		}
	}
	return false
}

func findWrappedCall(call *shellcmd.Call, calls []shellcmd.Call, name string, prefix []string) *shellcmd.Call {
	var best *shellcmd.Call
	bestOffset := -1
	bestLine := -1
	for i := range calls {
		candidate := &calls[i]
		if candidate.Name != name || !slices.Equal(candidate.Via, prefix) {
			continue
		}
		if call.Offset >= 0 && candidate.Offset >= 0 && candidate.Offset <= call.Offset {
			if candidate.Offset >= bestOffset {
				best = candidate
				bestOffset = candidate.Offset
			}
			continue
		}
		if bestOffset < 0 && candidate.Line <= call.Line && candidate.Line >= bestLine {
			best = candidate
			bestLine = candidate.Line
		}
	}
	return best
}

func lastVia(via []string, name string) int {
	for i := len(via) - 1; i >= 0; i-- {
		if via[i] == name {
			return i
		}
	}
	return -1
}

func firstSubcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return ""
		}
		if strings.HasPrefix(arg, "-") {
			if !strings.Contains(arg, "=") && commandOptionsWithValue[arg] && i+1 < len(args) {
				i++
			}
			continue
		}
		return arg
	}
	return ""
}

var commandOptionsWithValue = map[string]bool{
	"--as": true, "--as-group": true, "--certificate-authority": true,
	"--cluster": true, "--context": true, "--namespace": true,
	"--request-timeout": true, "--server": true, "--token": true,
	"--user": true, "-n": true,
}

func hasSubcommand(args []string, name string) bool {
	return firstSubcommand(args) == name
}

func switchesToNonRoot(wrapper string, args []string) bool {
	for i := range args {
		arg := args[i]
		if wrapper == "runuser" && (arg == "-u" || arg == "--user") {
			return i+1 < len(args) && strings.Trim(args[i+1], `"'`) != "root"
		}
		if wrapper == "runuser" && strings.HasPrefix(arg, "--user=") {
			return strings.Trim(strings.TrimPrefix(arg, "--user="), `"'`) != "root"
		}
		if wrapper == "su" && (arg == "-c" || arg == "--command") {
			return false
		}
		if arg == "--" {
			return false
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return strings.Trim(arg, `"'`) != "root"
	}
	return wrapper == "runuser"
}

func wrappedSudoRunsAsRoot(args []string) (bool, bool) {
	for i, arg := range args {
		if arg == "sudo" {
			return sudoRunsAsRoot(args[i+1:]), true
		}
	}
	return false, false
}

func sudoRunsAsRoot(args []string) bool {
	for i := range args {
		arg := args[i]
		if arg == "-u" || arg == "--user" {
			return i+1 >= len(args) || strings.Trim(args[i+1], `"'`) == "root"
		}
		if strings.HasPrefix(arg, "-u") && len(arg) > 2 {
			user := strings.TrimPrefix(arg, "-u")
			user = strings.TrimPrefix(user, "=")
			return strings.Trim(user, `"'`) == "root"
		}
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			break
		}
	}
	return true
}

// rootCommand returns what a line runs as root: the text after sudo, without
// quotes, up to the next chained command, and without redirections, which the
// calling shell opens with its own rights. sudo -u <user> runs as that user.
func rootCommand(line string) (string, bool) {
	loc := sudoCommand.FindStringIndex(line)
	if loc == nil {
		return "", false
	}
	command := line[loc[1]:]
	if m := sudoOtherUser.FindStringSubmatch(command); m != nil && m[1] != "root" {
		return "", false
	}
	command = strings.NewReplacer(`"`, "", "'", "").Replace(command)
	if end := strings.IndexAny(command, ";|&"); end >= 0 {
		command = command[:end]
	}
	return shellRedirect.ReplaceAllString(command, ""), true
}

// usesPredictableTmp reports a line naming a /tmp path not made by mktemp, or
// a variable assigned one.
func usesPredictableTmp(line string, tmpVars map[string]bool) bool {
	if strings.Contains(line, "mktemp") {
		return false
	}
	if predictableTmpPath.MatchString(line) {
		return true
	}
	for name := range tmpVars {
		if strings.Contains(line, "$"+name) || strings.Contains(line, "${"+name+"}") {
			return true
		}
	}
	return false
}

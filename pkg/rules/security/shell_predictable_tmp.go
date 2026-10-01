package security

import (
	"regexp"
	"strings"

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
	var violations []*core.Violation
	for i, line := range lines {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") {
			continue
		}
		command, ok := rootCommand(code)
		if !ok || !usesPredictableTmp(command, tmpVars) {
			continue
		}
		if ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, "sudo uses a file at a predictable /tmp path — another user of the host creates it, or a symlink, first and root runs their content")
		v.WithCode(code)
		v.WithSuggestion("Create the file with mktemp (remote: tmp=$(ssh host mktemp)) and pass that name")
		violations = append(violations, v)
	}
	return violations
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

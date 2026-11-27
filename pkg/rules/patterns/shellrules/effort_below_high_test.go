package shellrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A model run below high reasoning effort answers worse than the owner
// allows: an effort key, --effort of claude, model_reasoning_effort of codex
// set to low, medium or minimal, or codex exec left at its medium default.
func TestEffortBelowHighGo(t *testing.T) {
	ctx := rulestest.GoFile(t, "internal/judge/judge.go", `package judge

import "os/exec"

const understandEffort = "medium"

var judges = []CLIJudge{
	{Name: "opus", Effort: "medium", Timeout: 60},
	{Name: "sol", Effort: "xhigh"},
	{Name: "luna", Effort: effort},
}

func flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&effort, "effort", "low", "reasoning effort: low, medium, high")
	cmd.Flags().StringVar(&level, "level", "low", "log level")
}

func run(prompt string) {
	exec.Command("claude", "-p", "--effort", "medium", prompt)
	exec.Command("claude", "-p", "--effort=high", prompt)
	exec.Command("codex", "exec", "-c", "model_reasoning_effort=minimal", prompt)
	exec.Command("codex", "exec", "-c", "model_reasoning_effort=xhigh", prompt)
	exec.Command("codex", "exec", prompt)
	exec.Command("codex", "exec", "--profile", "deep", prompt)
	// The judge used to run with Effort: "medium".
	if understandEffort == "low" {
		return
	}
}
`)
	assert.Equal(t, []int{5, 8, 14, 19, 21, 23}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))
}

func TestEffortBelowHighTypeScript(t *testing.T) {
	ctx := rulestest.TextFile(t, "src/review.ts", `import Anthropic from '@anthropic-ai/sdk';
const config = {
  model: 'claude-opus-5-5',
  reasoningEffort: 'medium',
  reasoning_effort: "low",
  effort: 'high',
};
// effort: 'low' was the old default
const args = ['-p', '--effort', 'low'];
spawn('claude', ['-p', '--effort', effort]);
`)
	assert.Equal(t, []int{4, 5, 9}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))
}

func TestEffortBelowHighShell(t *testing.T) {
	ctx := rulestest.TextFile(t, "scripts/review.sh", `#!/bin/bash
EFFORT=medium
JUDGE_EFFORT="xhigh"
claude -p --effort low "$prompt"
claude -p --effort "$EFFORT" "$prompt"
codex exec -c model_reasoning_effort="medium" "$prompt"
codex exec -c 'model_reasoning_effort="high"' "$prompt"
codex exec "$prompt"
codex exec -c model_reasoning_effort="$EFFORT" "$prompt"
# codex exec ran on medium before
git commit -m "effort: low"
`)
	assert.Equal(t, []int{2, 4, 6, 8}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))
}

// The fixture of the ticket: low, medium and codex exec without the flag are
// found, high is not.
func TestEffortBelowHighTicketFixture(t *testing.T) {
	ctx := rulestest.TextFile(t, "run.sh", `claude -p --effort low "$p"
claude -p --effort medium "$p"
claude -p --effort high "$p"
codex exec "$p"
`)
	got := NewEffortBelowHighRule().AnalyzeFile(ctx)
	assert.Equal(t, []int{1, 2, 4}, rulestest.ViolationLines(got))
	require.NotEmpty(t, got)
	assert.Equal(t, core.SeverityHigh, got[0].Severity)
	assert.Contains(t, got[0].Message, "low")
}

// An effort of something other than a model — a task estimate, a story in a
// tracker — is not a reasoning effort: the key form counts only in a file
// that runs a model (names claude, codex, opencode, an SDK of a provider or
// a reasoning setting).
func TestEffortBelowHighNotAModel(t *testing.T) {
	ctx := rulestest.TextFile(t, "src/tasks/estimate.ts", `export const story = {
  title: 'Login page',
  effort: 'low',
  priority: 'medium',
};
`)
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(ctx))
	md := rulestest.TextFile(t, "docs/notes.md", "claude -p --effort low\n")
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(md))
}

// A Go or TypeScript test runs no model: an effort in its data is what the
// code under test reads. Only a process the test starts counts; a shell test
// script runs its lines.
func TestEffortBelowHighTestData(t *testing.T) {
	ctx := rulestest.GoFile(t, "judge/judge_test.go", `package judge

func TestParse(t *testing.T) {
	cases := []CLIJudge{{Name: "opus", Effort: "medium"}}
	write(t, "launch.sh", "claude -p --effort low\n")
	exec.Command("claude", "-p", "--effort", "low")
	exec.Command("codex", "exec", "x")
	_ = cases
}
`)
	assert.Equal(t, []int{6, 7}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))

	script := rulestest.TextFile(t, "scripts/review_test.sh", "EFFORT=low\nclaude -p --effort medium \"$p\"\n")
	assert.Equal(t, []int{1, 2}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(script)))
}

// A file that runs a model may name it on one line and set the effort on
// another: the sign of a model counts anywhere in the file. A flag named
// effort is a reasoning effort wherever it is declared. A help text or a
// validation switch lists the values, it does not set one.
func TestEffortBelowHighModelNamedElsewhereInTheFile(t *testing.T) {
	ctx := rulestest.GoFile(t, "cmd/judge/understand.go", `package judge

import "os/exec"

const understandEffort = "medium"

func flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&effort, "effort", "medium", "reasoning effort: low, medium, high")
	cmd.Flags().StringVarP(&effort, "effort", "e", "low", "reasoning effort")
	flag.String("effort", "minimal", "reasoning effort")
	cmd.Flags().StringVar(&effort, "effort", "high", "reasoning effort: low, medium, high")
}

func valid(e string) bool {
	switch e {
	case "low", "medium", "high":
		return true
	}
	return false
}

func run(prompt string) *exec.Cmd {
	return exec.Command("claude", "-p", prompt)
}
`)
	assert.Equal(t, []int{5, 8, 9, 10}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))
}

// The effort of a provider SDK request, and a default taken when the
// variable is unset.
func TestEffortBelowHighSDKAndDefaults(t *testing.T) {
	ctx := rulestest.TextFile(t, "src/ask.ts", `import OpenAI from 'openai';
const client = new OpenAI();
await client.responses.create({
  model: 'gpt-6.1-sol',
  reasoning: { effort: 'low' },
});
await anthropic.messages.create({ output_config: { effort: 'medium' } });
console.log('reasoning effort: low');
const e = process.env.EFFORT ?? 'medium';
const f = process.env.EFFORT ?? 'xhigh';
`)
	assert.Equal(t, []int{5, 7, 9}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))

	mk := rulestest.TextFile(t, "Makefile", "EFFORT ?= medium\nreview:\n\tclaude -p --effort $(EFFORT) \"$$P\"\n")
	assert.Equal(t, []int{1}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(mk)))
}

// codex exec counts where it is a command: the first words of a process a
// Go call starts, with the effort looked for in the whole call. A message,
// a label or a slice built further on is text.
func TestEffortBelowHighCodexExecAsACommandGo(t *testing.T) {
	ctx := rulestest.GoFile(t, "farm/probe.go", `package farm

func probe(ctx context.Context, bin, cfg, name string) error {
	fmt.Println("codex exec failed")
	if name == "codex" { exec.Command(bin, "exec") }
	cmd := exec.CommandContext(ctx, "codex", "exec", "--skip-git-repo-check", "ok")
	exec.Command("codex", "exec",
		"-c", "model_reasoning_effort=high", "x")
	exec.Command("codex", "exec", "-c", cfg, "x")
	exec.Command("codex", "e", "x")
	exec.CommandContext(ctx, codex, "app-server")
	h := harness{why: "Codex CLI (codex exec): rules"}
	args := []string{"codex", "exec"}
	args = append(args, "-c", "model_reasoning_effort="+effort)
	return fmt.Errorf("codex exec: %w", run(h, cmd, args))
}
`)
	got := NewEffortBelowHighRule().AnalyzeFile(ctx)
	assert.Equal(t, []int{6, 10}, rulestest.ViolationLines(got))
	require.NotEmpty(t, got)
	assert.Contains(t, got[0].Message, "codex")
	assert.NotContains(t, got[0].Message, `"medium"`, "no value is written on the line")
}

// In shell the same: codex is the command word (after variable assignments
// and wrappers such as timeout), a continued line is one command, and -p is
// the profile of codex only. Messages, titles and tests of a value are text.
func TestEffortBelowHighShellCommandsAndText(t *testing.T) {
	ctx := rulestest.TextFile(t, "scripts/run.sh", `#!/bin/bash
EFFORT=${EFFORT:-medium}
claude -p --effort "${EFFORT:-low}" "$p"
[ "$EFFORT" = low ] && echo slow
echo "effort: low"
printf 'codex exec failed\n'
gh pr create --title "effort: medium"
codex exec \
  -c model_reasoning_effort=high "$p"
mkdir -p "$out" && codex exec "$p"
claude -p --effort low "$p" && git commit -m x
CODEX_HOME=/tmp/h timeout 60 codex exec "$p"
codex exec -c model_reasoning_effort=none "$p"
codex exec -p deep "$p"
`)
	assert.Equal(t, []int{2, 3, 10, 11, 12, 13}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))
}

// The message names the value or the missing flag and the owner's rule.
func TestEffortBelowHighMessageNamesTheRule(t *testing.T) {
	got := NewEffortBelowHighRule().AnalyzeFile(rulestest.TextFile(t, "run.sh", "claude -p --effort medium \"$p\"\n"))
	require.Len(t, got, 1)
	assert.Contains(t, got[0].Message, `"medium"`)
	assert.Contains(t, got[0].Message, "high")
}

// A model of a known family named anywhere on a line marks the file as one
// that runs a model, not only at the start of the line.
func TestEffortBelowHighModelFamilyMidLine(t *testing.T) {
	ctx := rulestest.GoFile(t, "judge/judges.go", `package judge

var judges = []Judge{
	{Model: "opus", Effort: "medium"},
	{Model: "sol", Effort: "xhigh"},
}
`)
	assert.Equal(t, []int{4}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))
}

// TypeScript and JavaScript start codex with an argument array.
func TestEffortBelowHighCodexExecArrayTS(t *testing.T) {
	ctx := rulestest.TextFile(t, "src/run.ts", `import { spawn, execFile } from 'node:child_process';
spawn('codex', ['exec', prompt]);
execFile('codex', ['exec', '-c', 'model_reasoning_effort=high', prompt]);
spawn('codex', ['exec', '--profile', 'deep', prompt]);
execFile("codex", ["e", prompt], cb);
const body = {"reasoning_effort": "low", "model": "gpt-6.1-sol"};
`)
	assert.Equal(t, []int{2, 5, 6}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))
}

// codex is a command wherever the shell runs one: in a substitution, after
// if, do, !, time, nice, sudo, xargs, timeout with options, with options
// before exec, and in a make recipe after @ or -.
func TestEffortBelowHighCodexExecShellPositions(t *testing.T) {
	ctx := rulestest.TextFile(t, "scripts/loop.sh", `#!/bin/bash
out=$(codex exec "$p")
if codex exec "$p"; then echo ok; fi
for p in a b; do codex exec "$p"; done
time codex exec "$p"
sudo -u bot codex exec "$p"
timeout -k 5 60 codex exec "$p"
codex -a never exec "$p"
codex exec -c sandbox_mode=workspace-write "$p"
codex exec --help
`)
	assert.Equal(t, []int{2, 3, 4, 5, 6, 7, 8, 9}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))

	mk := rulestest.TextFile(t, "Makefile", "review:\n\t@codex exec \"$$P\"\n\t-codex exec \"$$P\"\n")
	assert.Equal(t, []int{2, 3}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(mk)))
}

// A value set in code counts, a value in the text of a string does not:
// errors, logs, panics, help and messages name values, they set none. A
// -c of codex and an --effort argument are settings although quoted.
func TestEffortBelowHighTextIsNotASetting(t *testing.T) {
	goFile := rulestest.GoFile(t, "judge/text.go", `package judge

const short = "reasoning effort: low, medium, high"

func check(effort string) error {
	exec.Command("claude", "-p", "--effort", "high")
	slog.Info("judge", "note", "effort: low is refused")
	if effort == "low" {
		panic("effort=minimal is refused")
	}
	settings := map[string]string{"reasoning_effort": "low"}
	exec.Command("codex", "exec", "--profile="+profile, "x")
	return fmt.Errorf("effort=low is below high: %v", settings)
}
`)
	assert.Equal(t, []int{11}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(goFile)))

	ts := rulestest.TextFile(t, "src/check.ts", `import Anthropic from '@anthropic-ai/sdk';
throw new Error('effort: low is refused');
console.error("reasoning effort: medium is too low");
process.stderr.write('effort=low\n');
`)
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(ts))

	sh := rulestest.TextFile(t, "scripts/check.sh", `#!/bin/bash
claude -p --effort high "$p"
>&2 echo "effort: low is refused"
log "effort: low is refused"
glab mr create --title "effort: medium"
grep -q 'effort: low' "$log"
[[ $EFFORT = medium ]] && exit 1
usage="usage: codex exec PROMPT"
echo done; git commit -m "effort: low"
cat <<EOT
codex exec "$p"
effort: low
EOT
`)
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(sh))
}

// The codex default depends on the model and can be low: the message does
// not claim medium.
func TestEffortBelowHighCodexMessage(t *testing.T) {
	got := NewEffortBelowHighRule().AnalyzeFile(rulestest.TextFile(t, "run.sh", "codex exec \"$p\"\n"))
	require.Len(t, got, 1)
	assert.NotContains(t, got[0].Message, "medium")
	assert.Contains(t, got[0].Message, "high")
}

package shellrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// A key named effort is a reasoning effort only in a file that runs a model:
// a story estimate in Go, a tracker script, a Makefile of an estimate tool
// set an effort of people. A file name with a digit (proto3.ts, video1.mp4)
// is not a model, and the word string next to a key is not a flag.
func TestEffortBelowHighKeyFormNeedsAModelFile(t *testing.T) {
	goFile := rulestest.GoFile(t, "internal/tasks/estimate.go", `package tasks

type Story struct{ Title, Effort string }

var backlog = []Story{
	{Title: "Login page", Effort: "low"},
	{Title: "video1.mp4", Effort: "medium"},
}

const defaultEffort = "medium"
`)
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(goFile))

	sh := rulestest.TextFile(t, "scripts/triage.sh", `#!/bin/bash
TASK_EFFORT=low
DEFAULT_EFFORT=${DEFAULT_EFFORT:-medium}
jira issue create --summary "$1" --custom "effort=$TASK_EFFORT"
`)
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(sh))

	mk := rulestest.TextFile(t, "Makefile", "EFFORT ?= medium\nestimate:\n\t./estimate --effort $(EFFORT)\n")
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(mk))

	ts := rulestest.TextFile(t, "src/stories.ts", `const files = ['proto3.ts', 'demo1.png'];
export const story = { title: 'Login', effort: 'low', kind: 'string' };
`)
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(ts))
}

// A flag named effort is a reasoning effort in any file: the program passes
// it to a model elsewhere. Its default is the third argument of StringP and
// the fourth of StringVarP.
func TestEffortBelowHighEffortFlagIsASign(t *testing.T) {
	ctx := rulestest.GoFile(t, "cmd/judge/flags.go", `package cmd

import (
	"flag"

	"github.com/spf13/cobra"
)

var effort, level string

func flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&effort, "effort", "medium", "how hard the judge thinks")
	cmd.Flags().StringP("effort", "e", "low", "how hard the judge thinks")
	cmd.Flags().StringVarP(&effort, "effort", "e", "minimal", "how hard the judge thinks")
	flag.String("effort", "low", "thinking level")
	flag.StringVar(&level, "level", "low", "log level")
	cmd.Flags().StringVar(&effort, "effort", "high", "how hard the judge thinks")
}
`)
	assert.Equal(t, []int{12, 13, 14, 15}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))
}

// In TypeScript a type, an interface field, a comparison, a record of levels
// and the text of an error name values and set none; a default parameter
// and an assignment to a member set one. A codex -c other than
// model_reasoning_effort sets no effort; --help runs no model.
func TestEffortBelowHighTypeScriptTypesAndCodexOptions(t *testing.T) {
	types := rulestest.TextFile(t, "src/judge/types.ts", "import Anthropic from '@anthropic-ai/sdk';\n"+
		"export type Effort = 'low' | 'medium' | 'high' | 'xhigh';\n"+
		"export interface JudgeOptions {\n"+
		"  effort?: 'low' | 'medium' | 'high';\n"+
		"}\n"+
		"type Req = { reasoning: { effort: 'low' | 'medium' | 'high' } };\n"+
		"export function ok(effort: Effort): boolean {\n"+
		"  if (effort != 'low') return true;\n"+
		"  return effort !== 'medium';\n"+
		"}\n"+
		"const allowed: Record<Effort, number> = { low: 1, medium: 2, high: 3 };\n"+
		"throw new Error(\"run with --effort low to save tokens\");\n"+
		"spawn('codex', ['exec', '--help']);\n"+
		"spawn('codex', ['exec', '-c', `model_reasoning_effort=${effort}`, prompt]);\n"+
		"const client = new Anthropic();\n")
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(types))

	set := rulestest.TextFile(t, "src/judge/run.ts", `import OpenAI from 'openai';
function judge(effort: string = 'low') { return effort; }
cfg.effort = 'medium';
spawn('codex', ['exec', '-c', 'sandbox_mode=workspace-write', prompt]);
spawn('codex', ['exec', '-c', 'model_reasoning_effort=high', prompt]);
`)
	assert.Equal(t, []int{2, 3, 4}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(set)))
}

// claude is a command behind nohup, timeout, env and in a substitution, and
// a command continued with a backslash is one. A Makefile is read as make:
// its assignments and its recipe lines, before and after a conditional, and
// a recipe line after @.
func TestEffortBelowHighClaudeBehindWrappersAndMake(t *testing.T) {
	sh := rulestest.TextFile(t, "scripts/review.sh", `#!/bin/bash
nohup claude -p --effort low "$p" > out.log &
timeout 600 claude -p --effort medium "$p"
env FOO=1 claude -p --effort low "$p"
out=$(claude -p --effort=medium "$p")
claude -p --effort low \
  --model opus "$p"
claude -p --effort high "$p"
`)
	assert.Equal(t, []int{2, 3, 4, 5, 6}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(sh)))

	mk := rulestest.TextFile(t, "Makefile", "JUDGE := claude\n"+
		"EFFORT := medium\n"+
		"SRC := $(wildcard *.go)\n"+
		"review: $(SRC)\n"+
		"\tclaude -p --effort low \"$$P\"\n"+
		"\t@claude -p --effort medium \"$$P\"\n"+
		"\ttimeout 60 codex exec \"$$P\"\n"+
		"ifeq ($(CI),1)\n"+
		"ci:\n"+
		"\tcodex exec \"$$P\"\n"+
		"endif\n")
	assert.Equal(t, []int{2, 5, 6, 7, 10}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(mk)))
}

// A shell sets an effort by export, declare, local, a positional default and
// the := default; a list of levels in a hint, the body of a heredoc and the
// text of printf set none.
func TestEffortBelowHighShellSettingForms(t *testing.T) {
	sh := rulestest.TextFile(t, "scripts/judge.sh", `#!/bin/bash
export EFFORT=medium
declare -r JUDGE_EFFORT=low
judge() { local effort=medium; claude -p --effort "$effort" "$p"; }
effort="${2:-medium}"
: "${REVIEW_EFFORT:=low}"
claude -p --effort "${2:-low}" "$p"
JUDGE_EFFORT_HINT="low medium high"
cat <<EOT
EFFORT=low
${EFFORT:-medium}
EOT
printf '%s\n' "EFFORT=low"
`)
	assert.Equal(t, []int{2, 3, 4, 5, 6, 7}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(sh)))
}

// The options of codex in a shell: -c and --config with
// model_reasoning_effort set the effort, before exec too, and so does a
// profile after another -c; a -c of something else does not. -h runs no
// model.
func TestEffortBelowHighCodexOptionsShell(t *testing.T) {
	sh := rulestest.TextFile(t, "scripts/codex.sh", `#!/bin/bash
codex exec -c sandbox_mode=workspace-write -p deep "$p"
codex exec --config model_reasoning_effort=high "$p"
codex exec --config=model_reasoning_effort=high "$p"
codex -c model_reasoning_effort=high exec "$p"
codex -p deep exec "$p"
codex exec -h
codex exec -c sandbox_mode=workspace-write -c model_reasoning_effort=low "$p"
codex exec --config model_reasoning_effort=low "$p"
codex -c model_reasoning_effort=low exec "$p"
`)
	assert.Equal(t, []int{8, 9, 10}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(sh)))
}

// The options of codex in Go: a -c other than model_reasoning_effort sets no
// effort, a raw string value counts, --help runs no model, and the text of
// a usage line or a hint sets nothing. An assignment to a field sets one.
func TestEffortBelowHighCodexOptionsGo(t *testing.T) {
	ctx := rulestest.GoFile(t, "internal/judge/codex.go", "package judge\n"+
		"\n"+
		"import (\n"+
		"\t\"fmt\"\n"+
		"\t\"os/exec\"\n"+
		")\n"+
		"\n"+
		"type Judge struct{ Model, Effort string }\n"+
		"\n"+
		"func help() string {\n"+
		"\treturn fmt.Sprintf(\"usage: judge --effort low|medium|high (default %s)\", \"high\")\n"+
		"}\n"+
		"\n"+
		"func run(p string) {\n"+
		"\texec.Command(\"codex\", \"exec\", \"--help\")\n"+
		"\texec.Command(\"codex\", \"--profile\", \"deep\", \"exec\", p)\n"+
		"\tfmt.Println(\"hint: --effort low is cheaper\")\n"+
		"\texec.Command(\"codex\", \"exec\", \"-c\", \"sandbox_mode=workspace-write\", p)\n"+
		"\tj := Judge{Model: \"opus\"}\n"+
		"\tj.Effort = \"medium\"\n"+
		"\texec.Command(\"codex\", \"exec\", \"-c\", `model_reasoning_effort=\"low\"`, p)\n"+
		"\texec.Command(\"codex\", \"exec\", \"-c\", `model_reasoning_effort=\"high\"`, p)\n"+
		"}\n")
	assert.Equal(t, []int{18, 20, 21}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ctx)))
}

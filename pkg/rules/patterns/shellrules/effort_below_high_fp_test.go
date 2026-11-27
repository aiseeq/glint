package shellrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// A value is a whole token: lowEffort and mediumBudget are names, not low and
// medium. JSON in the text of a prompt sets nothing, and a file that names a
// Solidity source (token.sol) runs no model.
func TestEffortBelowHighValueIsAWholeToken(t *testing.T) {
	ts := rulestest.TextFile(t, "src/judge/config.ts", `import Anthropic from '@anthropic-ai/sdk';
const a = { model: 'opus', effort: lowEffort };
const b = { model: 'opus', effort: mediumBudget ? 'high' : 'xhigh' };
const c = { model: 'opus', content: 'Answer as JSON {"effort": "low"}' };
const d = { model: 'opus', effort: 'low' };
`)
	assert.Equal(t, []int{5}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(ts)))

	sol := rulestest.TextFile(t, "src/stories.ts", `const files = ['contracts/token.sol'];
export const story = { title: 'Audit', effort: 'low' };
`)
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(sol))
}

// The typed constants of an effort type are its levels, not a setting: the
// setting is where one of them is passed.
func TestEffortBelowHighGoEnumIsNotASetting(t *testing.T) {
	ctx := rulestest.GoFile(t, "internal/judge/effort.go", `package judge

import "os/exec"

type Effort string

const (
	EffortLow    Effort = "low"
	EffortMedium Effort = "medium"
	EffortHigh   Effort = "high"
)

func run(p string) *exec.Cmd {
	return exec.Command("claude", "-p", "--effort", string(EffortHigh), p)
}
`)
	assert.Empty(t, NewEffortBelowHighRule().AnalyzeFile(ctx))
}

// An expansion in the text of echo shows a value and sets none; an expansion
// that cuts a suffix (%medium) sets no default. A default in an assignment
// sets one.
func TestEffortBelowHighShellExpansionInText(t *testing.T) {
	sh := rulestest.TextFile(t, "scripts/show.sh", `#!/bin/bash
claude -p --effort high "$p"
echo "effort: ${EFFORT:-medium}"
x=${EFFORT%medium}
y=${EFFORT:-medium}
`)
	assert.Equal(t, []int{5}, rulestest.ViolationLines(NewEffortBelowHighRule().AnalyzeFile(sh)))
}

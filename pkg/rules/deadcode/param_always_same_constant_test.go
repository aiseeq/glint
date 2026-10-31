package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestParamAlwaysSameConstantRule(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{
			name: "method parameter receives same boolean literal",
			files: map[string]string{"main.go": `package main

import "io/fs"
import "time"

type result struct{}

func (r *result) entry(sub string, e fs.DirEntry, cutoff time.Time, apply bool) error {
	if apply { return nil }
	return nil
}

func run(r *result, e fs.DirEntry, cutoff time.Time) {
	_ = r.entry("a", e, cutoff, false)
	_ = r.entry("b", e, cutoff, false)
}`},
			want: 1,
		},
		{
			name: "named constant and boolean operators",
			files: map[string]string{"main.go": `package main

const disabled = false
func check(enabled, extra bool) int {
	if !enabled || extra { return 1 }
	return 0
}
func run() { check(disabled, true); check(false, false) }`},
			want: 1,
		},
		{
			name: "single call",
			files: map[string]string{"main.go": `package main
func check(enabled bool) { if enabled {} }
func run() { check(false) }`},
		},
		{
			name: "parameter reassigned before the branch",
			files: map[string]string{"main.go": `package main
func check(enabled bool, force bool) {
	if force { enabled = true }
	if enabled {}
}
func run(f bool) { check(false, f); check(false, !f) }`},
		},
		{
			name: "parameter address taken",
			files: map[string]string{"main.go": `package main
func set(p *bool) { *p = true }
func check(enabled bool) {
	set(&enabled)
	if enabled {}
}
func run() { check(false); check(false) }`},
		},
		{
			name: "different constants",
			files: map[string]string{"main.go": `package main
func check(enabled bool) { if enabled {} }
func run() { check(false); check(true) }`},
		},
		{
			name: "constant parameter does not control branch",
			files: map[string]string{"main.go": `package main
func check(enabled bool) { if true {} ; _ = enabled }
func run() { check(false); check(false) }`},
		},
		{
			name: "exported library API",
			files: map[string]string{"lib.go": `package library
func Check(enabled bool) { if enabled {} }
func Run() { Check(false); Check(false) }`},
		},
		{
			name: "function used as a value",
			files: map[string]string{"main.go": `package main
func check(enabled bool) { if enabled {} }
func run() { check(false); check(false); _ = check }`},
		},
		{
			name: "method implements interface",
			files: map[string]string{"main.go": `package main
type checker interface { Check(bool) }
type value struct{}
func (value) Check(enabled bool) { if enabled {} }
func run() { var c checker = value{}; c.Check(false); c.Check(false) }`},
		},
		{
			name: "test calls do not count",
			files: map[string]string{
				"main.go": `package main
func check(enabled bool) { if enabled {} }
func run() { check(false) }`,
				"main_test.go": `package main
func TestCalls() { check(false); check(false) }`,
			},
		},
		{
			name: "computed constant expression",
			files: map[string]string{"main.go": `package main
func check(enabled bool) { if enabled {} }
func run() { check(false && true); check(false && true) }`},
		},
		{
			name: "parameter does not decide comparison with another value",
			files: map[string]string{"main.go": `package main
func head(s string, n int) { if len(s) <= n {} }
func run() { head("a", 300); head("b", 300) }`},
		},
		{
			name: "parameter inside call does not decide branch",
			files: map[string]string{"main.go": `package main
import "strings"
func envWith(name, key string) { if !strings.EqualFold(name, key) {} }
func run() { envWith("a", "GOWORK"); envWith("b", "GOWORK") }`},
		},
		{
			name: "logical leaf decides branch by its value",
			files: map[string]string{"main.go": `package main
func check(eyes, extra bool) { if eyes && extra {} }
func run() { check(false, true); check(false, false) }`},
			want: 1,
		},
		{
			name: "true logical leaf decides branch",
			files: map[string]string{"main.go": `package main
func check(eyes, extra bool) { if eyes || extra {} }
func run() { check(true, true); check(true, false) }`},
			want: 1,
		},
		{
			name: "true left operand does not decide and",
			files: map[string]string{"main.go": `package main
func check(eyes, extra bool) { if eyes && extra {} }
func run() { check(true, true); check(true, false) }`},
		},
		{
			name: "false left operand does not decide or",
			files: map[string]string{"main.go": `package main
func check(eyes, extra bool) { if eyes || extra {} }
func run() { check(false, true); check(false, false) }`},
		},
		{
			name: "constant equality decides branch",
			files: map[string]string{"main.go": `package main
const expected = 4
func check(code int) { if code == expected {} }
func run() { check(4); check(4) }`},
			want: 1,
		},
		{
			name: "comparison with variable does not decide branch",
			files: map[string]string{"main.go": `package main
func check(code, expected int) { if code == expected {} }
func run() { check(4, 4); check(4, 4) }`},
		},
		{
			name: "spread call makes function uncertain",
			files: map[string]string{"main.go": `package main
func check(eyes bool, rest ...int) { if eyes {} }
func run(values []int) { check(false, values...); check(false, values...) }`},
		},
		{
			name: "method expression makes method uncertain",
			files: map[string]string{"main.go": `package main
type runner struct{}
func (runner) check(eyes bool) { if eyes {} }
func run() { runner.check(runner{}, false); runner.check(runner{}, false) }`},
		},
		{
			name: "variadic parameter is not analyzed",
			files: map[string]string{"main.go": `package main
func check(eyes ...bool) { if eyes[0] {} }
func run() { check(false); check(false) }`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := analyzeParamAlwaysSameConstant(t, tt.files)
			assert.Len(t, violations, tt.want)
			if tt.want != 0 && len(violations) > 0 {
				assert.Contains(t, violations[0].Message, "the code for other values never runs")
			}
		})
	}
}

func analyzeParamAlwaysSameConstant(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := NewParamAlwaysSameConstantRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	return violations
}

func TestParamAlwaysSameConstantRuleUsesConstantValue(t *testing.T) {
	violations := analyzeParamAlwaysSameConstant(t, map[string]string{"main.go": `package main
const first = 1
const second = 1.0
func check(code int) { switch code { case 0: } }
func run() { check(first); check(second) }`})
	require.Len(t, violations, 1)
	assert.Equal(t, "code", violations[0].Context["param"])
}

func TestParamAlwaysSameConstantRuleMessage(t *testing.T) {
	violations := analyzeParamAlwaysSameConstant(t, map[string]string{"main.go": `package main
func walk(eyes bool) { if eyes {} }
func run() { walk(true); walk(true) }`})
	require.Len(t, violations, 1)
	assert.Equal(t, "Parameter eyes of walk is true at every call — the code for other values never runs", violations[0].Message)
}

package depgraph

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixture is a small glint: a registry, a core with a file context, a
// helper reached through a method value, rules of their own type and rules
// sharing one type with a check function each, a go:embed table, and a
// command with the check handler and another one.
var fixture = map[string]string{
	"go.mod": "module example.com/lint\n\ngo 1.24\n",
	"pkg/core/core.go": `package core

type FileContext struct{ Text string }

func (c *FileContext) HasText() bool { return c.Text != "" }

func (c *FileContext) Lines() int { return len(c.Text) }

type Violation struct{ Message string }
`,
	"pkg/rules/rule.go": `package rules

import "example.com/lint/pkg/core"

type Rule interface {
	Name() string
	Configure(map[string]any) error
	AnalyzeFile(*core.FileContext) []*core.Violation
}

type Base struct{ name string }

func NewBase(name string) *Base { return &Base{name: name} }

func (b *Base) Name() string { return b.name }

func (b *Base) Configure(map[string]any) error { return nil }

func (b *Base) Setting() string { return "unused by the run" }

var registry []Rule

func Register(rule Rule) {
	rule.Name()
	registry = append(registry, rule)
}

func All() []Rule { return registry }
`,
	"pkg/rules/helpers/funcs.go": `package helpers

import "example.com/lint/pkg/core"

type Checker func(*core.FileContext, string) []*core.Violation

func ForEachWord(
	ctx *core.FileContext,
	check Checker,
) []*core.Violation {
	var out []*core.Violation
	for _, w := range []string{ctx.Text} {
		out = append(out, check(ctx, w)...)
	}
	return out
}
`,
	"pkg/rules/check/words.go": `package check

import (
	"example.com/lint/pkg/core"
	"example.com/lint/pkg/rules"
	"example.com/lint/pkg/rules/helpers"
)

func init() {
	rules.Register(&WordsRule{Base: rules.NewBase("words")})
}

type WordsRule struct{ *rules.Base }

func (r *WordsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return helpers.ForEachWord(ctx, r.word)
}

func (r *WordsRule) word(ctx *core.FileContext, w string) []*core.Violation {
	if w == forbidden {
		return []*core.Violation{{Message: w}}
	}
	return nil
}

const forbidden = "x"
`,
	"pkg/rules/check/length.go": `package check

import (
	"example.com/lint/pkg/core"
	"example.com/lint/pkg/rules"
)

func init() { rules.Register(newLengthRule()) }

type LengthRule struct{ *rules.Base }

func newLengthRule() *LengthRule { return &LengthRule{Base: rules.NewBase("length")} }

func (r *LengthRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.Lines() > limit {
		return []*core.Violation{{Message: "long"}}
	}
	return nil
}

var limit = 10
`,
	"pkg/rules/check/shared.go": `package check

import (
	_ "embed"
	"strings"

	"example.com/lint/pkg/core"
	"example.com/lint/pkg/rules"
)

//go:embed words.txt
var banned string

type textRule struct {
	*rules.Base
	check func(string) bool
}

func newTextRule(name string, check func(string) bool) *textRule {
	return &textRule{Base: rules.NewBase(name), check: check}
}

func (r *textRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if r.check(ctx.Text) {
		return []*core.Violation{{Message: r.Name()}}
	}
	return nil
}

func init() {
	rules.Register(newTextRule("text-banned",
		hasBanned))
	rules.Register(newTextRule("text-empty", func(s string) bool { return s == "" }))
}

func hasBanned(s string) bool { return strings.Contains(s, banned) }
`,
	"pkg/rules/check/words.txt": "secret\n",
	"cmd/glint/main.go": `package main

import (
	"fmt"
	"os"

	"example.com/lint/pkg/core"
	"example.com/lint/pkg/rules"
	_ "example.com/lint/pkg/rules/check"
)

type command struct {
	name string
	run  func(args []string) error
}

var commands = []command{{name: "check", run: runCheck}, {name: "fix", run: runFix}}

func main() {
	for _, c := range commands {
		if c.name == os.Args[1] {
			_ = c.run(os.Args[2:])
		}
	}
}

func runCheck(args []string) error {
	ctx := &core.FileContext{Text: args[0]}
	for _, rule := range rules.All() {
		_ = rule.Configure(nil)
		if ctx.HasText() {
			report(rule.AnalyzeFile(ctx))
		}
	}
	return nil
}

func report(found []*core.Violation) {
	for _, v := range found {
		fmt.Println(v.Message)
	}
}

func runFix(args []string) error {
	fmt.Println("fixing", args)
	return nil
}
`,
}

func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	return root
}

func analyzeFixture(t *testing.T, files map[string]string) *Result {
	t.Helper()
	root := writeFixture(t, files)
	result, err := Analyze(context.Background(), Config{
		Dir: root, Command: "example.com/lint/cmd/glint", Entry: "runCheck",
		Register: "example.com/lint/pkg/rules.Register", Rule: "example.com/lint/pkg/rules.Rule",
		RegistryMethods: []string{"Name", "Configure"},
	})
	require.NoError(t, err)
	return result
}

// siteOf returns the site of the Register call on the line holding text.
func siteOf(t *testing.T, result *Result, file, text string) Site {
	t.Helper()
	lines := strings.Split(fixture[file], "\n")
	line := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, text) }) + 1
	require.Positive(t, line, text)
	for _, s := range result.Sites {
		if strings.HasSuffix(s.File, "/"+filepath.Base(file)) && s.From <= line && line <= s.To {
			return s
		}
	}
	t.Fatalf("no site at %s:%d", file, line)
	return Site{}
}

// funcAt returns the key of the function declared on the line starting with
// text: the line its body's brace opens on, as go tool covdata func names it.
func funcAt(file, text string) string {
	lines := strings.Split(fixture[file], "\n")
	line := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, text) })
	for line >= 0 && line < len(lines) && !strings.Contains(lines[line], "{") {
		line++
	}
	return "example.com/lint/" + file + ":" + strconv.Itoa(line+1)
}

func with(files map[string]string, name, old, replacement string) map[string]string {
	changed := make(map[string]string, len(files))
	maps.Copy(changed, files)
	changed[name] = strings.Replace(files[name], old, replacement, 1)
	if changed[name] == files[name] {
		panic("fixture edit did not apply: " + old)
	}
	return changed
}

func TestRuleScopesSeparateRulesAndTheDriver(t *testing.T) {
	result := analyzeFixture(t, fixture)

	words := siteOf(t, result, "pkg/rules/check/words.go", "rules.Register(")
	length := siteOf(t, result, "pkg/rules/check/length.go", "rules.Register(")
	banned := siteOf(t, result, "pkg/rules/check/shared.go", `"text-banned"`)
	empty := siteOf(t, result, "pkg/rules/check/shared.go", `"text-empty"`)

	assert.Contains(t, words.Funcs, funcAt("pkg/rules/helpers/funcs.go", "func ForEachWord"), "keyed by the line of its body's brace")
	assert.Contains(t, words.Funcs, "example.com/lint/pkg/rules/helpers/funcs.go:10")
	assert.Contains(t, words.Funcs, funcAt("pkg/rules/check/words.go", "func (r *WordsRule) word"), "a method value passed as a callback")
	assert.NotContains(t, length.Funcs, funcAt("pkg/rules/helpers/funcs.go", "func ForEachWord"))
	assert.Contains(t, length.Funcs, funcAt("pkg/core/core.go", "func (c *FileContext) Lines"))
	assert.Contains(t, banned.Funcs, funcAt("pkg/rules/check/shared.go", "func hasBanned"), "the check its registration passes")
	assert.NotContains(t, empty.Funcs, funcAt("pkg/rules/check/shared.go", "func hasBanned"), "a sibling of the same type")
	assert.NotContains(t, words.Funcs, funcAt("pkg/rules/rule.go", "func (b *Base) Setting"), "a promoted method nobody calls")

	driver := result.DriverFuncs
	for _, want := range []string{
		funcAt("cmd/glint/main.go", "func main"), funcAt("cmd/glint/main.go", "func runCheck"),
		funcAt("pkg/rules/check/length.go", "func newLengthRule"), funcAt("pkg/rules/check/shared.go", "func init"),
		funcAt("pkg/rules/rule.go", "func (b *Base) Name"), funcAt("pkg/rules/rule.go", "func (b *Base) Configure"),
		funcAt("pkg/core/core.go", "func (c *FileContext) HasText"),
	} {
		assert.Contains(t, driver, want)
	}
	for _, unwanted := range []string{
		funcAt("cmd/glint/main.go", "func runFix"),
		funcAt("pkg/rules/check/length.go", "func (r *LengthRule) AnalyzeFile"),
		funcAt("pkg/rules/check/shared.go", "func hasBanned"),
		funcAt("pkg/rules/helpers/funcs.go", "func ForEachWord"),
	} {
		assert.NotContains(t, driver, unwanted)
	}
}

func TestAnEditChangesTheKeysOfTheCodeItTouches(t *testing.T) {
	base := analyzeFixture(t, fixture)
	key := func(result *Result, file, text string) string { return siteOf(t, result, file, text).Hash }
	type keys struct{ driver, words, length, banned, empty string }
	all := func(result *Result) keys {
		return keys{result.Driver, key(result, "pkg/rules/check/words.go", "rules.Register("), key(result, "pkg/rules/check/length.go", "rules.Register("),
			key(result, "pkg/rules/check/shared.go", `"text-banned"`), key(result, "pkg/rules/check/shared.go", `"text-empty"`)}
	}
	before := all(base)

	for _, tc := range []struct {
		name    string
		files   map[string]string
		changed []string
	}{
		{"a rule's method", with(fixture, "pkg/rules/check/length.go", "> limit", ">= limit"), []string{"length"}},
		{"a constant a rule names", with(fixture, "pkg/rules/check/words.go", `forbidden = "x"`, `forbidden = "y"`), []string{"words"}},
		{"a variable's initializer", with(fixture, "pkg/rules/check/length.go", "limit = 10", "limit = 12"), []string{"length"}},
		{"a helper behind a callback", with(fixture, "pkg/rules/helpers/funcs.go", "[]string{ctx.Text}", "[]string{ctx.Text, ctx.Text}"), []string{"words"}},
		{"a check function of a shared type", with(fixture, "pkg/rules/check/shared.go", "strings.Contains(s, banned)", "strings.HasPrefix(s, banned)"), []string{"banned"}},
		{"an embedded file", with(fixture, "pkg/rules/check/words.txt", "secret", "password"), []string{"banned"}},
		{"the method of the shared type", with(fixture, "pkg/rules/check/shared.go", "if r.check(ctx.Text)", "if r.check(ctx.Text + \" \")"), []string{"banned", "empty"}},
		{"the driver", with(fixture, "pkg/core/core.go", `c.Text != ""`, `len(c.Text) > 0`), []string{"driver"}},
		{"a comment", with(fixture, "pkg/rules/check/length.go", "var limit = 10", "// limit is long\nvar limit = 10"), nil},
		{"another command", with(fixture, "cmd/glint/main.go", `"fixing", args`, `"fix", args`), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := all(analyzeFixture(t, tc.files))
			var changed []string
			for _, c := range []struct {
				name      string
				old, next string
			}{{"driver", before.driver, after.driver}, {"words", before.words, after.words}, {"length", before.length, after.length},
				{"banned", before.banned, after.banned}, {"empty", before.empty, after.empty}} {
				if c.old != c.next {
					changed = append(changed, c.name)
				}
			}
			assert.Equal(t, tc.changed, changed)
		})
	}
}

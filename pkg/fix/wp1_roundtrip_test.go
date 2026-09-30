package fix_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/fix"
	"github.com/aiseeq/glint/pkg/rules"
	_ "github.com/aiseeq/glint/pkg/rules/doccheck"
	_ "github.com/aiseeq/glint/pkg/rules/patterns"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	_ "github.com/aiseeq/glint/pkg/rules/typesafety"
)

// The round-trip tests run a fix the way `glint fix --dry-run=false` does:
// analyze the module, generate and apply the fixes, then build the module and
// fix it once more. A fix that leaves code which does not build, or that a
// second run would change again, fails here.

var roundTripRules = []string{
	"bool-compare", "deprecated-ioutil", "interface-any",
	"map-iteration-order", "reimplemented-stdlib",
}

// fixOnce analyzes the module under root with the given rules, applies every
// fix and returns the results and the number of fixes that were generated.
func fixOnce(t *testing.T, root string, ruleNames []string) ([]fix.Result, []*fix.Fix) {
	t.Helper()

	contexts := moduleContexts(t, root)
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)

	contextMap := make(map[string]*core.FileContext)
	for _, ctx := range contexts {
		contextMap[ctx.Path] = ctx
		contextMap[ctx.RelPath] = ctx
	}

	var violations []*core.Violation
	for _, name := range ruleNames {
		rule, ok := rules.Get(name)
		require.True(t, ok, name)
		if projectRule, ok := rule.(rules.GoProjectRule); ok {
			found, err := projectRule.AnalyzeGoProject(project)
			require.NoError(t, err)
			violations = append(violations, found...)
			continue
		}
		for _, ctx := range contexts {
			violations = append(violations, rule.AnalyzeFile(ctx)...)
		}
	}

	engine := fix.NewEngine(fix.DefaultRegistry, false)
	fixes := engine.GenerateFixes(violations, contextMap)
	return engine.ApplyFixes(fixes), fixes
}

// moduleContexts reads every file of the module back from disk.
func moduleContexts(t *testing.T, root string) []*core.FileContext {
	t.Helper()
	var paths []string
	require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && (strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".md")) {
			paths = append(paths, path)
		}
		return nil
	}))
	sort.Strings(paths)

	contexts := make([]*core.FileContext, 0, len(paths))
	for _, path := range paths {
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		ctx, err := core.NewFileContextChecked(path, root, content, core.DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}
	return contexts
}

// buildModule compiles the module and fails the test with the compiler output.
func buildModule(t *testing.T, root string) {
	t.Helper()
	cmd := exec.Command("go", "vet", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOFLAGS=-mod=mod")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "fixed module does not build:\n%s", output)
}

// roundTrip fixes the module, builds it, and checks that a second run changes
// nothing. It returns the fixed content of every file by relative path.
func roundTrip(t *testing.T, files map[string]string) map[string]string {
	t.Helper()
	return roundTripWith(t, files, roundTripRules)
}

// roundTripWith is roundTrip with a chosen set of rules.
func roundTripWith(t *testing.T, files map[string]string, ruleNames []string) map[string]string {
	t.Helper()
	root, _ := rulestest.Module(t, files)

	results, _ := fixOnce(t, root, ruleNames)
	for _, result := range results {
		require.NoError(t, result.Error, result.File)
	}
	buildModule(t, root)

	again, fixes := fixOnce(t, root, ruleNames)
	applied := 0
	for _, result := range again {
		require.NoError(t, result.Error, result.File)
		applied += result.FixesApplied
	}
	assert.Zero(t, applied, "a second fix run must change nothing, got fixes: %v", describeFixes(fixes))

	fixed := make(map[string]string, len(files))
	for name := range files {
		content, err := os.ReadFile(filepath.Join(root, name))
		require.NoError(t, err)
		fixed[name] = string(content)
	}
	return fixed
}

func describeFixes(fixes []*fix.Fix) []string {
	described := make([]string, 0, len(fixes))
	for _, f := range fixes {
		described = append(described, f.RuleName+": "+f.OldText+" -> "+f.NewText)
	}
	return described
}

const modGo123 = "module example.com/projecta\n\ngo 1.23\n"

// Replacing ioutil calls must bring in os and io and drop io/ioutil; a second
// call on the same line, and a call after a string holding "//", are fixed in
// the same run.
func TestRoundTripDeprecatedIoutil(t *testing.T) {
	fixed := roundTrip(t, map[string]string{
		"go.mod": modGo123,
		"a.go": `package projecta

import (
	"fmt"
	"io"
	"io/ioutil"
)

// Read reads.
func Read(p string) ([]byte, error) {
	b, err := ioutil.ReadFile(p) // keep this comment
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return b, nil
}

// Two uses two ioutil funcs on one line.
func Two(p string) error {
	_, err := ioutil.ReadFile(p); if err == nil { err = ioutil.WriteFile(p, nil, 0o600) }
	return err
}

// Fetch reads after a URL literal.
func Fetch(r io.Reader) ([]byte, string) {
	u := "http://example.com"; data, _ := ioutil.ReadAll(r)
	return data, u
}
`,
	})

	assert.NotContains(t, fixed["a.go"], `"io/ioutil"`)
	assert.NotContains(t, fixed["a.go"], "ioutil.")
	assert.Contains(t, fixed["a.go"], "os.ReadFile(p) // keep this comment")
	assert.Contains(t, fixed["a.go"], "os.WriteFile(p, nil, 0o600)")
	assert.Contains(t, fixed["a.go"], "io.ReadAll(r)")
}

// ioutil.ReadDir returns []fs.FileInfo and os.ReadDir []fs.DirEntry: the
// rewrite would not compile, so it is left to a human.
func TestRoundTripIoutilReadDirIsNotRewritten(t *testing.T) {
	fixed := roundTrip(t, map[string]string{
		"go.mod": modGo123,
		"a.go": `package projecta

import (
	"io/ioutil"
	"os"
)

// Sizes sums sizes.
func Sizes(dir string) int64 {
	var n int64
	entries, _ := ioutil.ReadDir(dir)
	for _, e := range entries {
		n += e.Size()
	}
	_ = os.Getpid()
	return n
}
`,
	})

	assert.Contains(t, fixed["a.go"], "ioutil.ReadDir(dir)")
}

// Two rules adding the same import must add it once.
func TestRoundTripSharedImportIsAddedOnce(t *testing.T) {
	fixed := roundTrip(t, map[string]string{
		"go.mod": modGo123,
		"a.go": `package projecta

import (
	"fmt"
	"strings"
)

// Keys returns keys.
func Keys(m map[string]int) []string {
	var out []string
	for k, v := range m {
		out = append(out, fmt.Sprint(k, v))
	}
	return out
}

func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func hasLower(xs []string, s string) bool {
	for _, x := range xs {
		if x == strings.ToLower(s) {
			return true
		}
	}
	return false
}

func hasAny(xs []any, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Use uses.
func Use() bool { return has(nil, "") || hasLower(nil, "") || hasAny(nil, "") }
`,
	})

	assert.Equal(t, 1, strings.Count(fixed["a.go"], `"slices"`))
	assert.Contains(t, fixed["a.go"], "range slices.Sorted(maps.Keys(m))")
	assert.Contains(t, fixed["a.go"], "return slices.Contains(xs, s)")
	assert.Contains(t, fixed["a.go"], "x == strings.ToLower(s)", "a comparison with a converted value is not slices.Contains")
	assert.Equal(t, 1, strings.Count(fixed["a.go"], "slices.Contains("), "[]any searched for a string does not compile as slices.Contains")
}

// Sorting keys needs an ordered key type: a struct key stays a map walk.
func TestRoundTripStructKeyIsNotSorted(t *testing.T) {
	fixed := roundTrip(t, map[string]string{
		"go.mod": modGo123,
		"a.go": `package projecta

import (
	"fmt"
)

type point struct{ X, Y int }

// Names lists names.
func Names(m map[point]string) []string {
	var out []string
	for p, name := range m {
		out = append(out, fmt.Sprint(p, name))
	}
	return out
}
`,
	})

	assert.Contains(t, fixed["a.go"], "for p, name := range m {")
}

// A named key type with an ordered underlying type sorts fine.
func TestRoundTripNamedOrderedKeyIsSorted(t *testing.T) {
	fixed := roundTrip(t, map[string]string{
		"go.mod": modGo123,
		"a.go": `package projecta

type accountID int64

// IDs lists ids.
func IDs(m map[accountID]bool) []accountID {
	var out []accountID
	for id := range m {
		out = append(out, id)
	}
	return out
}
`,
	})

	assert.Contains(t, fixed["a.go"], "range slices.Sorted(maps.Keys(m))")
}

// The comparison is rewritten through the syntax tree: a name that merely
// starts with "true" is not a literal, and negating an operator expression
// needs parentheses.
func TestRoundTripBoolCompare(t *testing.T) {
	fixed := roundTrip(t, map[string]string{
		"go.mod": modGo123,
		"a.go": `package projecta

// F compares.
func F(a, trueSeen, done bool, n int, p *bool) bool {
	if a == trueSeen && done == false {
		return true
	}
	if *p == false {
		return false
	}
	if done == true && a != false {
		return true
	}
	return n > 0 == false
}
`,
	})

	assert.Contains(t, fixed["a.go"], "if a == trueSeen && !done {")
	assert.Contains(t, fixed["a.go"], "if !*p {")
	assert.Contains(t, fixed["a.go"], "if done && a {")
	assert.Contains(t, fixed["a.go"], "return !(n > 0)")
}

// interface{} inside a string stays; every interface{} in code becomes any.
func TestRoundTripInterfaceAny(t *testing.T) {
	fixed := roundTrip(t, map[string]string{
		"go.mod": modGo123,
		"a.go": `package projecta

import "fmt"

// Box holds values.
type Box struct {
	A interface{}
	B map[string]interface{}
	C func(interface{}) interface{}
}

// Describe describes.
func Describe(v interface{}) string { return "want interface{} here" + fmt.Sprint(v) }

const raw = ` + "`" + `
var x interface{}
` + "`" + `

// Print prints.
func Print() { fmt.Print(map[string]interface{}{}, raw) }
`,
	})

	assert.Contains(t, fixed["a.go"], `"want interface{} here"`)
	assert.Contains(t, fixed["a.go"], "var x interface{}\n", "raw string content is data")
	assert.Contains(t, fixed["a.go"], "C func(any) any")
	assert.Contains(t, fixed["a.go"], "fmt.Print(map[string]any{}, raw)")
	assert.Equal(t, 2, strings.Count(fixed["a.go"], "interface{}"))
}

// A module older than Go 1.18 has no any: nothing may be rewritten to it.
func TestRoundTripInterfaceAnyOldModule(t *testing.T) {
	fixed := roundTrip(t, map[string]string{
		"go.mod": "module example.com/projecta\n\ngo 1.16\n",
		"p/p.go": `package p

// V holds a value.
var V interface{}
`,
	})

	assert.Contains(t, fixed["p/p.go"], "var V interface{}")
}

// A file with CRLF line endings keeps them.
func TestRoundTripKeepsCRLF(t *testing.T) {
	source := strings.ReplaceAll(`package projecta

import (
	"fmt"
)

// Keys returns keys.
func Keys(m map[string]int) []string {
	var out []string
	for k, v := range m {
		out = append(out, fmt.Sprint(k, v))
	}
	return out
}
`, "\n", "\r\n")
	fixed := roundTrip(t, map[string]string{"go.mod": modGo123, "c.go": source})

	assert.Contains(t, fixed["c.go"], "range slices.Sorted(maps.Keys(m))")
	assert.Equal(t, strings.Count(fixed["c.go"], "\n"), strings.Count(fixed["c.go"], "\r\n"), "every line must keep CRLF")
}

// A label line gets both a hard line break and a blank line before the list
// that follows it; both fixes land in one run, CRLF lines included.
func TestRoundTripMarkdownLabelsBeforeList(t *testing.T) {
	readme := "# T\n\n**Version:** 1.0\n**Owner:** me\n**Items:**\n- one\n- two\n"
	want := "# T\n\n**Version:** 1.0  \n**Owner:** me  \n**Items:**\n\n- one\n- two\n"
	rules := []string{"md-line-break", "md-list-after-label"}

	fixed := roundTripWith(t, map[string]string{"go.mod": modGo123, "doc.go": "package projecta\n", "README.md": readme}, rules)
	assert.Equal(t, want, fixed["README.md"])

	crlf := strings.ReplaceAll(readme, "\n", "\r\n")
	fixed = roundTripWith(t, map[string]string{"go.mod": modGo123, "doc.go": "package projecta\n", "README.md": crlf}, rules)
	assert.Equal(t, strings.ReplaceAll(want, "\n", "\r\n"), fixed["README.md"])
}

package depgraph

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The holes fixture extends the small glint with what a cached finding can
// depend on beyond the calls a rule makes: the order of initialization, the
// files a go:embed directive names, methods the standard library or another
// module calls by name or through an interface it never declares, and state
// another rule writes.
const holesProbe = `package check

import (
	"bytes"
	"fmt"
	"text/template"

	"example.com/ext"
	"example.com/lint/pkg/core"
	"example.com/lint/pkg/rules"
)

func init() { rules.Register(newProbeRule()) }

type ProbeRule struct{ *rules.Base }

func newProbeRule() *ProbeRule { return &ProbeRule{Base: rules.NewBase("probe")} }

func (r *ProbeRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	msg := hook + order + order2 + embedA + fmt.Sprint(deep0{}) + render() + viaPtr() + viaBox() + ext.Show(shown{}) + ext.Probe(flavored{})
	return []*core.Violation{{Message: msg}}
}

var order string

func init() { order = "first" }

func init() { order = "second" }

type deep0 struct{ In deep1 }
type deep1 struct{ In deep2 }
type deep2 struct{ In deep3 }
type deep3 struct{ In deep4 }
type deep4 struct{ In deep5 }
type deep5 struct{ V int }

func (deep5) String() string { return "deep-one" }

type view struct{}

func (view) Label() string { return "label-one" }

var page = template.Must(template.New("p").Parse("{{.Label}}"))

func render() string {
	var b bytes.Buffer
	_ = page.Execute(&b, view{})
	return b.String()
}

type state struct{ v string }

func (s *state) set(v string) { s.v = v }

var shared = &state{}

func viaPtr() string { return shared.v }

var boxed string

type box[T any] struct{ v T }

func (b box[T]) put(v string) { boxed = v + fmt.Sprint(b.v) }

func viaBox() string { return boxed }

type shown struct{}

func (shown) String() string { return "shown-one" }

type flavored struct{}

func (flavored) Flavor() string { return "flavor-one" }
`

const holesWriter = `package check

import (
	"example.com/lint/pkg/core"
	"example.com/lint/pkg/rules"
)

func init() { rules.Register(&WriterRule{Base: rules.NewBase("writer")}) }

type WriterRule struct{ *rules.Base }

func (r *WriterRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	shared.set("w-one")
	box[int]{}.put("b-one")
	return nil
}
`

// A rule that sets a variable through a setter: the value is its own.
const holesSetter = `package check

import (
	"example.com/lint/pkg/core"
	"example.com/lint/pkg/rules"
)

func init() { rules.Register(&SetterRule{Base: rules.NewBase("setter")}) }

type SetterRule struct{ *rules.Base }

func (r *SetterRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	setHook("h-one")
	return nil
}

var hook string

func setHook(v string) { hook = v }
`

const holesEmbed = `package check

import _ "embed"

//go:embed probe_a.txt
var embedA string

//go:embed probe_b.txt
var embedB string
`

const holesExt = `package ext

import "fmt"

// Show prints any value: fmt calls its String method.
func Show[T any](t T) string { return fmt.Sprint(t) }

// Probe calls Flavor through an interface no package declares.
func Probe(v any) string {
	if f, ok := v.(interface{ Flavor() string }); ok {
		return f.Flavor()
	}
	return ""
}
`

func holesFixture() map[string]string {
	files := maps.Clone(fixture)
	files["go.mod"] = "module example.com/lint\n\ngo 1.24\n\nrequire example.com/ext v0.0.0\n\nreplace example.com/ext => ./ext\n"
	files["ext/go.mod"] = "module example.com/ext\n\ngo 1.24\n"
	files["ext/ext.go"] = holesExt
	files["pkg/rules/check/probe.go"] = holesProbe
	files["pkg/rules/check/writer.go"] = holesWriter
	files["pkg/rules/check/embed.go"] = holesEmbed
	files["pkg/rules/check/setter.go"] = holesSetter
	files["pkg/rules/check/probe_a.txt"] = "alpha\n"
	files["pkg/rules/check/probe_b.txt"] = "beta\n"
	files["pkg/rules/check/za.go"] = "package check\n\nfunc init() { order2 = \"za\" }\n"
	files["pkg/rules/check/zb.go"] = "package check\n\nvar order2 string\n\nfunc init() { order2 = \"zb\" }\n"
	return files
}

// siteIn returns the site of the Register call on the line of files[file]
// holding text.
func siteIn(t *testing.T, result *Result, files map[string]string, file, text string) Site {
	t.Helper()
	lines := strings.Split(files[file], "\n")
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

// probeKey is what keys the cached findings of the probe rule: the driver
// and the rule's own scope.
func probeKey(t *testing.T, files map[string]string) string {
	t.Helper()
	result := analyzeFixture(t, files)
	return result.Driver + " " + siteIn(t, result, files, "pkg/rules/check/probe.go", "rules.Register(").Hash
}

func TestEditsThatChangeAFindingChangeItsKey(t *testing.T) {
	base := holesFixture()
	before := probeKey(t, base)
	edit := func(name, old, next string) map[string]string { return with(base, name, old, next) }
	renamed := maps.Clone(base)
	renamed["pkg/rules/check/a0.go"] = renamed["pkg/rules/check/zb.go"]
	delete(renamed, "pkg/rules/check/zb.go")
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"control: the rule's own code", edit("pkg/rules/check/probe.go", "msg := hook", "msg := \"!\" + hook")},
		{"the go:embed directives of two variables swapped",
			edit("pkg/rules/check/embed.go", "//go:embed probe_a.txt\nvar embedA string\n\n//go:embed probe_b.txt\nvar embedB string",
				"//go:embed probe_b.txt\nvar embedA string\n\n//go:embed probe_a.txt\nvar embedB string")},
		{"two init functions of one file swapped",
			edit("pkg/rules/check/probe.go", "func init() { order = \"first\" }\n\nfunc init() { order = \"second\" }",
				"func init() { order = \"second\" }\n\nfunc init() { order = \"first\" }")},
		{"a file with an init renamed, so it initializes first", renamed},
		{"String of a type five levels deep in a value fmt prints", edit("pkg/rules/check/probe.go", `return "deep-one"`, `return "deep-two"`)},
		{"a method text/template calls by its name", edit("pkg/rules/check/probe.go", `return "label-one"`, `return "label-two"`)},
		{"a pointer method another rule writes shared state with", edit("pkg/rules/check/probe.go", "s.v = v", "s.v = v + \"!\"")},
		{"the value another rule writes into shared state", edit("pkg/rules/check/writer.go", `shared.set("w-one")`, `shared.set("w-two")`)},
		{"the value another rule passes to a setter of a variable", edit("pkg/rules/check/setter.go", `setHook("h-one")`, `setHook("h-two")`)},
		{"a method of a generic type another rule writes a variable with", edit("pkg/rules/check/writer.go", `put("b-one")`, `put("b-two")`)},
		{"String of a value a generic function of another module prints", edit("pkg/rules/check/probe.go", `return "shown-one"`, `return "shown-two"`)},
		{"a method another module calls through an interface it does not declare", edit("pkg/rules/check/probe.go", `return "flavor-one"`, `return "flavor-two"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEqual(t, before, probeKey(t, tc.files))
		})
	}
	t.Run("control: a comment", func(t *testing.T) {
		assert.Equal(t, before, probeKey(t, edit("pkg/rules/check/probe.go", "var order string", "// order is set by init.\nvar order string")))
	})
}

// Two rules registered on one line: the run finds a rule's site by the line
// it was registered on, so both keys cover both rules.
func TestRulesRegisteredOnOneLineShareTheirKey(t *testing.T) {
	files := maps.Clone(fixture)
	files["pkg/rules/check/pair.go"] = `package check

import (
	"example.com/lint/pkg/core"
	"example.com/lint/pkg/rules"
)

type OneRule struct{ *rules.Base }

func (r *OneRule) AnalyzeFile(*core.FileContext) []*core.Violation { return []*core.Violation{{Message: "one"}} }

type TwoRule struct{ *rules.Base }

func (r *TwoRule) AnalyzeFile(*core.FileContext) []*core.Violation { return []*core.Violation{{Message: "two"}} }

func init() { rules.Register(&OneRule{Base: rules.NewBase("one")}); rules.Register(&TwoRule{Base: rules.NewBase("two")}) }
`
	key := func(files map[string]string) []string {
		result := analyzeFixture(t, files)
		var keys []string
		for _, s := range result.Sites {
			if strings.HasSuffix(s.File, "/pair.go") {
				keys = append(keys, s.Hash)
			}
		}
		require.Len(t, keys, 2)
		return keys
	}
	before := key(files)
	for _, edit := range [][2]string{{`"one"}}`, `"one!"}}`}, {`"two"}}`, `"two!"}}`}} {
		after := key(with(files, "pkg/rules/check/pair.go", edit[0], edit[1]))
		for i := range before {
			assert.NotEqual(t, before[i], after[i], "the site the run may take for either rule changes with %s", edit[1])
		}
	}
}

// A //go:linkname directive binds a declaration to code the call graph does
// not see: every rule is keyed by the whole module.
func TestALinknameDirectiveKeysEveryRuleByTheModule(t *testing.T) {
	files := with(fixture, "pkg/core/core.go", "type Violation struct{ Message string }",
		"type Violation struct{ Message string }\n\n//go:linkname coreLines\nfunc coreLines(c *FileContext) int { return len(c.Text) }\n")
	files["pkg/core/core.go"] = strings.Replace(files["pkg/core/core.go"], "package core\n", "package core\n\nimport _ \"unsafe\"\n", 1)
	result := analyzeFixture(t, files)
	require.NotEmpty(t, result.Sites)
	for _, s := range result.Sites {
		assert.Equal(t, result.All, s.Hash, "%s:%d", s.File, s.From)
	}
}

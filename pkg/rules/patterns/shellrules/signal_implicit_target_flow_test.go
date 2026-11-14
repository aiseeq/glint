package shellrules

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signalWantLines are the lines of source marked // WANT (not WANT-NONE).
func signalWantLines(source string) []int {
	var want []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// WANT") && !strings.Contains(line, "WANT-NONE") {
			want = append(want, i+1)
		}
	}
	return want
}

func assertSignalWanted(t *testing.T, source string) {
	t.Helper()
	file, pkg := signalSourceTyped(t, "flow_test.go", source)
	assert.Equal(t, signalWantLines(source), rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

// A table string handed in a struct field to a validator that copies it into
// another struct and reads it as text (strings, regexp, a recursive walk, a
// logger declared in the package) is data. The same field handed to a shell,
// to os/exec as a program or to a package without a body is not. Each table
// has its own function: fields are tracked by type, so a sibling use of the
// same struct type in one function would count too.
func TestSignalImplicitTargetRangeStructFields(t *testing.T) {
	assertSignalWanted(t, `package sample
import (
 "os/exec"
 "regexp"
 "strings"
 "example.com/runner"
)
type toolInput struct { Name, Command string }
type scan struct { text string; reasons []string }
type logger interface { Warn(msg string, args ...any); With(args ...any) logger }
type quietLogger struct{}
func (quietLogger) Warn(string, ...any) {}
func (q quietLogger) With(...any) logger { return q }
type validator struct{ log logger }
var words = regexp.MustCompile("kill")
func (s *scan) add(reason string) { s.reasons = append(s.reasons, reason) }
func (s *scan) walk(text string, depth int) {
 if depth > 2 { return }
 for _, part := range strings.Split(text, ";") {
  if words.MatchString(part) { s.add("signal: " + strings.TrimSpace(part)) }
  s.walk(part, depth+1)
 }
}
func (v validator) Validate(in *toolInput) []string {
 if in.Name != "Bash" { return nil }
 s := scan{text: in.Command}
 s.walk(s.text, 0)
 v.log.Warn("checked", "command", in.Command)
 return s.reasons
}
func (validator) run(in *toolInput) { _ = exec.Command("sh", "-c", in.Command).Run() }
func (validator) program(in *toolInput) { _ = exec.Command(in.Command).Run() }
func (validator) opaque(in *toolInput) { runner.Run(in.Command) }
func validate(command string) []string { return validator{log: quietLogger{}}.Validate(&toolInput{Name: "Bash", Command: command}) }
func literal() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = validate(s) } } // WANT-NONE
func variable() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { in := toolInput{Name: "Bash", Command: s}; _ = (validator{log: quietLogger{}}).Validate(&in) } } // WANT-NONE
func shell() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { (validator{}).run(&toolInput{Command: s}) } } // WANT
func shellVariable() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { in := toolInput{Command: s}; (validator{}).run(&in) } } // WANT
func lone() { for _, s := range []string{"kill -9 -1"} { (validator{}).run(&toolInput{Command: s}) } } // WANT
func program() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { (validator{}).program(&toolInput{Command: s}) } } // WANT
func hidden() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { (validator{}).opaque(&toolInput{Command: s}) } } // WANT
`)
}

// A store the analysis cannot keep within the code it follows - a
// package-level variable, memory behind a pointer it did not allocate - may
// be read and run elsewhere.
func TestSignalImplicitTargetRangeStoresBeyondTheAnalysis(t *testing.T) {
	assertSignalWanted(t, `package sample
import (
 "os/exec"
 "strings"
)
type record struct{ command string }
var global record
var shared *record
func set(r *record, s string) { r.command = s }
func pointer() *record { return shared }
func toGlobal() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { global.command = s } } // WANT
func throughParameter() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { set(&global, s) } } // WANT
func throughAlias() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { p := &global; p.command = s } } // WANT
func throughCall() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { pointer().command = s } } // WANT
func local() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { var r record; set(&r, s); _ = strings.TrimSpace(r.command) } } // WANT-NONE
func fresh() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { r := &record{}; set(r, s); _ = strings.TrimSpace(r.command) } } // WANT-NONE
func later() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { r := &record{}; set(r, s); _ = exec.Command("sh", "-c", r.command).Run() } } // WANT
`)
}

// A builder a helper writes the value into carries it on; a writer that is
// not memory may be a shell's stdin; a callback runs with the value where the
// analysis does not look.
func TestSignalImplicitTargetRangeWritersAndCallbacks(t *testing.T) {
	assertSignalWanted(t, `package sample
import (
 "fmt"
 "io"
 "os/exec"
 "strings"
 "testing"
 "unicode"
)
func write(b *strings.Builder, s string) { b.WriteString(s) }
func builder() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { var b strings.Builder; write(&b, s); _ = exec.Command("sh", "-c", b.String()).Run() } } // WANT
func builderText() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { var b strings.Builder; write(&b, s); _ = strings.Contains(b.String(), "kill") } } // WANT-NONE
func memory() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { var b strings.Builder; fmt.Fprintln(&b, s); _ = exec.Command("sh", "-c", b.String()).Run() } } // WANT
func writer(w io.Writer) { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { fmt.Fprintln(w, s) } } // WANT
func closure() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = strings.Map(func(r rune) rune { return r }, s) } } // WANT
func function() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = strings.FieldsFunc(s, unicode.IsSpace) } } // WANT-NONE
func key() { seen := map[string]bool{}; for _, s := range []string{"bash -c 'kill -9 $PPID'"} { seen[s] = true }; for k := range seen { _ = exec.Command("sh", "-c", k).Run() } } // WANT
func subtest(t *testing.T) { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run(s, func(t *testing.T) { t.Log(s) }) } } // WANT-NONE
`)
}

// A call of an interface method reaches every implementation in the
// package; an interface whose methods name no type of its package may be
// implemented outside it.
func TestSignalImplicitTargetRangeInterfaceMethods(t *testing.T) {
	assertSignalWanted(t, `package sample
import (
 "os/exec"
 "strings"
)
type runner interface { Run(cmd string); Self() runner }
type shell struct{}
func (shell) Run(cmd string) { _ = exec.Command("sh", "-c", cmd).Run() }
func (s shell) Self() runner { return s }
type printer struct{}
func (printer) Run(cmd string) { _ = strings.TrimSpace(cmd) }
func (p printer) Self() runner { return p }
type checker interface { Check(cmd string); Self() checker }
type plain struct{}
func (plain) Check(cmd string) { _ = strings.TrimSpace(cmd) }
func (p plain) Self() checker { return p }
type open interface { Check(cmd string) }
func viaRunner(r runner) { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { r.Run(s) } } // WANT
func viaChecker(c checker) { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { c.Check(s) } } // WANT-NONE
func viaOpen(o open) { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { o.Check(s) } } // WANT
`)
}

func TestSignalImplicitTargetRangeRecursion(t *testing.T) {
	assertSignalWanted(t, `package sample
import (
 "os/exec"
 "strings"
)
func split(text string, depth int) int {
 if depth > 3 { return 0 }
 n := 0
 for _, part := range strings.Fields(text) { n += split(part, depth+1) }
 return n + len(text)
}
func nested(text string, depth int) {
 if depth > 0 { _ = exec.Command("sh", "-c", text).Run(); return }
 nested(text, depth+1)
}
func parse() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = split(s, 0) } } // WANT-NONE
func run() { for _, s := range []string{"bash -c 'kill -9 $PPID'"} { nested(s, 0) } } // WANT
`)
}

func TestSignalImplicitTargetRangeStructDepth(t *testing.T) {
	var source strings.Builder
	source.WriteString("package sample\ntype input struct { Command string }\n")
	for i := range 8 {
		source.WriteString("func helper" + strconv.Itoa(i) + "(in *input) {")
		if i < 7 {
			source.WriteString(" helper" + strconv.Itoa(i+1) + "(in)")
		}
		source.WriteString(" }\n")
	}
	source.WriteString("func tables() { for _, s := range []string{\"bash -c 'kill -9 $PPID'\"} { helper0(&input{Command:s}) } } // WANT\n")
	assertSignalWanted(t, source.String())
}

// A function the depth limit cuts on a long path is known in full from a
// shorter one with the same classes: what it does does not depend on depth.
func TestSignalImplicitTargetRangeDepthReusesShorterPath(t *testing.T) {
	var source strings.Builder
	source.WriteString("package sample\n")
	for i := range 8 {
		source.WriteString("func helper" + strconv.Itoa(i) + "(command string) {")
		if i < 7 {
			source.WriteString(" helper" + strconv.Itoa(i+1) + "(command)")
		}
		source.WriteString(" }\n")
	}
	source.WriteString("func tables() { for _, s := range []string{\"bash -c 'kill -9 $PPID'\"} { helper0(s); helper7(s) } } // WANT-NONE\n")
	assertSignalWanted(t, source.String())
}

// A parser package is read as data only while its own source imports nothing
// that can start a process.
func TestSignalImplicitTargetRangeParserPackageSource(t *testing.T) {
	for _, tc := range []struct {
		name, imports string
		wantFinding   bool
	}{
		{name: "parser", imports: `import "strings"`},
		{name: "runs processes", imports: `import "os/exec"`, wantFinding: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "shellcmd.go")
			require.NoError(t, os.WriteFile(path, []byte("package shellcmd\n"+tc.imports+"\n"), 0o600))
			source := "package sample\nimport \"github.com/aiseeq/akit/shellcmd\"\n" +
				"func tables() { for _, s := range []string{\"bash -c 'kill -9 $PPID'\"} { _ = shellcmd.Calls(s) } }\n"
			fset := token.NewFileSet()
			pos := fset.AddFile(path, -1, 64).Pos(0)
			parsed, err := parser.ParseFile(fset, "parser_test.go", source, parser.AllErrors)
			require.NoError(t, err)
			info := &types.Info{
				Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
				Uses: make(map[*ast.Ident]types.Object), Selections: make(map[*ast.SelectorExpr]*types.Selection),
			}
			_, err = (&types.Config{Importer: shellcmdTestImporter{pos: pos}}).Check("example.com/sample", fset, []*ast.File{parsed}, info)
			require.NoError(t, err)
			file := core.NewFileContext("parser_test.go", ".", []byte(source), nil)
			file.GoAST, file.GoFileSet, file.GoTypesInfo = parsed, fset, info
			got := rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, newSignalPackage("example.com/sample", info, parsed)))
			if tc.wantFinding {
				assert.Equal(t, []int{3}, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

// shellcmdTestImporter declares shellcmd.Calls(string) int at pos.
type shellcmdTestImporter struct{ pos token.Pos }

func (i shellcmdTestImporter) Import(path string) (*types.Package, error) {
	if path != "github.com/aiseeq/akit/shellcmd" {
		return importer.Default().Import(path)
	}
	pkg := types.NewPackage(path, "shellcmd")
	params := types.NewTuple(types.NewVar(token.NoPos, pkg, "cmd", types.Typ[types.String]))
	results := types.NewTuple(types.NewVar(token.NoPos, pkg, "", types.Typ[types.Int]))
	pkg.Scope().Insert(types.NewFunc(i.pos, pkg, "Calls", types.NewSignatureType(nil, nil, nil, params, results, false)))
	pkg.MarkComplete()
	return pkg, nil
}

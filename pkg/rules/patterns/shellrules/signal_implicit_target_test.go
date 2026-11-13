package shellrules

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignalImplicitTargetShell(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "signal.sh", `#!/bin/sh
kill "$PPID" # want
kill -TERM -1 # want
kill -1 "$pid"
kill -0 "$PPID"
echo "kill $PPID"
bash <<'EOF'
kill -9 ${PPID} # want
EOF
`)
}

func TestSignalImplicitTargetCommandFormsAndQuotedText(t *testing.T) {
	assert.Empty(t, shellCommands(`grep -q "x;kill $PPID" run.log`))
	shellWanted(t, "signal-implicit-target", "forms.sh", `#!/bin/bash
  if kill 0; then :; fi # want
while kill 0; do :; done # want
until kill 0; do :; done # want
! kill 0 # want
(kill 0) # want
FOO=1 kill 0 # want
sudo kill 0 # want
exec kill 0 # want
command kill 0 # want
builtin kill 0 # want
nohup kill 0 # want
timeout 5 kill 0 # want
/bin/kill 0 # want
/usr/bin/kill 0 # want
echo "a; kill 0"
grep 'x|kill 0'
log "then kill -9 -1"
sh -c "kill 0" # want
bash -c 'kill -9 -1' # want
trap "kill -TERM $PPID" EXIT # want
`)
}

func TestSignalImplicitTargetParentChecksAndHeredocs(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "checks.sh", `#!/bin/bash
cat /proc/$PPID/comm
kill "$PPID" # want
cat /proc/$PPID/comm >> log
kill "$PPID" # want
parent_comm=$(cat /proc/$PPID/comm)
kill "$PPID" # want
if [ "$(cat /proc/$PPID/comm)" = runner ]; then
  kill "$PPID" # want
fi
if ps -p "$PPID" | grep -q runner; then
  kill "$PPID" # want
fi
if [ -e /proc/$PPID/exe ]; then kill "$PPID"; fi # want
if [ -e /proc/$PPID/cmdline ]; then kill "$PPID"; fi # want
if [ -e /proc/$PPID/fd/2 ]; then kill "$PPID"; fi # want
if [ -e /proc/$PPID/comm ]; then
  :
  :
  :
  :
  kill "$PPID" # want
fi
if [ -e /proc/$PPID/comm ]; then
  :
fi
kill "$PPID" # want
cat > note.md <<EOF
kill 0
kill -9 -1
EOF
bash <<EOF
kill 0 # want
EOF
ssh host <<EOF
kill -9 -1 # want
EOF
cat > stub <<EOF
#!/bin/sh
kill 0 # want
EOF
`)
}

func TestSignalImplicitTargetHeredocArithmeticAndQuotedLines(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "logical.sh", `#!/bin/bash
MSG="message begins
kill 0
ends here"
git commit -m "message begins
kill 0 is only text"
cat <<\EOF
kill 0 |
EOF
cat <<<EOF
kill 0 # want
cat <<EOF
kill 0
EOF
n=$((1 << 4))
kill 0 # want
(( n <<= 1 ))
kill 0 # want
echo "text <<EOF"
kill 0 # want
`)
}

func TestSignalImplicitTargetParentChecksDoNotExcuseSignal(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "parent-check.sh", `#!/bin/bash
if [ "$(cat /proc/$PPID/comm)" = runner ]; then kill "$PPID"; fi # want
if [ "$(cat /proc/$PPID/comm)" = runner ]; then kill 0; fi # want
if [ "$(cat /proc/$PPID/comm)" != runner ]; then kill "$PPID"; fi # want
if [ "$(cat /proc/$PPID/comm)" -ne runner ]; then kill "$PPID"; fi # want
if ! grep runner /proc/$PPID/comm; then kill "$PPID"; fi # want
grep -v runner /proc/$PPID/cmdline && kill "$PPID" # want
grep runner /proc/$PPID/cmdline || kill "$PPID" # want
grep runner /proc/$PPID/cmdline && kill "$PPID" # want
if grep runner /proc/$PPID/cmdline; then kill "$PPID"; fi # want
[ -r /proc/$PPID/comm ] && kill "$PPID" # want
parent="$(cat /proc/$PPID/comm)"
kill "$PPID" # want
if [ "$(cat /proc/$PPID/comm)" = runner ]; then :; fi; kill "$PPID" # want
if [ "$(cat /proc/$PPID/comm)" = runner ]; then kill -9 -1; fi # want
`)
}

func TestSignalImplicitTargetMakeHeredocBodyDoesNotContinue(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "Makefile", `all:
	cat <<EOF
	kill 0 |
	EOF
	kill 0 # want
`)
}

func TestSignalImplicitTargetGoScriptClassificationAndText(t *testing.T) {
	source := `package sample
import (
	"errors"
  "fmt"
  "log"
	"log/slog"
  "testing"
)
const help = "Usage:\nkill 0 is an example"
const prompt = ` + "`" + `kill 0 is only prose` + "`" + `
const script = ` + "`" + `#!/bin/sh
cat > README <<EOF
kill 0 is data
EOF
kill 0
` + "`" + ` // want
const command = "a; kill 1; kill 0" // want
const inlineKill = "kill 1; kill 0" // want
const singleLineShebang = "#!/bin/sh\nkill 0" // want
func report(t *testing.T) {
  fmt.Print("a; kill 0")
  fmt.Printf("a; kill 0")
  fmt.Println("a; kill 0")
  fmt.Fprint(nil, "a; kill 0")
  fmt.Fprintf(nil, "a; kill 0")
  fmt.Fprintln(nil, "a; kill 0")
  fmt.Sprint("a; kill 0")
  fmt.Sprintf("a; kill 0")
  fmt.Errorf("a; kill 0")
  fmt.Sprintln("a; kill -9 -1")
  log.Println("a; kill 0")
  slog.Error("a; kill 0")
  _ = errors.New("a; kill 0")
  t.Errorf("a; kill 0")
  t.Error("a; kill 0")
  t.Fatalf("a; kill 0")
  t.Fatal("a; kill 0")
  t.Logf("a; kill 0")
  t.Log("a; kill 0")
  t.Skipf("a; kill 0")
}
`
	file := core.NewFileContext("prose.go", ".", []byte(source), nil)
	file.GoFileSet = token.NewFileSet()
	file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
	assert.Equal(t, []int{15, 17, 18, 19}, rulestest.ViolationLines(newSignalImplicitTargetRule().goFile(file, nil)))
}

func TestSignalImplicitTargetDoesNotTreatOtherGetppidAsOS(t *testing.T) {
	source := `package sample
import "syscall"
func Getppid() int { return 42 }
func stop() { _ = syscall.Kill(Getppid(), syscall.SIGTERM) }
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "other.go", source, parser.AllErrors)
	require.NoError(t, err)
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	_, err = (&types.Config{Importer: importer.Default()}).Check("example.com/sample", fset, []*ast.File{parsed}, info)
	require.NoError(t, err)
	file := core.NewFileContext("other.go", ".", []byte(source), nil)
	file.GoAST, file.GoFileSet, file.GoTypesInfo = parsed, fset, info
	assert.Empty(t, newSignalImplicitTargetRule().goFile(file, newSignalPackage("", info, parsed)))
}

func TestSignalImplicitTargetGoExecutedHeredocIsNotScriptData(t *testing.T) {
	source := `package sample
import "os/exec"
func run() {
  _ = exec.Command("bash", "-c", "cat > README <<EOF\nkill 0\nEOF").Run()
  _ = exec.Command("sh", "-c", "echo start; kill -9 -1").Run() // want
}
`
	file := core.NewFileContext("run.go", ".", []byte(source), nil)
	file.GoFileSet = token.NewFileSet()
	file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
	assert.Equal(t, []int{5}, rulestest.ViolationLines(newSignalImplicitTargetRule().goFile(file, nil)))
}

func TestSignalImplicitTargetGoSuggestionNamesExplicitChildPID(t *testing.T) {
	source := "package sample\n\nfunc stop() {}\n"
	file := core.NewFileContext("run.go", ".", []byte(source), nil)
	file.GoFileSet = token.NewFileSet()
	file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
	v := signalViolationAt(newSignalImplicitTargetRule(), file, 3)
	assert.Contains(t, v.Suggestion, "returning an error or exit code")
	assert.Contains(t, v.Suggestion, "cmd.Process")
}

func TestSignalImplicitTargetShellSuggestionPrefersNormalExit(t *testing.T) {
	file := core.NewFileContext("stop.sh", ".", []byte("#!/bin/sh\nkill \"$PPID\"\n"), nil)
	v := signalViolationAt(newSignalImplicitTargetRule(), file, 2)
	assert.Contains(t, v.Suggestion, "exit with a status code")
	assert.Contains(t, v.Suggestion, "PID from $!")
}

func TestSignalImplicitTargetProbeSignalsAndExpansions(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "probe.sh", `#!/bin/sh
kill -n 0 "$PPID"
kill -s0 "$PPID"
kill -s 0 "$PPID"
kill --signal 0 "$PPID"
kill --signal=0 "$PPID"
kill -SIG0 "$PPID"
kill -l 0
kill -L
kill -n 15 -1 # want
kill -s TERM 0 # want
kill $(pgrep -P $PPID)
kill -9 `+"`pgrep -P $PPID`"+`
`)
}

func TestSignalImplicitTargetGoLiterals(t *testing.T) {
	source := "package sample\nconst script = `#!/bin/sh\nkill -9 $PPID\necho done\n`\nfunc text() { println(\"kill $PPID failed\") }\n"
	file := core.NewFileContext("signal.go", ".", []byte(source), nil)
	file.GoFileSet = token.NewFileSet()
	file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
	assert.Equal(t, []int{3}, rulestest.ViolationLines(newSignalImplicitTargetRule().goFile(file, nil)))
}

func TestSignalImplicitTargetTestFileCommandData(t *testing.T) {
	source := `package sample
import "os/exec"
var guardInputs = []string{"kill -9 -1"}
func stop() { _ = exec.Command("sh", "-c", "kill -9 -1") }
`
	file := core.NewFileContext("guard_test.go", ".", []byte(source), nil)
	file.GoFileSet = token.NewFileSet()
	file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
	assert.Equal(t, []int{4}, rulestest.ViolationLines(newSignalImplicitTargetRule().goFile(file, nil)))
}

func TestSignalImplicitTargetGoLiteralContexts(t *testing.T) {
	source := `package sample
import (
  "fmt"
  "os/exec"
)
var data = "kill -9 -1"
var script = "sleep 1; kill -9 -1" // want
func report() { fmt.Println("stopping; kill 0"); fmt.Errorf("then kill 0") }
func stop(ctx context.Context) {
  _ = exec.CommandContext(ctx, "/bin/bash", "-c", "kill 0")
}
`
	file := core.NewFileContext("guard_test.go", ".", []byte(source), nil)
	file.GoFileSet = token.NewFileSet()
	file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
	assert.Equal(t, []int{7, 10}, rulestest.ViolationLines(newSignalImplicitTargetRule().goFile(file, nil)))
}

func TestSignalImplicitTargetAlwaysKeepsShellRoots(t *testing.T) {
	_, ok := any(newSignalImplicitTargetRule()).(rules.GoProjectRule)
	assert.True(t, ok)
}

func TestSignalImplicitTargetTypedPackageCallsAndProcessHandles(t *testing.T) {
	source := `package sample
import (
  "os"
  "syscall"
  "golang.org/x/sys/unix"
)
func send() {
  parentPID := os.Getppid()
  _ = syscall.Kill(parentPID, syscall.SIGTERM) // want
  parent, _ := os.FindProcess(os.Getppid())
  _ = parent.Signal(syscall.SIGTERM) // want
  other, _ := os.FindProcess(os.Getppid())
  _ = other.Kill() // want
  _ = unix.Kill(os.Getppid(), unix.SIGTERM) // want
  _ = unix.Kill(0, 0)
}
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "typed.go", source, parser.AllErrors)
	require.NoError(t, err)
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	_, err = (&types.Config{Importer: signalTestImporter{base: importer.Default()}}).Check("example.com/sample", fset, []*ast.File{parsed}, info)
	require.NoError(t, err)
	file := core.NewFileContext("typed.go", ".", []byte(source), nil)
	file.GoAST, file.GoFileSet, file.GoTypesInfo = parsed, fset, info
	violations := newSignalImplicitTargetRule().goFile(file, newSignalPackage("", info, parsed))
	assert.Equal(t, []int{9, 11, 13, 14}, rulestest.ViolationLines(violations))
	assert.Contains(t, violations[0].Suggestion, "cmd.Process")
}

func TestSignalImplicitTargetTgkillSecondTargetAndPackageLiteral(t *testing.T) {
	source := `package sample
import (
	"os"
	"syscall"
)
func send(pid, tid int) {
	_ = syscall.Tgkill(pid, 0, syscall.SIGTERM) // want
	_ = syscall.Tgkill(os.Getppid(), tid, syscall.SIGTERM) // want
	_ = syscall.Tgkill(os.Getpid(), 0, syscall.SIGTERM) // want
}
var sendGroup = func() {
	_ = syscall.Tgkill(0, 21, syscall.SIGTERM) // want
}
`
	file, pkg := rawProcessTypedFile(t, "tgkill.go", "example.com/sample", source)
	findings := newSignalImplicitTargetRule().goFile(file, pkg)
	assert.Equal(t, []int{7, 8, 9, 12}, rulestest.ViolationLines(findings))
}

func TestSignalImplicitTargetSkipsTypedCallsWithoutTypes(t *testing.T) {
	source := "package sample\nimport (\"os\"; \"syscall\")\nfunc send() { _ = syscall.Kill(os.Getppid(), syscall.SIGTERM) }\n"
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "untyped.go", source, parser.AllErrors)
	require.NoError(t, err)
	file := core.NewFileContext("untyped.go", ".", []byte(source), nil)
	file.GoAST, file.GoFileSet = parsed, fset
	assert.Empty(t, newSignalImplicitTargetRule().goFile(file, nil))
}

type signalTestImporter struct{ base types.Importer }

func (i signalTestImporter) Import(path string) (*types.Package, error) {
	if path != "golang.org/x/sys/unix" && path != "example.com/other" && path != "github.com/aiseeq/akit/proc" {
		return i.base.Import(path)
	}
	syscall, err := i.base.Import("syscall")
	if err != nil {
		return nil, err
	}
	pkg := types.NewPackage(path, filepath.Base(path))
	if path == "github.com/aiseeq/akit/proc" {
		params := types.NewTuple(
			types.NewVar(token.NoPos, pkg, "pid", types.Typ[types.Int]),
			types.NewVar(token.NoPos, pkg, "grace", types.Typ[types.Int]),
			types.NewVar(token.NoPos, pkg, "request", types.NewSignatureType(nil, nil, nil, nil, nil, false)),
		)
		fn := types.NewSignatureType(nil, nil, nil, params, nil, false)
		pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "StopChild", fn))
		execPkg, err := i.base.Import("os/exec")
		if err != nil {
			return nil, err
		}
		timePkg, err := i.base.Import("time")
		if err != nil {
			return nil, err
		}
		cmdType := types.NewPointer(execPkg.Scope().Lookup("Cmd").Type())
		for _, name := range []string{"CancelByStop", "CancelByStopWithObserver"} {
			cancelParams := []*types.Var{
				types.NewVar(token.NoPos, pkg, "cmd", cmdType),
				types.NewVar(token.NoPos, pkg, "grace", timePkg.Scope().Lookup("Duration").Type()),
				types.NewVar(token.NoPos, pkg, "sig", syscall.Scope().Lookup("Signal").Type()),
			}
			if name == "CancelByStopWithObserver" {
				cancelParams = append(cancelParams, types.NewVar(token.NoPos, pkg, "observer", types.NewSignatureType(nil, nil, nil, nil, nil, false)))
			}
			cancelSig := types.NewSignatureType(nil, nil, nil, types.NewTuple(cancelParams...), types.NewTuple(types.NewVar(token.NoPos, pkg, "", types.Universe.Lookup("error").Type())), false)
			pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, name, cancelSig))
		}
		pkg.MarkComplete()
		return pkg, nil
	}
	pid := types.NewSignatureType(nil, nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, pkg, "", types.Typ[types.Int])), false)
	if path == "example.com/other" {
		pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "Getppid", pid))
	} else {
		pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "Getpid", pid))
	}
	signal := syscall.Scope().Lookup("Signal").Type()
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "SIGTERM", signal, constant.MakeInt64(15)))
	params := types.NewTuple(types.NewVar(token.NoPos, pkg, "pid", types.Typ[types.Int]), types.NewVar(token.NoPos, pkg, "sig", signal))
	results := types.NewTuple(types.NewVar(token.NoPos, pkg, "", types.Universe.Lookup("error").Type()))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "Kill", types.NewSignatureType(nil, nil, nil, params, results, false)))
	tgkillParams := types.NewTuple(types.NewVar(token.NoPos, pkg, "tgid", types.Typ[types.Int]), types.NewVar(token.NoPos, pkg, "tid", types.Typ[types.Int]), types.NewVar(token.NoPos, pkg, "sig", signal))
	pkg.Scope().Insert(types.NewFunc(token.NoPos, pkg, "Tgkill", types.NewSignatureType(nil, nil, nil, tgkillParams, results, false)))
	pkg.MarkComplete()
	return pkg, nil
}

func TestSignalImplicitTargetQuotesCommentsAndJoins(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "quotes.sh", `#!/bin/bash
cd /srv/app || exit 1 # can't continue
kill 0 # want
msg=$'it\'s'
kill 0 # want
echo "it's" # it's
kill 0 # want
python3 -c '
print("stop")
kill 0
'
bash -c '
  echo stopping
  kill 0 # want
'
echo \
kill 0
kill 0 && # want
  kill 0
echo a\|
kill 0 # want
echo a#'b
kill 0
'
kill 0 # want
`)
}

func TestSignalImplicitTargetNestedAndStrippedHeredocs(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "nested.sh", `#!/bin/bash
bash <<'OUTER'
cat > /etc/note.txt <<'INNER'
kill 0
INNER
kill "$PPID" # want
OUTER
bash <<'OUTER'
cat > /etc/note.txt <<'INNER'
kill 0
OUTER
kill 0 # want
cat <<-EOF
	kill 0
	EOF
kill 0 # want
cat <<A <<B
kill 0
A
kill 0
B
kill 0 # want
cat > stub <<EOF \
  && chmod +x stub
#!/bin/sh
kill 0 # want
EOF
bash <<EOF
echo "never closed
EOF
kill 0 # want
`)
}

// A line that ends an outer here-document ends the one opened inside it.
func TestSignalImplicitTargetOuterDelimiterEndsNested(t *testing.T) {
	inputs := textInputs([]string{"bash <<'kill 0'", "cat > note <<'INNER'", "kill 0", "kill 0"}, func(i int) int { return i + 1 })
	assert.Equal(t, []int{4}, scanSignalLines(inputs, false))
}

func TestSignalImplicitTargetCarriageReturns(t *testing.T) {
	inputs := textInputs([]string{"cat <<EOF\r", "kill 0\r", "EOF\r", "kill 0 &&\r", "kill 0\r"}, func(i int) int { return i + 1 })
	assert.Equal(t, []int{4}, scanSignalLines(inputs, false))
}

func TestSignalImplicitTargetMakeHeredocsAndLines(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "Makefile", "run:\n"+
		"\tbash <<EOF\n"+
		"\tkill $$PPID # want\n"+
		"\tEOF\n"+
		"stub:\n"+
		"\tcat > stub <<EOF\n"+
		"\t#!/bin/sh\n"+
		"\tkill 0 # want\n"+
		"\tEOF\n"+
		"quote:\n"+
		"\techo \"a\n"+
		"\tkill 0 # want\n")
}

func TestSignalImplicitTargetSignalsThatEndNothing(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "harmless.sh", `#!/bin/bash
kill -CONT 0
kill -SIGWINCH "$PPID"
kill -s CHLD -1
kill -s urg 0
kill -18 0
kill -28 "$PPID"
kill -17 0
kill -23 0
kill -STOP 0 # want
kill -TSTP "$PPID" # want
kill -USR1 -1 # want
kill -n 19 0 # want
kill -SIGTERM 0 # want
`)
}

func TestSignalImplicitTargetGoTextDataContexts(t *testing.T) {
	source := `package sample
import (
  "bytes"
  "strings"
)
func check(out string, t, b, r runner, audit logger) {
  _ = strings.Contains(out, "; kill 0")
  _ = bytes.HasPrefix([]byte(out), []byte("a; kill 0"))
  _ = out == "sleep 1; kill -9 -1"
  _ = "sleep 1; kill -9 -1" != out
  t.Run("blocks; kill 0 variants", nil)
  t.Run()
  b.Run("blocks; kill 0 variants", nil)
  audit.Infof("unexpected; kill 0 in %s", "x")
  audit.Warnf("a; kill 0")
  audit.Debug("a; kill 0")
  Infof("a; kill 0")
  _ = other.Contains(out, "a; kill 0") // want
  r.Run("a; kill 0", nil) // want
  run("a; kill 0") // want
  _ = strings.Fields("a; kill 0") // want
}
`
	file := core.NewFileContext("data.go", ".", []byte(source), nil)
	file.GoFileSet = token.NewFileSet()
	file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
	assert.Equal(t, []int{18, 19, 20, 21}, rulestest.ViolationLines(newSignalImplicitTargetRule().goFile(file, nil)))
}

func TestSignalImplicitTargetTypedReceiversPackagesAndSignals(t *testing.T) {
	source := `package sample
import (
  "os"
  "syscall"
  "testing"

  "example.com/other"
)
type runner struct{}
func (runner) Skipf(string, ...any) {}
func (runner) Run(string, func()) {}
func typed(t *testing.T, x runner) {
  t.Skipf("a; kill 0")
  x.Skipf("a; kill 0") // want
  t.Run("a; kill 0", func(*testing.T) {})
  x.Run("a; kill 0", func() {}) // want
  _ = other.Kill(os.Getppid(), syscall.SIGTERM)
  _ = syscall.Kill(other.Getppid(), syscall.SIGTERM)
  a := os.Getppid()
  b := a
  _ = syscall.Kill(b, syscall.SIGTERM) // want
  _ = syscall.Kill(a, syscall.SIGCONT)
  _ = syscall.Kill(a, syscall.SIGWINCH)
  _ = syscall.Kill(0, syscall.SIGCHLD)
  _ = syscall.Kill(-1, syscall.SIGURG)
  _ = syscall.Kill(a, syscall.SIGSTOP) // want
  _ = syscall.Kill(a, syscall.SIGUSR1) // want
  p, _ := os.FindProcess(os.Getppid())
  _ = p.Signal(syscall.SIGCONT)
  _ = p.Signal(syscall.SIGTSTP) // want
}
func named(t runner) {
  t.Run("a; kill 0", func() {}) // want
}
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "typed.go", source, parser.AllErrors)
	require.NoError(t, err)
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	_, err = (&types.Config{Importer: signalTestImporter{base: importer.Default()}}).Check("example.com/sample", fset, []*ast.File{parsed}, info)
	require.NoError(t, err)
	file := core.NewFileContext("typed.go", ".", []byte(source), nil)
	file.GoAST, file.GoFileSet, file.GoTypesInfo = parsed, fset, info
	got := rulestest.ViolationLines(newSignalImplicitTargetRule().goFile(file, newSignalPackage("", info, parsed)))
	slices.Sort(got)
	assert.Equal(t, []int{14, 16, 21, 26, 27, 30, 33}, got)
}

// A test file typed partially: the receiver of a package that did not load
// is known by its name.
func TestSignalImplicitTargetSubtestOfUnloadedReceiver(t *testing.T) {
	source := `package sample
import "example.com/missing"
func check(t missing.T) {
  t.Run("a; kill 0", nil)
}
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "partial_test.go", source, parser.AllErrors)
	require.NoError(t, err)
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	_, err = (&types.Config{Importer: importer.Default(), Error: func(error) {}}).Check("example.com/sample", fset, []*ast.File{parsed}, info)
	require.Error(t, err)
	file := core.NewFileContext("partial_test.go", ".", []byte(source), nil)
	file.GoAST, file.GoFileSet, file.GoTypesInfo = parsed, fset, info
	assert.Empty(t, newSignalImplicitTargetRule().goFile(file, newSignalPackage("", info, parsed)))
}

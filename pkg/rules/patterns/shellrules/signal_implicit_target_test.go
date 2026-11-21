package shellrules

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goFile preserves the package-level acceptance tests' typed-info helper.
func (r *signalImplicitTargetRule) goFile(f *core.FileContext, info *types.Info) []*core.Violation {
	var pkg *signalPackage
	if info != nil {
		pkg = newSignalPackage("", info, f.GoAST)
	}
	return r.goTypedFile(f, pkg)
}

func TestSignalImplicitTargetGoSSHArgv(t *testing.T) {
	source := `package main

import (
	"context"
	"os/exec"
)

func remote(ctx context.Context, host, pid string) []*exec.Cmd {
	return []*exec.Cmd{
		exec.Command("ssh", "host", "kill -TERM -1"),                            // P1
		exec.Command("ssh", "-T", "-o", "BatchMode=yes", "host", "kill", "0"),   // P2
		exec.CommandContext(ctx, "ssh", host, "kill -9 -1"),                     // P3
		exec.Command("/usr/bin/ssh", "-p", "2222", host, "kill", "-TERM", "-1"), // P4
		exec.Command("ssh", "host", "kill", pid),                                // N1
		exec.Command("ssh", "host", "kill -TERM 1234"),                          // N2
		exec.Command("ssh", "-p", "22", "host", "uptime"),                       // N3
		exec.Command("ssh", "host"),                                             // N4
		exec.Command("sh", "-c", "kill -TERM -1"),                               // C1
		exec.Command("ssh", "-l", "kill", "host", "uptime"),                     // N5
		exec.Command("ssh", "host", "echo", "kill -TERM -1"),                    // N6
	}
}
func main() {}
`
	file := core.NewFileContext("main.go", ".", []byte(source), nil)
	file.GoFileSet = token.NewFileSet()
	file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
	assert.Equal(t, []int{10, 11, 12, 13, 18}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, nil)))
}

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

func TestSignalImplicitTargetCallExprAfterLineEndingOperator(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "operators.sh", `#!/bin/bash
true &&
kill 0 # want
false || # note
kill $PPID # want
if true; then true &&
  kill 0 # want
fi
cat >/dev/null <<EOF
x
EOF
true &&
kill 0 # want
bash <<'BODY'
true &&
kill 0 # want
BODY
bash <<A; cat >/dev/null <<B
true &&
kill 0 # want
A
data
B
x="a &&
"; kill 0 # want
kill 0 && # want
kill $PPID # want
`)
}

func TestSignalImplicitTargetParserBranches(t *testing.T) {
	t.Run("here document interpreter", func(t *testing.T) {
		shellWanted(t, "signal-implicit-target", "heredoc.sh", `#!/bin/bash
bash <<'EOF'
kill -9 0 # want
EOF
cat <<EOF | bash
kill -TERM -1 # want
EOF
sh <<'SH_BODY'
kill -9 $PPID # want
SH_BODY
ssh worker <<'SSH_BODY'
kill -9 -1 # want
SSH_BODY
cat <<EOF | sh
kill -9 0 # want
EOF
cat > note <<EOF
kill 0
EOF
bash <<'OUTER'
bash <<'INNER'
kill -9 0 # want
INNER
OUTER
bash <<A; cat >/dev/null <<B
kill 0 # want
A
data
B
`)
	})
	t.Run("make recipe", func(t *testing.T) {
		shellWanted(t, "signal-implicit-target", "Makefile", `all:
	command kill -9 $$PPID # want
	command \
	  kill -TERM $$PPID # want
`)
	})
	t.Run("make recipe here document", func(t *testing.T) {
		shellWanted(t, "signal-implicit-target", "Makefile", "all:\n"+
			"\tbash <<EOF\n"+
			"\tkill -9 $$PPID # want\n"+
			"\tEOF\n")
	})
	t.Run("Go shell string", func(t *testing.T) {
		source := `package sample
import "os/exec"
func run() { _ = exec.Command("bash", "-c", "kill -9 $PPID").Run() }
`
		file := core.NewFileContext("run.go", ".", []byte(source), nil)
		file.GoFileSet = token.NewFileSet()
		file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
		assert.Equal(t, []int{3}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, nil)))
	})
	t.Run("parse error fallback", func(t *testing.T) {
		shellWanted(t, "signal-implicit-target", "broken.sh", `#!/bin/bash
if then
kill -9 0 # want
kill -TERM $PPID # want
`)
	})
}

func TestSignalImplicitTargetFindsExecutedGoStringsInsideLoggingCalls(t *testing.T) {
	cases := []struct {
		name, expression string
	}{
		{"log.Println", `log.Println(exec.Command("sh", "-c", "kill -TERM 0").Run())`},
		{"fmt.Fprintln", `fmt.Fprintln(os.Stderr, exec.Command("bash", "-c", "kill -9 $PPID").Run())`},
		{"log.Fatal", "log.Fatal(exec.Command(\"bash\", \"-c\", \"#!/bin/bash\\nkill 0\").Run())"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := "package sample\nfunc run() {\n" + tc.expression + "\n}\n"
			file := core.NewFileContext("run.go", ".", []byte(source), nil)
			file.GoFileSet = token.NewFileSet()
			file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
			assert.Equal(t, []int{3}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, nil)))
		})
	}
}

func TestSignalImplicitTargetMapsUnknownCallOffsetAcrossInputs(t *testing.T) {
	inputs := []signalInput{
		{text: "echo ready", line: 7, next: "bash -c $'kill -9 0'"},
		{text: "bash -c $'kill -9 0'", line: 11},
	}
	assert.Equal(t, []int{11}, parseSignalLines(inputs, false))
}

func TestSignalImplicitTargetMakeStripTabsHeredoc(t *testing.T) {
	delim := patternkit.HeredocRedirect{Word: "EOF", StripTabs: true}
	assert.True(t, signalHeredocTerminator("\tEOF", delim))
	assert.False(t, signalHeredocTerminator("  EOF", delim))
	assert.False(t, signalHeredocTerminator("\tEOF", patternkit.HeredocRedirect{Word: "EOF"}))
	inputs := []signalInput{
		{text: "\tbash <<-EOF", line: 1},
		{text: "\tEOF", line: 2},
		{text: "\tkill -9 0", line: 3},
	}
	assert.Equal(t, []int{3}, parseMakeSignalLines(inputs))
}

func TestSignalImplicitTargetParserFallbackBranches(t *testing.T) {
	t.Run("make continuation", func(t *testing.T) {
		// patternkit has already turned make's $$ into $ in a recipe line.
		text := "command \\\n kill -9 $PPID"
		input := signalInput{text: text, lineAt: func(offset int) int { return 2 + strings.Count(text[:offset], "\n") }}
		assert.Equal(t, []int{3}, parseMakeSignalLines([]signalInput{input}))
	})
	t.Run("nested script", func(t *testing.T) {
		shellWanted(t, "signal-implicit-target", "nested.sh", `kill -9 0 # want
bash -c 'if then; kill -9 0'`)
	})
	t.Run("make recipe", func(t *testing.T) {
		shellWanted(t, "signal-implicit-target", "Makefile", "all:\n\tif then; kill -9 0 # want\n")
	})
	t.Run("executed here document", func(t *testing.T) {
		shellWanted(t, "signal-implicit-target", "body.sh", `kill -9 0 # want
bash <<'END_BODY'
if then; kill 0
END_BODY
`)
	})
	t.Run("suffix fallback", func(t *testing.T) {
		source := signalDeepChain("echo safe\n", "if then\nkill -TERM -1\n")
		assert.Equal(t, []int{131}, scanSignalLines(signalTestInputs(source), false))
	})
}

func signalDeepChain(leaf, suffix string) string {
	var source strings.Builder
	for i := range 64 {
		source.WriteString("bash <<D")
		source.WriteString(strconv.Itoa(i))
		source.WriteByte('\n')
	}
	source.WriteString(leaf)
	for i := 63; i >= 0; i-- {
		source.WriteByte('D')
		source.WriteString(strconv.Itoa(i))
		source.WriteByte('\n')
	}
	source.WriteString(suffix)
	return source.String()
}

func signalTestInputs(text string) []signalInput {
	lines := strings.Split(text, "\n")
	inputs := make([]signalInput, len(lines))
	for i, line := range lines {
		lineNum := i + 1
		inputs[i] = signalInput{text: line, lineAt: func(int) int { return lineNum }}
		if i+1 < len(lines) {
			inputs[i].next = lines[i+1]
		}
	}
	return inputs
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
kill 0
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
	assert.Equal(t, []int{15, 17, 18, 19}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, nil)))
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
	assert.Empty(t, newSignalImplicitTargetRule().goTypedFile(file, newSignalPackage("", info, parsed)))
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
	assert.Equal(t, []int{5}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, nil)))
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
	assert.Equal(t, []int{3}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, nil)))
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
	assert.Equal(t, []int{4}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, nil)))
}

func TestSignalImplicitTargetRangeStringsFollowTheirUse(t *testing.T) {
	source := `package sample
import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)
func inspect(string) {}
type recorder struct{}
func (recorder) Command(string, string, string) {}
type command string
func (c command) run() { _ = exec.Command("sh", "-c", string(c)).Run() }
type commandRecord struct { command string }
var storedCommand commandRecord
func runShell(s string) { _ = exec.Command("sh", "-c", s).Run() }
func runGrouped(a, b string) { _ = exec.Command("sh", "-c", b).Run() }
func reverse(a, b string) { _ = exec.Command("sh", "-c", a).Run() }
func tables() {
	var saved string
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { runShell(s) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { runOtherFile(s) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { alias := s; _ = exec.Command("sh", "-c", alias).Run() } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = exec.Command("sh", "-c", "exec " + s).Run() } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = exec.CommandContext(context.Background(), "bash", "-c", fmt.Sprintf("exec %s", s)).Run() } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = exec.Command("env", "sh", "-c", s).Run() } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = exec.Command("/bin/sh", "-c", s).Run() } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = exec.CommandContext(context.Background(), "bash", "-c", s, "arg").Run() } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { command(s).run() } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { runGrouped("safe", s) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { reverse(s, "safe") } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { inspect(strings.TrimSpace(s)) } // WANT-NONE
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = s == strings.TrimSpace(s) } // WANT-NONE
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { saved = s } // WANT
	_ = exec.Command("sh", "-c", saved).Run()
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { inspect(s); { s := "safe"; _ = exec.Command("sh", "-c", s) } } // WANT-NONE
	for _, s := range []string{"kill -9 $PPID"} { inspect(s); { s := "safe"; _ = exec.Command("sh", "-c", s) } } // WANT-NONE
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { (recorder{}).Command("sh", "-c", s) } // WANT-NONE
	for _, s := range []string{"kill -9 $PPID"} { (recorder{}).Command("sh", "-c", s) } // WANT-NONE
	for _, s := range []string{
		"kill -9 $PPID", // WANT
		"bash -c 'kill -9 $PPID'", // WANT
	} { _ = exec.Command("sh", "-c", s).Run() }
	for _, s := range []string{} { _ = exec.Command("sh", "-c", s).Run() }
	for _, s := range []string{"kill -9 $PPID"} { other := "safe"; inspect(s); _ = exec.Command("sh", "-c", other).Run() } // WANT-NONE
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { inspect(s) } // WANT-NONE
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { storedCommand.command = s } // WANT-NONE
}
`
	helper := `package sample
import "os/exec"
func runOtherFile(s string) { _ = exec.Command("bash", "-c", s).Run() }
`
	file, pkg := signalSourceTyped(t, "signal_test.go", source, helper)
	var want []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// WANT") && !strings.Contains(line, "WANT-NONE") {
			want = append(want, i+1)
		}
	}
	assert.Equal(t, want, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

func TestSignalImplicitTargetRangeStringsWithoutTypesRemainFindings(t *testing.T) {
	source := `package sample
func inspect(string) {}
func tables() {
	for _, command := range []string{"bash -c 'kill -9 $PPID'"} { inspect(command) }
}
`
	file := core.NewFileContext("signal_test.go", ".", []byte(source), nil)
	file.GoFileSet = token.NewFileSet()
	file.GoAST, _ = parser.ParseFile(file.GoFileSet, file.Path, source, parser.AllErrors)
	assert.Equal(t, []int{4}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, nil)))
}

func TestSignalImplicitTargetRangeStringsRecognizeShellInvocationForms(t *testing.T) {
	source := `package sample
import (
	"context"
	"os/exec"
)
type recorder struct{}
func (recorder) Command(string, string, string) {}
func run(command string) {
	_ = exec.Command("/bin/sh", "-c", command)
	_ = exec.CommandContext(context.Background(), "bash", "-c", command, "extra")
	_ = exec.Command("env", "sh", "-c", command)
	(recorder{}).Command("sh", "-c", command)
}
`
	file, pkg := signalSourceTyped(t, "signal_test.go", source)
	var recognized, rejected int
	ast.Inspect(file.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		_, ok = shellExecutionScript(call, pkg.info)
		if ok {
			recognized++
		} else if rangeCallFunc(call, pkg.info) != nil {
			rejected++
		}
		return true
	})
	assert.Equal(t, 3, recognized)
	assert.GreaterOrEqual(t, rejected, 1)
}

func TestSignalImplicitTargetGoExecShellFlagsAndWrappers(t *testing.T) {
	source := `package sample
import (
	"fmt"
	"os/exec"
)
func run() {
	_ = exec.Command("sh", "-ec", "kill 0").Run() // P1
	_ = exec.Command("sh", "-xc", "kill 0").Run() // P2
	_ = exec.Command("sh", "-euc", "kill 0").Run() // P3
	_ = exec.Command("sudo", "sh", "-c", "kill 0").Run() // P4
	_ = exec.Command("nohup", "bash", "-c", "kill 0").Run() // P5
	_ = exec.Command("env", "LANG=C", "bash", "-xc", "kill 0").Run() // P6
	_ = exec.Command("sudo", "nohup", "env", "LANG=C", "sh", "-ec", "kill 0").Run() // P7
	s := "kill 0"
	_ = exec.Command("env", "LANG=C", "bash", "-xc", s).Run() // P8
	fmt.Println("kill 0") // N1
	_ = exec.Command("grep", "-c", "kill 0", "log").Run() // N2
	_ = exec.Command("sudo", "grep", "-c", "kill 0", "log").Run() // N3
	_ = exec.Command("sh", "-ec", "echo kill 0").Run() // N4
	_ = exec.Command("sh", "-e", "script.sh", "kill 0").Run() // N5
}
`
	file, pkg := signalSourceTyped(t, "exec.go", source)
	assert.Equal(t, []int{7, 8, 9, 10, 11, 12, 13, 14}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

func signalSourceTyped(t *testing.T, filename, source string, otherSources ...string) (*core.FileContext, *signalPackage) {
	t.Helper()
	fset := token.NewFileSet()
	allSources := append([]string{source}, otherSources...)
	parsed := make([]*ast.File, 0, len(allSources))
	for i, text := range allSources {
		name := filename
		if i > 0 {
			name = "helper.go"
		}
		file, err := parser.ParseFile(fset, name, text, parser.AllErrors)
		require.NoError(t, err)
		parsed = append(parsed, file)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object), Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	_, err := (&types.Config{Importer: signalTestImporter{base: importer.Default()}}).Check("example.com/sample", fset, parsed, info)
	require.NoError(t, err)
	ctx := core.NewFileContext(filename, ".", []byte(source), nil)
	ctx.GoAST, ctx.GoFileSet, ctx.GoTypesInfo = parsed[0], fset, info
	return ctx, newSignalPackage("example.com/sample", info, parsed...)
}

func TestSignalImplicitTargetRangeHelperDepthIsConservative(t *testing.T) {
	for _, tc := range []struct {
		name        string
		helpers     int
		wantFinding bool
	}{
		{name: "text helper chain below limit", helpers: 6},
		{name: "depth limit leaves finding", helpers: 8, wantFinding: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("package sample\nfunc inspect(string) {}\n")
			for i := 0; i < tc.helpers; i++ {
				source.WriteString("func helper")
				source.WriteString(strconv.Itoa(i))
				source.WriteString("(command string) {")
				if i+1 < tc.helpers {
					source.WriteString(" helper")
					source.WriteString(strconv.Itoa(i + 1))
					source.WriteString("(command)")
				} else if !tc.wantFinding {
					source.WriteString(" inspect(command)")
				}
				source.WriteString(" }\n")
			}
			source.WriteString("func tables() {\n for _, command := range []string{\"bash -c 'kill -9 $PPID'\"} { helper0(command) }")
			if tc.wantFinding {
				source.WriteString(" // WANT")
			}
			source.WriteString("\n}\n")
			file, pkg := signalSourceTyped(t, "signal_test.go", source.String())
			got := rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg))
			if tc.wantFinding {
				assert.Equal(t, []int{tc.helpers + 4}, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
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
	assert.Equal(t, []int{7, 10}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, nil)))
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
	violations := newSignalImplicitTargetRule().goTypedFile(file, newSignalPackage("", info, parsed))
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
	findings := newSignalImplicitTargetRule().goTypedFile(file, pkg)
	assert.Equal(t, []int{7, 8, 9, 12}, rulestest.ViolationLines(findings))
}

func TestSignalImplicitTargetSkipsTypedCallsWithoutTypes(t *testing.T) {
	source := "package sample\nimport (\"os\"; \"syscall\")\nfunc send() { _ = syscall.Kill(os.Getppid(), syscall.SIGTERM) }\n"
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "untyped.go", source, parser.AllErrors)
	require.NoError(t, err)
	file := core.NewFileContext("untyped.go", ".", []byte(source), nil)
	file.GoAST, file.GoFileSet = parsed, fset
	assert.Empty(t, newSignalImplicitTargetRule().goTypedFile(file, nil))
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
  kill 0 # want
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
kill 0
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
	assert.Equal(t, []int{4, 5}, scanSignalLines(inputs, false))
}

func TestSignalImplicitTargetMakeHeredocsAndLines(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "Makefile", "run:\n"+
		"\tbash <<EOF\n"+
		"\tkill $$PPID # want\n"+
		"\tEOF\n"+
		"stub:\n"+
		"\tcat > stub <<EOF\n"+
		"\t#!/bin/sh\n"+
		"\tkill 0\n"+
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
	assert.Equal(t, []int{18, 19, 20, 21}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, nil)))
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
	got := rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, newSignalPackage("", info, parsed)))
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
	assert.Empty(t, newSignalImplicitTargetRule().goTypedFile(file, newSignalPackage("", info, parsed)))
}

func TestSignalImplicitTargetSingleInputKeepsSourceLine(t *testing.T) {
	text := "echo harmless\nkill -9 0"
	input := signalInput{text: text, lineAt: func(offset int) int { return 40 + strings.Count(text[:offset], "\n") }}
	assert.Equal(t, []int{41}, parseSignalLines([]signalInput{input}, false))
}

func TestSignalImplicitTargetEmptyInputs(t *testing.T) {
	assert.Nil(t, parseSignalLines(nil, false))
}

// In a shell script $$PPID is the shell's own PID followed by the letters
// PPID: an explicit target, not $PPID. Only make turns $$ into $, so in a
// recipe $$PPID is $PPID and $$$$PPID is the shell's $$PPID again.
func TestSignalImplicitTargetDoubleDollarIsOwnPID(t *testing.T) {
	shellWanted(t, "signal-implicit-target", "own.sh", `#!/bin/bash
kill -9 $$PPID
kill "$$PPID"
kill -9 $PPID # want
`)
	shellWanted(t, "signal-implicit-target", "Makefile", "all:\n"+
		"\tkill -9 $$PPID # want\n"+
		"\tkill $$$$PPID\n"+
		"\tkill \"$$$$PPID\"\n")
}

// A $PPID that the shell passes as text is no target: kill gets the letters
// $PPID and fails. shellcmd proves a word literal only in a simple script, so
// each form is a script of its own; 0 and -1 written literally still are
// targets.
func TestSignalImplicitTargetLiteralDollarIsNoTarget(t *testing.T) {
	for _, src := range []string{
		"kill \\$PPID",
		"kill '$PPID'",
		"kill -TERM '${PPID}'",
		"bash -c 'kill \\$PPID'",
	} {
		assert.Empty(t, parseSignalLines([]signalInput{{text: src, line: 1}}, false), src)
	}
	for _, src := range []string{
		"kill $PPID",
		"kill \"$PPID\"",
		"bash -c \"kill \\$PPID\"",
		"kill '0'",
		"kill -- '-1'",
	} {
		assert.Equal(t, []int{1}, parseSignalLines([]signalInput{{text: src, line: 1}}, false), src)
	}
}

// shellcmd gives Offset -1 when the command name comes from a variable, as in
// a heredoc body; the finding then takes the line the call reports.
func TestSignalImplicitTargetCommandNameFromVariable(t *testing.T) {
	inputs := []signalInput{
		{text: "K=kill; runuser -k <<EOF", line: 7},
		{text: "$K 0", line: 11},
		{text: "EOF", line: 12},
	}
	assert.Equal(t, []int{11}, parseSignalLines(inputs, false))
}

// A table string whose use the analysis cannot follow (here: a struct field
// handed to a method) keeps the verdict it had without the analysis: a lone
// kill is a fixture, a nested shell is still a finding.
func TestSignalImplicitTargetRangeStringsUnknownUseKeepsDefaultVerdict(t *testing.T) {
	source := `package sample
type toolInput struct{ Command string }
type guard struct{}
func (guard) Validate(in *toolInput) bool { return len(in.Command) > 0 }
func tables() {
	for _, command := range []string{"kill -9 -1"} { (guard{}).Validate(&toolInput{Command: command}) } // WANT-NONE
	for _, command := range []string{"bash -c 'kill -9 $PPID'"} { (guard{}).Validate(&toolInput{Command: command}) } // WANT
}
`
	file, pkg := signalSourceTyped(t, "guard_test.go", source)
	var want []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// WANT") && !strings.Contains(line, "WANT-NONE") {
			want = append(want, i+1)
		}
	}
	assert.Equal(t, want, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

// A subtest body t.Run receives as a value — a method value bound to a table
// string, a named closure, a closure a package factory returns — may run the
// string in a shell; only a function literal on the spot shows what the body
// does with it.
func TestSignalImplicitTargetRangeStringsReachSubtestFunctionValues(t *testing.T) {
	source := `package sample
import (
	"os/exec"
	"testing"
)
func inspect(string) {}
type job struct{ command string }
func (j job) run(t *testing.T) { _ = exec.Command("sh", "-c", j.command).Run() }
func (j job) check(t *testing.T) { inspect(j.command) }
func mk(command string) func(*testing.T) {
	return func(t *testing.T) { _ = exec.Command("sh", "-c", command).Run() }
}
func mkRead(command string) func(*testing.T) {
	return func(t *testing.T) { inspect(command) }
}
var fixed job
func TestTable(t *testing.T) {
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", job{command: s}.run) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { j := job{command: s}; t.Run("case", j.run) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { j := job{command: s}; t.Run("case", (j.check)) } // WANT-NONE: resolved method only passes the field to a data helper
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { run := job{command: s}.run; t.Run("case", run) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { run := func(t *testing.T) { _ = exec.Command("sh", "-c", s).Run() }; t.Run("case", run) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", mk(s)) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { run := mk(s); t.Run("case", run) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", func(t *testing.T) { inspect(s) }) } // WANT-NONE
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", func(t *testing.T) { t.Log(s) }) } // WANT-NONE
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", (func(t *testing.T) { inspect(s) })) } // WANT-NONE
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run(s, fixed.run) } // WANT-NONE
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", mkRead(s)) } // WANT-NONE
}
`
	file, pkg := signalSourceTyped(t, "signal_test.go", source)
	var want []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// WANT") && !strings.Contains(line, "WANT-NONE") {
			want = append(want, i+1)
		}
	}
	assert.Equal(t, want, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

func TestSignalImplicitTargetRangeStringsReachNamedSubtestBodies(t *testing.T) {
	source := `package sample
import (
	"os/exec"
	"testing"
)
type job struct{ command string }
func (j job) logIt(t *testing.T) { t.Log(j.command) }
func (j job) runIt(t *testing.T) { _ = exec.Command("sh", "-c", j.command).Run() }
func accept(body func(*testing.T)) {}
func TestTable(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} {
		body := func(t *testing.T) { t.Log(s) }
		t.Run("case", body) // N1
	}
	for _, s := range []string{"kill -9 $PPID"} {
		t.Run("case", job{command: s}.logIt) // N2
	}
	for _, s := range []string{"kill -9 $PPID"} { // P1
		body := func(t *testing.T) { _ = exec.Command("sh", "-c", s).Run() }
		t.Run("case", body)
	}
	for _, s := range []string{"kill -9 $PPID"} { // P2
		t.Run("case", job{command: s}.runIt)
	}
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} {
		body := func(t *testing.T) { t.Log(s) }
		t.Run("case", body) // N3
	}
}
`

	file, pkg := signalSourceTyped(t, "named_subtest_test.go", source)
	want := []int{}
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// P") {
			want = append(want, i+1)
		}
	}
	assert.Equal(t, want, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
	ast.Inspect(file.GoAST, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "Run" {
			pkg.info.Types[selector.X] = types.TypeAndValue{Type: types.NewPointer(types.Typ[types.Invalid])}
		}
		return true
	})
	assert.Equal(t, want, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
	ast.Inspect(file.GoAST, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Command" {
			return true
		}
		delete(pkg.info.Selections, selector)
		delete(pkg.info.Uses, selector.Sel)
		if receiver, ok := ast.Unparen(selector.X).(*ast.Ident); ok {
			delete(pkg.info.Uses, receiver)
		}
		return true
	})
	assert.Equal(t, want, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

func TestSignalImplicitTargetNamedSubtestBodiesInLoadedTestOnlyPackage(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	require.NoError(t, os.MkdirAll(appDir, 0700))
	const source = `package app
import (
	"os/exec"
	"testing"
)
type job struct{ command string }
func (j job) logIt(t *testing.T) { t.Log(j.command) }
func (j job) runIt(t *testing.T) { _ = exec.Command("sh", "-c", j.command).Run() }
func N1(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} {
		body := func(t *testing.T) { t.Log(s) }
		t.Run("case", body)
	}
}
func N2(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} {
		t.Run("case", job{command: s}.logIt)
	}
}
func P1(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} {
		body := func(t *testing.T) { _ = exec.Command("sh", "-c", s).Run() }
		t.Run("case", body)
	}
}
func P2(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} {
		t.Run("case", job{command: s}.runIt)
	}
}
`
	filePath := filepath.Join(appDir, "a_test.go")
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/fx\n\ngo 1.26\n"), 0600))
	require.NoError(t, os.WriteFile(filePath, []byte(source), 0600))
	file, err := core.NewFileContextChecked(filePath, root, []byte(source), core.DefaultConfig())
	require.NoError(t, err)
	project, err := core.LoadGoProject(root, []*core.FileContext{file}, core.GoProjectOptions{RequireSSA: true})
	require.NoError(t, err)
	violations, err := newSignalImplicitTargetRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []int{21, 27}, rulestest.ViolationLines(violations))
}

// A lone kill behind wrappers that run it directly (sudo with its options and
// assignments, timeout, nice) is the same fixture as a bare kill; a kill that a
// nested shell runs behind them is still a finding.
func TestSignalImplicitTargetWrappedKillIsFixture(t *testing.T) {
	source := "package sample\n" +
		"type toolInput struct{ Command string }\n" +
		"type guard struct{}\n" +
		"func (guard) Validate(in *toolInput) bool { return len(in.Command) > 0 }\n" +
		"func tables() {\n" +
		"	for _, command := range []string{`sudo kill -9 -1`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT-NONE\n" +
		"	for _, command := range []string{`sudo -- X=1 kill -9 -1`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT-NONE\n" +
		"	for _, command := range []string{`sudo -u root -- X=1 kill -9 -1`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT-NONE\n" +
		"	for _, command := range []string{`sudo -- X=1 k\\ill -9 -1`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT-NONE\n" +
		"	for _, command := range []string{`sudo -- A=$a B=1 /bin/kill -9 -1`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT-NONE\n" +
		"	for _, command := range []string{`timeout 5 nice kill -9 -1`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT-NONE\n" +
		"	for _, command := range []string{`pkexec kill -9 -1`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT-NONE\n" +
		"	for _, command := range []string{`run0 kill 1`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT-NONE\n" +
		"	for _, command := range []string{`pkexec --user root kill -9 -1`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT-NONE\n" +
		"	for _, command := range []string{`run0 bash -c 'kill -9 -1'`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT\n" +
		"	for _, command := range []string{`sudo -- X=1 bash <<< 'kill -9 -1'`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT\n" +
		"	for _, command := range []string{`sudo bash -c 'kill -9 $PPID'`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT\n" +
		"	for _, command := range []string{`sudo kill -9 -1 $(sh -c 'kill -9 -1')`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT\n" +
		"	for _, command := range []string{`timeout 5 kill -9 -1 $(sudo kill -9 -1)`} { (guard{}).Validate(&toolInput{Command: command}) } // WANT\n" +
		"}\n"
	file, pkg := signalSourceTyped(t, "guard_test.go", source)
	var want []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// WANT") && !strings.Contains(line, "WANT-NONE") {
			want = append(want, i+1)
		}
	}
	assert.Equal(t, want, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

// A method value whose method hands its receiver on — to another method or
// to a function — may run the table string out of sight, like an unknown
// function value.
func TestSignalImplicitTargetMethodValuePassingReceiverOn(t *testing.T) {
	source := `package sample
import (
	"os/exec"
	"testing"
)
type task struct{ cmd string }
func (k task) shellIt(t *testing.T) { _ = exec.Command("sh", "-c", k.cmd).Run() }
func (k task) viaMethod(t *testing.T) { k.shellIt(t) }
func (k task) viaStruct(t *testing.T) { runTask(k) }
func (k task) logIt(t *testing.T) { t.Log(k.cmd) }
func runTask(k task) { _ = exec.Command("sh", "-c", k.cmd).Run() }
func TestTable(t *testing.T) {
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("a", task{cmd: s}.viaMethod) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("b", task{cmd: s}.viaStruct) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("c", task{cmd: s}.shellIt) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("d", task{cmd: s}.logIt) }
}
`
	file, pkg := signalSourceTyped(t, "receiver_on_test.go", source)
	var want []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// WANT") {
			want = append(want, i+1)
		}
	}
	assert.Equal(t, want, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

func TestSignalImplicitTargetMethodValueThroughReceiverMethods(t *testing.T) {
	source := `package sample
import (
	"os/exec"
	"testing"
)
type taskE struct{ cmd string }
func (k taskE) describe(t *testing.T) { t.Log("cmd", k.cmd) }
func (k taskE) logged(t *testing.T) { t.Log(k.cmd); k.describe(t) }
func (k taskE) twice(t *testing.T) { k.logged(t); k.describe(t) }
func (k taskE) ping(t *testing.T) { t.Log(k.cmd); if t.Failed() { k.pong(t) } }
func (k taskE) pong(t *testing.T) { t.Log(k.cmd); if !t.Failed() { k.ping(t) } }
func (k taskE) shellIt(t *testing.T) { _ = exec.Command("sh", "-c", k.cmd).Run() }
func (k taskE) mid(t *testing.T) { t.Log(k.cmd); k.shellIt(t) }
func (k taskE) viaMid(t *testing.T) { k.mid(t) }
func (k taskE) hands(t *testing.T) { runTaskE(k) }
func (k taskE) viaHands(t *testing.T) { k.describe(t); k.hands(t) }
func (k taskE) helper(t *testing.T) { t.Log(k.cmd); shellStr(k.cmd) }
func (k taskE) viaHelper(t *testing.T) { k.helper(t) }
func shellStr(s string) { _ = exec.Command("sh", "-c", s).Run() }
func runTaskE(k taskE) { _ = exec.Command("sh", "-c", k.cmd).Run() }
func TestTable(t *testing.T) {
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("a", taskE{cmd: s}.logged) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("b", taskE{cmd: s}.twice) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("c", taskE{cmd: s}.ping) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { e := taskE{cmd: s}; t.Run("d", e.logged) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("e", taskE{cmd: s}.mid) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("f", taskE{cmd: s}.viaMid) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("g", taskE{cmd: s}.viaHands) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { e := taskE{cmd: s}; t.Run("h", e.viaMid) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("i", taskE{cmd: s}.viaHelper) } // WANT
}
`
	file, pkg := signalSourceTyped(t, "receiver_methods_test.go", source)
	var want []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// WANT") {
			want = append(want, i+1)
		}
	}
	assert.Equal(t, want, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

func TestSignalImplicitTargetMethodValueReceiverFixedPointAndCopies(t *testing.T) {
	source := `package sample
import (
	"os/exec"
	"strings"
	"testing"
)
type rec struct{ cmd, script string; ptr *string }
func (k *rec) prep(t *testing.T) { k.script = k.cmd }
func (k *rec) runScript(t *testing.T) { _ = exec.Command("sh", "-c", k.script).Run() }
func (k *rec) deferRun(t *testing.T) { defer k.runScript(t); k.prep(t) }
func (k rec) vprep(t *testing.T) { k.script = k.cmd }
func (k rec) vrun(t *testing.T) { _ = exec.Command("sh", "-c", k.script).Run() }
func (k rec) vboth(t *testing.T) { k.vprep(t); k.vrun(t) }
func (k rec) shellIt(t *testing.T) { _ = exec.Command("sh", "-c", k.cmd).Run() }
func (k rec) overwrite(t *testing.T) { k.cmd = "echo safe"; k.shellIt(t) }
func (k rec) selfCopy(t *testing.T) { k.script = k.cmd; _ = exec.Command("sh", "-c", k.script).Run() }
func (k rec) trimmed(t *testing.T) { k.cmd = strings.TrimSpace(k.cmd); _ = exec.Command("sh", "-c", k.cmd).Run() }
func (k rec) trimCall(t *testing.T) { k.cmd = strings.TrimSpace(k.cmd); k.shellIt(t) }
func (k rec) runCopy(t *testing.T) { _ = exec.Command("sh", "-c", k.script).Run() }
func (k rec) copyCall(t *testing.T) { k.script = k.cmd; k.runCopy(t) }
func (k rec) mapWrite(t *testing.T) { m := map[string]int{}; m[k.cmd] = 1 }
func (k rec) pointerWrite(t *testing.T) { *k.ptr = "echo safe" }
type wr struct{ cmd, script string }
func (k wr) runThenReset(t *testing.T) { _ = exec.Command("sh", "-c", k.cmd).Run(); k.cmd = "echo done" }
func (k wr) shell(t *testing.T) { _ = exec.Command("sh", "-c", k.cmd).Run() }
func (k wr) callThenReset(t *testing.T) { k.shell(t); k.cmd = "echo done" }
func (k *wr) pRunThenReset(t *testing.T) { _ = exec.Command("sh", "-c", k.cmd).Run(); k.cmd = "echo done" }
func TestTable(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} { k := rec{cmd: s}; t.Run("pointer", k.deferRun) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("value-copy", rec{cmd: s}.vboth) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("value-overwrite", rec{cmd: s}.overwrite) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("value-self-copy-L", rec{cmd: s}.selfCopy) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("value-self-copy-N", rec{cmd: s}.selfCopy) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("value-trim-L", rec{cmd: s}.trimmed) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("value-trim-N", rec{cmd: s}.trimmed) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("value-trim-call-L", rec{cmd: s}.trimCall) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("value-trim-call-N", rec{cmd: s}.trimCall) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("value-copy-call-L", rec{cmd: s}.copyCall) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("value-copy-call-N", rec{cmd: s}.copyCall) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("map-key-read", rec{cmd: s}.mapWrite) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("deref-target-read", rec{ptr: &s}.pointerWrite) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("reset-L-value", wr{cmd: s}.runThenReset) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("reset-N-value", wr{cmd: s}.runThenReset) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("reset-L-call", wr{cmd: s}.callThenReset) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("reset-N-call", wr{cmd: s}.callThenReset) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { e := wr{cmd: s}; t.Run("reset-L-pointer", e.pRunThenReset) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { e := wr{cmd: s}; t.Run("reset-N-pointer", e.pRunThenReset) } // WANT
}
`
	file, pkg := signalSourceTyped(t, "method_value_fixed_point_test.go", source)
	var want []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// WANT") {
			want = append(want, i+1)
		}
	}
	assert.Equal(t, want, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

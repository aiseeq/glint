package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const signalAcceptShell = `#!/bin/bash
kill "$PPID" # WANT
kill $PPID # WANT
kill -TERM $PPID # WANT
kill -9 "${PPID}" # WANT
kill -s TERM "$PPID" # WANT
kill -n 15 "$PPID" # WANT
kill -SIGKILL "$PPID" # WANT
kill -- -1 # WANT
kill -TERM -1 # WANT
kill -9 -1 # WANT
kill 0 # WANT
kill -TERM 0 # WANT
kill -s TERM 0 # WANT
trap 'kill 0' EXIT # WANT
true && kill "$PPID" # WANT
[ -n "$PPID" ] && kill "$PPID" # WANT
if [ -f stop ]; then kill "$PPID"; fi # WANT
sh -c 'kill -9 $PPID' # WANT
: > /proc/$PPID/fd/2; kill -9 $PPID # WANT
`

const signalAcceptShellForms = `#!/bin/bash
f() {
  kill "$PPID" # WANT
}
case "$x" in
  stop)
    kill 0 # WANT
    ;;
esac
if kill "$PPID"; then :; fi # WANT
while kill 0; do sleep 1; done # WANT
sudo kill -TERM "$PPID" # WANT
exec kill 0 # WANT
command kill "$PPID" # WANT
timeout 5 kill -9 -1 # WANT
nohup kill "$PPID" # WANT
/bin/kill "$PPID" # WANT
(kill 0) # WANT
FOO=1 kill 0 # WANT
`

const signalAcceptShellGuardScope = `#!/bin/bash
cat /proc/$PPID/comm
kill 0 # WANT
cat /proc/$PPID/comm >> log
kill "$PPID" # WANT
if [ "$(cat /proc/$PPID/comm)" = runner ]; then
  echo ok
fi
kill "$PPID" # WANT
`

const signalAcceptShellText = `#!/bin/bash
echo "stopping; kill $PPID"
echo "a | kill 0"
log "if stuck, then kill -9 -1"
echo 'hint: do kill 0'
grep -E 'term|kill 0' run.log
grep -q "x;kill $PPID" run.log
kill $(pgrep -P $PPID -f worker)
kill -s0 "$PPID"
kill --signal 0 "$PPID"
kill -l 0
cat > note.md <<EOF
kill 0
kill -9 -1 ends everything
EOF
`

// Review round 3: prose and data that only look like a kill command, and
// a heredoc-like << that is an arithmetic shift.
const signalAcceptShellProse = `#!/bin/bash
MSG="To stop everything:
kill 0
"
git commit -m "fix: guard
kill 0 no longer runs"
cat > notes.txt <<\EOF
kill 0 stops the whole group
EOF
cat > u.txt <<EOF
run it like: foo |
EOF
kill 0 # WANT
n=$((1 << 4))
kill 0 # WANT
(( n <<= 1 ))
kill "$PPID" # WANT
cd /srv/app || exit 1 # can't continue
kill 0 # WANT
msg=$'it\'s'
kill 0 # WANT
`

// A check of the parent excuses nothing: the parent is not a process the
// script started, whatever its name.
const signalAcceptShellGuardTarget = `#!/bin/bash
if [ "$(cat /proc/$PPID/comm)" = runner ]; then
  kill -TERM "$PPID" # WANT
fi
if ps -o comm= -p "$PPID" | grep -q runner; then
  kill "$PPID" # WANT
fi
grep -q runner /proc/$PPID/cmdline && kill "$PPID" # WANT
if [ "$(cat /proc/$PPID/comm)" = runner ]; then kill 0; fi # WANT
grep -q runner /proc/$PPID/cmdline && kill -9 -1 # WANT
if [ "$(cat /proc/$PPID/comm)" != runner ]; then kill "$PPID"; fi # WANT
parent=$(cat /proc/$PPID/comm)
echo 1
echo 2
echo 3
echo 4
echo 5
echo 6
kill "$PPID" # WANT
`

// Go text that only mentions a signal: help, prompts, output, and a script
// whose kill line is heredoc data.
const signalAcceptGoProse = `package check

import (
	"fmt"
	"log"
	"os"
	"testing"
)

const help = "Usage:\n  kill 0 stops the group\n"

const prompt = ` + "`" + `When the job hangs,
kill 0 ends the group.
` + "`" + `

const readme = ` + "`" + `#!/bin/sh
cat > README <<EOF
kill 0
EOF
` + "`" + `

func report(w *os.File, name string, t *testing.T) {
	fmt.Fprintln(os.Stderr, "stuck; kill 0 by hand")
	fmt.Fprintf(w, "case %s: %s\n", name, "a; kill 0")
	log.Printf("then run %q", "sleep 1; kill -9 -1")
	t.Errorf("want finding for %q", "a; kill 0")
	t.Logf("case %s", "sleep 1; kill -9 -1")
}
`

const signalAcceptShellFed = `#!/bin/bash
bash <<EOF
kill 0 # WANT
EOF
bash <<'OUTER'
cat > /etc/note.txt <<'INNER'
kill 0
INNER
kill "$PPID" # WANT
OUTER
`

const signalAcceptMake = "stop:\n\t@echo \"stop; kill $$PPID\"\n\tkill $$PPID # WANT\n" +
	"a:\n\techo $$(( 1 << 2 ))\nb:\n\tsh -c \"kill -9 -1\" # WANT\n"

const signalAcceptGoText = `package check

import (
	"log"
	"os/exec"
)

var dangerous = []string{"kill -9 -1", "rm -rf /"}
var known = map[string]bool{"kill 0": true}

const helpExample = "kill 0"

const withNewlines = "#!/bin/sh\nsleep 1\nkill 0\n" // WANT

func words(c string) bool {
	log.Println("kill -9 $PPID")
	log.Println("failed to stop worker; kill $PPID")
	log.Println("wait 5s, then kill 0")
	return c == "kill -9 $PPID"
}

func run() error {
	return exec.Command("bash", "-c", "kill 0").Run() // WANT
}
`

const signalAcceptStub = `#!/bin/bash
cat > "$dir/stub" <<'EOF'
#!/bin/bash
sleep 1
kill -TERM "$PPID" # WANT
EOF
chmod +x "$dir/stub"
`

const signalAcceptShellFine = `#!/bin/bash
kill -0 "$PPID"
kill -s 0 "$PPID"
kill -CONT 0
kill -WINCH "$PPID"
kill -s CHLD "$PPID"
kill -URG -1
kill -0 -1
kill "$pid"
kill "$$"
kill %1
kill "$child"
kill -1 "$pid"
kill -1 1234
kill -l
kill -- -"$pgid"
echo "kill $PPID"
printf 'kill -9 $PPID\n'
log "will kill $PPID"
# kill $PPID
grep 'kill.*PPID' run.log
killall worker
`

const signalAcceptGo = `package check

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const stubLines = ` + "`" + `#!/bin/bash
sleep 1
if [ -e "$f" ]; then rm -f "$f"; kill -9 "$PPID"; exit 137; fi # WANT
` + "`" + `

func direct(pid, pgid int, sig syscall.Signal, cmd *exec.Cmd) {
	_ = syscall.Kill(os.Getppid(), syscall.SIGTERM) // WANT
	_ = syscall.Kill(os.Getppid(), sig)             // WANT
	_ = unix.Kill(os.Getppid(), unix.SIGKILL)       // WANT
	_ = syscall.Kill(-1, syscall.SIGKILL)           // WANT
	_ = syscall.Kill(0, syscall.SIGTERM)            // WANT
	ppid := os.Getppid()
	_ = syscall.Kill(ppid, syscall.SIGTERM) // WANT
	parent, _ := os.FindProcess(os.Getppid())
	_ = parent.Signal(syscall.SIGTERM) // WANT
	other, _ := os.FindProcess(os.Getppid())
	_ = other.Kill() // WANT

	_ = syscall.Kill(os.Getppid(), 0)
	_ = syscall.Kill(os.Getppid(), syscall.Signal(0))
	_ = syscall.Kill(0, 0)
	_ = syscall.Kill(pid, sig)
	_ = syscall.Kill(os.Getpid(), sig)
	_ = syscall.Kill(-pgid, sig)
	_ = cmd.Process.Signal(sig)
	probe, _ := os.FindProcess(os.Getppid())
	_ = probe.Signal(syscall.Signal(0))
	own, _ := os.FindProcess(pid)
	_ = own.Kill()
}

func script() []string {
	return []string{
		"a; kill -9 $PPID",                      // WANT
		"printf x >> /proc/$PPID/fd/1; " + "x",
		"sh -c 'kill -TERM \"$PPID\"'; sleep 30", // WANT
	}
}

func text(name, out string) error {
	_ = strings.Contains(out, "; kill 0")
	_ = out == "sleep 1; kill -9 -1"
	fmt.Println("kill $PPID failed")
	fmt.Println("would kill -9 $PPID")
	_ = "echo \"kill $PPID\""
	_ = "grep 'kill.*PPID' log"
	return errors.New("cannot kill 0 of " + name)
}
`

// A test table of command strings for a parser or guard: data, nothing runs
// it. A script in a test is reported, and so is a command the code runs.
const signalAcceptGoTest = `package check

var guardInputs = []string{
	"kill -9 -1",
	"kill $PPID",
	` + "`kill 0`" + `,
}

var stubInTest = "sleep 1; kill -9 $PPID" // WANT

func TestGuard(t *testing.T) {
	t.Run("blocks; kill 0 variants", func(t *testing.T) {})
	audit.Infof("unexpected; kill 0 in %s", "x")
}
`

const signalAcceptGoRun = `package check

import "os/exec"

func stop() error { return exec.Command("sh", "-c", "kill -9 $PPID").Run() } // WANT
`

// The rule reads shell too, so a root is not dropped for having no Go file
// that mentions a signal.
func TestSignalImplicitTargetRootsWithoutGoSignals(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"no go files":       {},
		"no signal in go":   {"a.go": "package check\n\nconst note = 1\n"},
		"only a go literal": {"a.go": "package check\n\nconst script = \"sleep 1; kill -9 $PPID\" // WANT\n"},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]string{"go.mod": "module example.com/check\n\ngo 1.24\n", ".glint.yaml": "version: 1\n", "y.sh": "#!/bin/bash\nkill 0 # WANT\n"}
			maps.Copy(files, extra)
			var want []string
			for file, content := range files {
				require.NoError(t, os.WriteFile(filepath.Join(root, file), []byte(content), 0o644))
				for i, line := range strings.Split(content, "\n") {
					if strings.Contains(line, "WANT") {
						want = append(want, fmt.Sprintf("%s:%d", file, i+1))
					}
				}
			}
			findings, _ := analyzeWithRules(t, root, nil, "signal-implicit-target")
			got := foundAt(findings)
			slices.Sort(got)
			slices.Sort(want)
			assert.Equal(t, want, got)

			cfg, all, err := loadConfig(root)
			require.NoError(t, err)
			enabled := slices.DeleteFunc(all, func(rule rules.Rule) bool { return rule.Name() != "signal-implicit-target" })
			prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, enabled, false)
			require.NoError(t, err)
			_, typedRules, _ := rootProjectRulePlan(enabled)
			_, active := selectTypedProjectRules(enabled, nil, typedRules, prepared.contexts)
			assert.Len(t, active, 1, "the run must keep the rule on this root")
		})
	}
}

func TestSignalImplicitTargetAcceptance(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":            "module example.com/check\n\ngo 1.24\n\nrequire golang.org/x/sys v0.0.0\n\nreplace golang.org/x/sys => ./xsys\n",
		".glint.yaml":       "version: 1\n",
		"xsys/go.mod":       "module golang.org/x/sys\n\ngo 1.24\n",
		"xsys/unix/unix.go": "package unix\n\nimport \"syscall\"\n\nconst SIGKILL = syscall.SIGKILL\n\nfunc Kill(pid int, sig syscall.Signal) error { return nil }\n",
		"bad.sh":            signalAcceptShell,
		"stub.sh":           signalAcceptStub,
		"fine.sh":           signalAcceptShellFine,
		"check.go":          signalAcceptGo,
		"guard_test.go":     signalAcceptGoTest,
		"run.go":            signalAcceptGoRun,
		"forms.sh":          signalAcceptShellForms,
		"scope.sh":          signalAcceptShellGuardScope,
		"text.sh":           signalAcceptShellText,
		"fed.sh":            signalAcceptShellFed,
		"Makefile":          signalAcceptMake,
		"text.go":           signalAcceptGoText,
		"prose.sh":          signalAcceptShellProse,
		"target.sh":         signalAcceptShellGuardTarget,
		"prose.go":          signalAcceptGoProse,
	}
	var want []string
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		for i, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "WANT") {
				want = append(want, fmt.Sprintf("%s:%d", name, i+1))
			}
		}
	}
	findings, _ := analyzeWithRules(t, root, nil, "signal-implicit-target")
	got := foundAt(findings)
	slices.Sort(got)
	slices.Sort(want)
	assert.Equal(t, want, got)
}

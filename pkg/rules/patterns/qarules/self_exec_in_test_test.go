package qarules

import (
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selfExecLauncher is a launcher package of the module: it starts any binary
// it is given in its own session and does not wait for it.
const selfExecLauncher = `package procutil

import (
	"os/exec"
	"syscall"
)

func StartDetached(path string, args ...string) error {
	cmd := exec.Command(path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
`

// selfExecSweep hands the process's own executable to the launcher of
// another package from a function a test reaches.
const selfExecSweep = `package cachesweep

import (
	"os"

	"example.com/rulestest/internal/procutil"
)

func Sweep(dir string) error {
	return startSweep([]string{dir})
}

func startSweep(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return procutil.StartDetached(exe, append([]string{"sweep-cleanup"}, args...)...)
}
`

const selfExecSweepTest = `package cachesweep

import "testing"

func TestSweep(t *testing.T) { _ = Sweep(t.TempDir()) }
`

func selfExecPlaces(t *testing.T, files map[string]string) []string {
	t.Helper()
	return rulestest.ProjectRulePlaces(t, NewSelfExecInTestRule(), files)
}

func selfExecFiles(extra map[string]string) map[string]string {
	files := map[string]string{"internal/procutil/procutil.go": selfExecLauncher}
	maps.Copy(files, extra)
	return files
}

func TestSelfExecInTestRule_Metadata(t *testing.T) {
	rule := NewSelfExecInTestRule()
	assert.Equal(t, "self-exec-in-test", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
}

// Repro of a real fork bomb: a test reached a function that passed
// os.Executable() to the launcher of another package. Under go test that path
// is the package's .test binary; Go stops parsing flags at the positional
// subcommand and runs every test again, and every copy starts the next one.
func TestSelfExecInTestRule_ExecutableThroughParameterOfAnotherPackage(t *testing.T) {
	files := selfExecFiles(map[string]string{
		"internal/cachesweep/sweep.go":      selfExecSweep,
		"internal/cachesweep/sweep_test.go": selfExecSweepTest,
	})
	violations := rulestest.RunRuleOnFiles(t, NewSelfExecInTestRule(), files)
	require.Equal(t, []string{"internal/cachesweep/sweep.go:18"}, rulestest.ViolationPlaces(violations))
	message := violations[0].Message
	for _, part := range []string{"TestSweep", "Sweep → startSweep", "procutil.StartDetached"} {
		assert.Contains(t, message, part)
	}
}

// os.Args[0] is the own executable too, and a test reaches the launch through
// a method of a value the test builds.
func TestSelfExecInTestRule_ArgsZeroThroughMethod(t *testing.T) {
	assert.Equal(t, []string{"worker/pool.go:15"}, selfExecPlaces(t, map[string]string{
		"worker/pool.go": `package worker

import (
	"os"
	"os/exec"
)

type Pool struct{ size int }

func (p *Pool) Grow() error {
	return p.spawn()
}

func (p *Pool) spawn() error {
	return exec.Command(os.Args[0], "worker").Start()
}
`,
		"worker/pool_test.go": `package worker_test

import (
	"testing"

	"example.com/rulestest/worker"
)

func TestGrow(t *testing.T) {
	p := &worker.Pool{}
	_ = p.Grow()
}
`,
	}))
}

// The own path comes back from a helper and travels through a copy before it
// reaches exec.CommandContext.
func TestSelfExecInTestRule_ExecutableFromHelper(t *testing.T) {
	assert.Equal(t, []string{"relaunch/relaunch.go:24"}, selfExecPlaces(t, map[string]string{
		"relaunch/relaunch.go": `package relaunch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

func selfPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func Restart(ctx context.Context) error {
	path, err := selfPath()
	if err != nil {
		return err
	}
	bin := path
	return exec.CommandContext(ctx, bin, "serve").Start()
}
`,
		"relaunch/relaunch_test.go": `package relaunch

import (
	"context"
	"testing"
)

func TestRestart(t *testing.T) {
	if err := Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
}
`,
	}))
}

// A test that starts its own binary without -test.run and with no TestMain
// that answers the child runs every test again in the child.
func TestSelfExecInTestRule_TestStartsItsOwnBinary(t *testing.T) {
	assert.Equal(t, []string{"daemon/daemon_test.go:14"}, selfExecPlaces(t, map[string]string{
		"daemon/daemon.go": "package daemon\n\nfunc Ready() bool { return true }\n",
		"daemon/daemon_test.go": `package daemon

import (
	"os"
	"os/exec"
	"testing"
)

func TestDaemonStarts(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "serve")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
}
`,
	}))
}

// A TestMain that only prepares the run does not answer the child: it still
// reaches m.Run and runs every test.
func TestSelfExecInTestRule_TestMainWithoutDispatch(t *testing.T) {
	assert.Equal(t, []string{"internal/cachesweep/sweep.go:18"}, selfExecPlaces(t, selfExecFiles(map[string]string{
		"internal/cachesweep/sweep.go":      selfExecSweep,
		"internal/cachesweep/sweep_test.go": selfExecSweepTest,
		"internal/cachesweep/main_test.go": `package cachesweep

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sweep")
	if err != nil {
		os.Exit(1)
	}
	defer os.RemoveAll(dir)
	os.Exit(m.Run())
}
`,
	})))
}

// The launch only from main() is not reached by any test.
func TestSelfExecInTestRule_OnlyFromMain(t *testing.T) {
	assert.Empty(t, selfExecPlaces(t, selfExecFiles(map[string]string{
		"internal/cachesweep/sweep.go": strings.Replace(selfExecSweep, "return startSweep([]string{dir})", "return nil", 1) +
			"\nfunc Background(dir string) error { return startSweep([]string{dir}) }\n",
		"internal/cachesweep/sweep_test.go": selfExecSweepTest,
		"cmd/sweeper/main.go": `package main

import "example.com/rulestest/internal/cachesweep"

func main() {
	_ = cachesweep.Background(".")
}
`,
	})))
}

// testing.Testing() true on the path refuses the launch: in the launching
// function, in its caller, or in the launcher the own path is passed to.
func TestSelfExecInTestRule_TestingGuard(t *testing.T) {
	guardedSweep := strings.Replace(selfExecSweep, "\texe, err := os.Executable()",
		"\tif testing.Testing() {\n\t\treturn errors.New(\"refused in the test binary\")\n\t}\n\texe, err := os.Executable()", 1)
	guardedSweep = strings.Replace(guardedSweep, "import (\n\t\"os\"", "import (\n\t\"errors\"\n\t\"os\"\n\t\"testing\"", 1)
	assert.Empty(t, selfExecPlaces(t, selfExecFiles(map[string]string{
		"internal/cachesweep/sweep.go":      guardedSweep,
		"internal/cachesweep/sweep_test.go": selfExecSweepTest,
	})), "guard in the launching function")

	callerGuard := strings.Replace(selfExecSweep, "\treturn startSweep([]string{dir})",
		"\tif !testing.Testing() && dir != \"\" {\n\t\treturn startSweep([]string{dir})\n\t}\n\treturn nil", 1)
	callerGuard = strings.Replace(callerGuard, "import (\n\t\"os\"", "import (\n\t\"os\"\n\t\"testing\"", 1)
	assert.Empty(t, selfExecPlaces(t, selfExecFiles(map[string]string{
		"internal/cachesweep/sweep.go":      callerGuard,
		"internal/cachesweep/sweep_test.go": selfExecSweepTest,
	})), "guard in the caller")

	assert.Empty(t, selfExecPlaces(t, map[string]string{
		"internal/procutil/procutil.go": `package procutil

import (
	"errors"
	"os/exec"
	"testing"
)

func StartDetached(path string, args ...string) error {
	if testing.Testing() || path == "" {
		return errors.New("refused")
	}
	return exec.Command(path, args...).Start()
}
`,
		"internal/cachesweep/sweep.go":      selfExecSweep,
		"internal/cachesweep/sweep_test.go": selfExecSweepTest,
	}), "guard in the launcher")
}

// The helper process: the test starts its own binary with -test.run, so the
// child runs the one helper test and not the whole suite.
func TestSelfExecInTestRule_HelperProcessWithTestRun(t *testing.T) {
	assert.Empty(t, selfExecPlaces(t, map[string]string{
		"shell/shell.go": "package shell\n\nfunc Name() string { return \"sh\" }\n",
		"shell/shell_test.go": `package shell

import (
	"os"
	"os/exec"
	"testing"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	os.Exit(0)
}

func TestRunsHelper(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", "echo")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}
`,
	}))
}

// The helper process through TestMain: the test binary answers the child by
// its environment or its positional argument before m.Run, so a self-launch
// the tests reach never runs the suite again.
func TestSelfExecInTestRule_TestMainDispatch(t *testing.T) {
	for name, testMain := range map[string]string{
		"env": `package cachesweep

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("SWEEP_CHILD") == "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
`,
		"helper": `package cachesweep

import (
	"os"
	"testing"
)

func childCode() (int, bool) {
	if len(os.Args) > 1 && os.Args[1] == "sweep-cleanup" {
		return 0, true
	}
	return 0, false
}

func TestMain(m *testing.M) {
	if code, ok := childCode(); ok {
		os.Exit(code)
	}
	os.Exit(m.Run())
}
`,
		"positional": `package cachesweep

import (
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	for _, arg := range os.Args[1:] {
		if !strings.HasPrefix(arg, "-test.") {
			os.Exit(2)
		}
	}
	os.Exit(m.Run())
}
`,
	} {
		assert.Empty(t, selfExecPlaces(t, selfExecFiles(map[string]string{
			"internal/cachesweep/sweep.go":      selfExecSweep,
			"internal/cachesweep/sweep_test.go": selfExecSweepTest,
			"internal/cachesweep/main_test.go":  testMain,
		})), name)
	}
}

// Another binary - a tool on PATH or a sibling of the own executable - is
// not the test binary.
func TestSelfExecInTestRule_OtherBinary(t *testing.T) {
	assert.Empty(t, selfExecPlaces(t, selfExecFiles(map[string]string{
		"internal/tools/tools.go": `package tools

import (
	"os"
	"os/exec"
	"path/filepath"

	"example.com/rulestest/internal/procutil"
)

func Status() error {
	return exec.Command("git", "status").Run()
}

func Sibling() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return procutil.StartDetached(filepath.Join(filepath.Dir(exe), "helper"), "run")
}

func Named() string {
	return filepath.Base(os.Args[0])
}
`,
		"internal/tools/tools_test.go": `package tools

import "testing"

func TestTools(t *testing.T) {
	_ = Status()
	_ = Sibling()
	_ = Named()
}
`,
	})))
}

// A launcher a test only stores - a command handler in a struct field - is
// not run by building the struct.
func TestSelfExecInTestRule_StoredHandlerIsNotRun(t *testing.T) {
	assert.Empty(t, selfExecPlaces(t, selfExecFiles(map[string]string{
		"cli/cli.go": `package cli

import (
	"os"

	"example.com/rulestest/internal/procutil"
)

type Command struct {
	Name string
	Run  func() error
}

func Commands() []Command {
	return []Command{{Name: "watch", Run: func() error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		return procutil.StartDetached(exe, "watch")
	}}}
}
`,
		"cli/cli_test.go": `package cli

import "testing"

func TestCommands(t *testing.T) {
	if len(Commands()) != 1 {
		t.Fatal("one command")
	}
}
`,
	})))
}

// Every standard launch counts: an exec.Cmd literal, os.StartProcess and
// syscall.Exec, given the own path from a package variable or os.Args[0].
func TestSelfExecInTestRule_OtherLaunches(t *testing.T) {
	assert.Equal(t, []string{"spawn/spawn.go:13", "spawn/spawn.go:17", "spawn/spawn.go:23"}, selfExecPlaces(t, map[string]string{
		"spawn/spawn.go": `package spawn

import (
	"os"
	"os/exec"
	"syscall"
)

var selfBin, _ = os.Executable()

func All() error {
	cmd := &exec.Cmd{
		Path: selfBin,
		Args: []string{selfBin, "child"},
	}
	_ = cmd.Start()
	if _, err := os.StartProcess(os.Args[0], []string{"child"}, &os.ProcAttr{}); err != nil {
		return err
	}
	return replace()
}

func replace() error { return syscall.Exec(selfBin, []string{"child"}, os.Environ()) }
`,
		"spawn/spawn_test.go": `package spawn

import "testing"

func TestAll(t *testing.T) { _ = All() }
`,
	}))
}

// A launcher that copies its parameter before the launch still launches it;
// an example go test runs (one with an output comment) reaches it too, an
// example without one is only compiled.
func TestSelfExecInTestRule_ParameterCopyAndExample(t *testing.T) {
	files := map[string]string{
		"internal/procutil/procutil.go": `package procutil

import "os/exec"

func Start(path string) error {
	bin := path
	return exec.Command(bin).Start()
}
`,
		"internal/cachesweep/sweep.go": `package cachesweep

import (
	"os"

	"example.com/rulestest/internal/procutil"
)

func Sweep() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return procutil.Start(exe)
}
`,
	}
	withExample := func(body string) map[string]string {
		out := maps.Clone(files)
		out["internal/cachesweep/example_test.go"] = "package cachesweep_test\n\nimport \"example.com/rulestest/internal/cachesweep\"\n\nfunc ExampleSweep() {\n\t_ = cachesweep.Sweep()\n" + body + "}\n"
		return out
	}
	assert.Equal(t, []string{"internal/cachesweep/sweep.go:14"}, selfExecPlaces(t, withExample("\t// Output:\n")))
	assert.Empty(t, selfExecPlaces(t, withExample("")))
}

// A method of a value from outside the module - t.Run - is not a method of
// the module that happens to share its name; a method of the module is
// followed on the type the test builds, not on every type with that name.
func TestSelfExecInTestRule_MethodByReceiverType(t *testing.T) {
	runner := `package runner

import (
	"os"
	"os/exec"
)

type Runner struct{}

func (r *Runner) Run() error { return exec.Command(os.Args[0], "run").Start() }

type Local struct{}

func (l Local) Run() error { return nil }

func NewLocal() Local { return Local{} }
`
	assert.Empty(t, selfExecPlaces(t, map[string]string{
		"runner/runner.go": runner,
		"runner/runner_test.go": `package runner_test

import (
	"testing"

	"example.com/rulestest/runner"
)

func TestLocal(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		l := runner.NewLocal()
		_ = l.Run()
	})
}
`,
	}))
}

// A TestMain whose check of the environment comes after m.Run answers no
// child: the child has run the suite by then.
func TestSelfExecInTestRule_CheckAfterRun(t *testing.T) {
	assert.Equal(t, []string{"internal/cachesweep/sweep.go:18"}, selfExecPlaces(t, selfExecFiles(map[string]string{
		"internal/cachesweep/sweep.go":      selfExecSweep,
		"internal/cachesweep/sweep_test.go": selfExecSweepTest,
		"internal/cachesweep/main_test.go": `package cachesweep

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	if os.Getenv("KEEP_STATE") == "" {
		os.Exit(code)
	}
	os.Exit(code)
}
`,
	})))
}

// The own path a literal returns to whoever runs it is not what the
// function around it returns, and os.Args[1] is an argument, not the own
// executable.
func TestSelfExecInTestRule_NotTheOwnPath(t *testing.T) {
	assert.Empty(t, selfExecPlaces(t, map[string]string{
		"tool/tool.go": `package tool

import (
	"os"
	"os/exec"
)

func toolPath(describe func(func() string) string) string {
	_ = describe(func() string {
		exe, _ := os.Executable()
		return exe
	})
	return "/usr/bin/tool"
}

func Run(describe func(func() string) string) error {
	return exec.Command(toolPath(describe)).Run()
}

func FromArg() error {
	return exec.Command(os.Args[1]).Run()
}
`,
		"tool/tool_test.go": `package tool

import "testing"

func TestRun(t *testing.T) {
	_ = Run(func(f func() string) string { return f() })
	_ = FromArg()
}
`,
	}))
}

// selfExecEnvFallback falls back to the own executable when an environment
// variable names no binary.
const selfExecEnvFallback = `package tool

import (
	"os"
	"os/exec"
)

func runSelf(args ...string) (string, error) {
	exe := os.Getenv("TOOL_BIN")
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	out, err := exec.Command(exe, args...).Output()
	return string(out), err
}

func binPath() string {
	if p := os.Getenv("TOOL_BIN"); p != "" {
		return p
	}
	exe, _ := os.Executable()
	return exe
}

func Plan() (string, error) { return runSelf("plan") }

func Apply() error { return exec.Command(binPath(), "apply").Run() }

func direct() string {
	if os.Getenv("TOOL_BIN") != "" {
		return os.Getenv("TOOL_BIN")
	}
	exe, _ := os.Executable()
	return exe
}

func Direct() error { return exec.Command(direct(), "direct").Run() }
`

// The own executable as the fallback of an environment variable is not
// reached by a test that sets the variable, through a fixture too; a test
// that leaves it unset or empty reaches the own executable.
func TestSelfExecInTestRule_EnvironmentFallback(t *testing.T) {
	fixture := `package tool

import (
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) {
	t.Helper()
	t.Setenv("TOOL_BIN", filepath.Join(t.TempDir(), "tool"))
}

func TestPlan(t *testing.T) {
	fixture(t)
	_, _ = Plan()
	_ = Apply()
	_ = Direct()
}
`
	assert.Empty(t, selfExecPlaces(t, map[string]string{"tool/tool.go": selfExecEnvFallback, "tool/tool_test.go": fixture}))

	unset := fixture + `
func TestApplyBare(t *testing.T) {
	t.Setenv("TOOL_BIN", "")
	_ = Apply()
}
`
	violations := rulestest.RunRuleOnFiles(t, NewSelfExecInTestRule(), map[string]string{"tool/tool.go": selfExecEnvFallback, "tool/tool_test.go": unset})
	require.Equal(t, []string{"tool/tool.go:31"}, rulestest.ViolationPlaces(violations))
	assert.Contains(t, violations[0].Message, "TestApplyBare")
}

// selfExecMultiCall is a multi-call binary: the first argument names the
// function, and one of them starts the binary again.
const selfExecMultiCall = `package tool

import (
	"os"
	"os/exec"
)

func Run(args []string) error {
	name := args[0]
	switch name {
	case "plan", "list":
		return nil
	case "relaunch":
		return relaunch("again")
	case "self":
		return exec.Command(os.Args[0], "child").Run()
	default:
		return relaunch(name)
	}
}

func relaunch(arg string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return exec.Command(exe, arg).Run()
}
`

const selfExecDispatchFixture = `package tool

import (
	"slices"
	"testing"
)

type fixture struct{ dir string }

func (f fixture) call(name string, args ...string) error {
	full := append([]string{name, "-dir", f.dir}, args...)
	return Run(full)
}

func TestPlan(t *testing.T) {
	f := fixture{dir: t.TempDir()}
	if err := f.call("plan"); err != nil {
		t.Fatal(err)
	}
	args := []string{"plan", "-v"}
	_ = Run(args)
	bad := append([]string(nil), args...)
	bad[1] = "-q"
	_ = Run(bad)
	_ = Run(slices.Clone(args))
	for _, name := range []string{"plan", "list"} {
		_ = Run([]string{name})
	}
	build := func(v string) []string { return []string{"plan", v} }
	_ = Run(build("x"))
	more := []string{"list"}
	if testing.Short() {
		more = append(more, "-short")
	}
	_ = Run(more)
	nested := func() []string {
		inner := func() []string { return []string{"relaunch"} }
		_ = inner
		return []string{"plan"}
	}
	_ = Run(nested())
}
`

// A test that names the function of a multi-call binary does not reach the
// other cases of the switch on that name; naming the case that starts the
// binary, or one that falls to the default, does.
func TestSelfExecInTestRule_DispatchByName(t *testing.T) {
	assert.Empty(t, selfExecPlaces(t, map[string]string{"tool/tool.go": selfExecMultiCall, "tool/tool_test.go": selfExecDispatchFixture}))

	for name, tc := range map[string]struct {
		test   string
		places []string
	}{
		"case":     {"\nfunc TestRelaunch(t *testing.T) { _ = fixture{}.call(\"relaunch\") }\n", []string{"tool/tool.go:27"}},
		"default":  {"\nfunc TestRelaunch(t *testing.T) { _ = Run([]string{\"other\"}) }\n", []string{"tool/tool.go:27"}},
		"inline":   {"\nfunc TestRelaunch(t *testing.T) { _ = Run([]string{\"self\"}) }\n", []string{"tool/tool.go:16"}},
		"unknown":  {"\nfunc TestRelaunch(t *testing.T) { _ = Run(nil) }\n", []string{"tool/tool.go:16", "tool/tool.go:27"}},
		"range":    {"\nfunc TestRelaunch(t *testing.T) {\n\tfor _, name := range []string{\"plan\", \"relaunch\"} {\n\t\t_ = Run([]string{name})\n\t}\n}\n", []string{"tool/tool.go:27"}},
		"closure":  {"\nfunc TestRelaunch(t *testing.T) {\n\tbuild := func(n int) []string {\n\t\tif n > 0 {\n\t\t\treturn []string{\"relaunch\"}\n\t\t}\n\t\treturn []string{\"plan\"}\n\t}\n\t_ = Run(build(1))\n}\n", []string{"tool/tool.go:27"}},
		"dynamic":  {"\nfunc other() string { return \"relaunch\" }\n\nfunc TestRelaunch(t *testing.T) {\n\tfor _, n := range []string{\"plan\", other()} {\n\t\t_ = Run([]string{n})\n\t}\n}\n", []string{"tool/tool.go:16", "tool/tool.go:27"}},
		"reassign": {"\nfunc TestRelaunch(t *testing.T) {\n\tname := \"relaunch\"\n\tif testing.Short() {\n\t\tname = \"plan\"\n\t}\n\t_ = Run([]string{name})\n}\n", []string{"tool/tool.go:16", "tool/tool.go:27"}},
		"naked":    {"\nfunc TestRelaunch(t *testing.T) {\n\tbuild := func(n int) (out []string) {\n\t\tif n > 0 {\n\t\t\tout = []string{\"relaunch\"}\n\t\t\treturn\n\t\t}\n\t\treturn []string{\"plan\"}\n\t}\n\t_ = Run(build(1))\n}\n", []string{"tool/tool.go:16", "tool/tool.go:27"}},
		"param":    {"\nfunc callWith(name string) error {\n\tbuild := func(n int) []string {\n\t\tif n > 0 {\n\t\t\treturn []string{name}\n\t\t}\n\t\treturn []string{\"plan\"}\n\t}\n\treturn Run(build(1))\n}\n\nfunc TestRelaunch(t *testing.T) { _ = callWith(\"relaunch\") }\n", []string{"tool/tool.go:16", "tool/tool.go:27"}},
		"twice":    {"\nfunc TestRelaunch(t *testing.T) {\n\tbuild := func() []string { return []string{\"plan\"} }\n\tbuild = func() []string { return []string{\"relaunch\"} }\n\t_ = Run(build())\n}\n", []string{"tool/tool.go:16", "tool/tool.go:27"}},
		"base":     {"\nfunc TestRelaunch(t *testing.T) {\n\tbase := []string{\"relaunch\"}\n\trest := []string{\"plan\"}\n\t_ = Run(append(base, rest...))\n}\n", []string{"tool/tool.go:27"}},
		"written":  {"\nfunc TestRelaunch(t *testing.T) {\n\targs := []string{\"plan\"}\n\targs[0] = \"relaunch\"\n\t_ = Run(args)\n}\n", []string{"tool/tool.go:16", "tool/tool.go:27"}},
	} {
		t.Run(name, func(t *testing.T) {
			violations := rulestest.RunRuleOnFiles(t, NewSelfExecInTestRule(), map[string]string{"tool/tool.go": selfExecMultiCall, "tool/tool_test.go": selfExecDispatchFixture + tc.test})
			require.Equal(t, tc.places, rulestest.ViolationPlaces(violations))
			assert.Contains(t, violations[0].Message, "TestRelaunch")
		})
	}
}

// A call of a local variable of a test is not a call of the package function
// of the same name.
func TestSelfExecInTestRule_LocalShadowsFunction(t *testing.T) {
	tool := `package tool

import (
	"os"
	"os/exec"
)

func run(args []string) error { return exec.Command(os.Args[0], args...).Run() }

func Run(args []string) error { return run(args) }

func count(dir string) int { return len(dir) }
`
	test := `package tool

import (
	"os/exec"
	"testing"
)

func TestCount(t *testing.T) {
	run := func() int { return count(t.TempDir()) }
	if run() != run() {
		t.Fatal("unstable")
	}
	for _, exec := range []func() error{func() error { return nil }} {
		_ = exec()
	}
	_ = exec.ErrNotFound
}

func TestRange(t *testing.T) {
	for _, run := range []func(){func() {}} {
		run()
	}
}

func TestVar(t *testing.T) {
	var run = func() {}
	run()
}

func TestLiteral(t *testing.T) {
	func(run func()) { run() }(func() {})
}

func each(t *testing.T, run func()) { run() }

func TestHelper(t *testing.T) { each(t, func() {}) }
`
	ext := `package tool_test

import (
	"testing"

	"example.com/rulestest/tool"
)

type fake struct{}

func (fake) Run(args []string) error { return nil }

func TestSelector(t *testing.T) {
	tool := fake{}
	_ = tool.Run(nil)
}
`
	assert.Empty(t, selfExecPlaces(t, map[string]string{"tool/tool.go": tool, "tool/tool_test.go": test, "tool/ext_test.go": ext}))
}

// The child branch of a helper-process test runs in the helper the test
// starts with -test.run: what it calls is the helper's work, not a start of
// the suite; the parent branch is followed as any test.
func TestSelfExecInTestRule_HelperProcessChildBranch(t *testing.T) {
	test := `package tool

import (
	"os"
	"os/exec"
	"testing"
)

func TestMainExitCode(t *testing.T) {
	if os.Getenv("TOOL_CHILD") == "1" {
		os.Args = []string{"tool", "plan"}
		_ = Run(os.Args[1:])
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainExitCode$")
	cmd.Env = append(os.Environ(), "TOOL_CHILD=1")
	_ = cmd.Run()
}
`
	assert.Empty(t, selfExecPlaces(t, map[string]string{"tool/tool.go": selfExecMultiCall, "tool/tool_test.go": test}))

	parent := strings.Replace(test, "\t_ = cmd.Run()\n", "\t_ = cmd.Run()\n\t_ = Run([]string{\"relaunch\"})\n", 1)
	assert.Equal(t, []string{"tool/tool.go:27"}, selfExecPlaces(t, map[string]string{"tool/tool.go": selfExecMultiCall, "tool/tool_test.go": parent}))

	other := strings.Replace(test, "\tcmd := exec.Command", "\tif t.Name() == \"\" {\n\t\t_ = Run([]string{\"relaunch\"})\n\t\treturn\n\t}\n\tcmd := exec.Command", 1)
	assert.Equal(t, []string{"tool/tool.go:27"}, selfExecPlaces(t, map[string]string{"tool/tool.go": selfExecMultiCall, "tool/tool_test.go": other}))

	open := strings.Replace(test, "\t\t_ = Run(os.Args[1:])\n\t\treturn\n", "\t\t_ = Run([]string{\"relaunch\"})\n", 1)
	assert.Equal(t, []string{"tool/tool.go:27"}, selfExecPlaces(t, map[string]string{"tool/tool.go": selfExecMultiCall, "tool/tool_test.go": open}))
}

// A helper child that sets os.Args and calls main names the function of a
// multi-call binary as a test that passes it to the dispatcher does.
func TestSelfExecInTestRule_ChildSetsArgs(t *testing.T) {
	tool := strings.Replace(selfExecMultiCall, "package tool", "package main", 1) + "\nfunc main() { _ = Run(os.Args[1:]) }\n"
	test := `package main

import (
	"os"
	"os/exec"
	"testing"
)

func child() bool {
	if os.Getenv("TOOL_CHILD") != "1" {
		return false
	}
	os.Args = []string{"tool", "plan"}
	main()
	return true
}

func start(t *testing.T, name string) {
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$")
	cmd.Env = append(os.Environ(), "TOOL_CHILD=1")
	_ = cmd.Run()
}

func TestExit(t *testing.T) {
	if child() {
		return
	}
	start(t, "TestExit")
}
`
	assert.Empty(t, selfExecPlaces(t, map[string]string{"cmd/tool/main.go": tool, "cmd/tool/main_test.go": test}))

	relaunch := strings.Replace(test, `"tool", "plan"`, `"tool", "relaunch"`, 1)
	assert.Equal(t, []string{"cmd/tool/main.go:27"}, selfExecPlaces(t, map[string]string{"cmd/tool/main.go": tool, "cmd/tool/main_test.go": relaunch}))

	through := strings.Replace(test, "\tmain()\n", "\trunMain()\n", 1) + "\nfunc runMain() { main() }\n"
	assert.Empty(t, selfExecPlaces(t, map[string]string{"cmd/tool/main.go": tool, "cmd/tool/main_test.go": through}))

	index := strings.Replace(tool, "Run(os.Args[1:])", "Run([]string{os.Args[1]})", 1)
	assert.Empty(t, selfExecPlaces(t, map[string]string{"cmd/tool/main.go": index, "cmd/tool/main_test.go": test}))

	every := []string{"cmd/tool/main.go:16", "cmd/tool/main.go:27"}
	short := strings.Replace(test, `"tool", "plan"`, `"tool"`, 1)
	assert.Equal(t, every, selfExecPlaces(t, map[string]string{"cmd/tool/main.go": tool, "cmd/tool/main_test.go": short}))

	twice := strings.Replace(test, "\tos.Args = []string{\"tool\", \"plan\"}\n", "\tos.Args = []string{\"tool\", \"relaunch\"}\n\tos.Args = []string{\"tool\", \"plan\"}\n", 1)
	assert.Equal(t, every, selfExecPlaces(t, map[string]string{"cmd/tool/main.go": tool, "cmd/tool/main_test.go": twice}))

	later := strings.Replace(tool, "Run(os.Args[1:])", "Run(os.Args[2:])", 1)
	assert.Equal(t, every, selfExecPlaces(t, map[string]string{"cmd/tool/main.go": later, "cmd/tool/main_test.go": test}))
}

// A function of an external test package does not stand for the function of
// the same name of the package under test.
func TestSelfExecInTestRule_ExternalTestOwnFunction(t *testing.T) {
	tool := `package tool

import (
	"os"
	"os/exec"
)

func start() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return exec.Command(exe).Run()
}
`
	test := `package tool_test

import "testing"

func start() {}

func TestStart(t *testing.T) { start() }
`
	assert.Empty(t, selfExecPlaces(t, map[string]string{"tool/tool.go": tool, "tool/tool_test.go": test}))
}

// The switch on a name is decided only where each case is one constant and
// the name is a parameter the body does not assign; a switch on a constant
// is decided as well.
func TestSelfExecInTestRule_DispatchSwitchForms(t *testing.T) {
	relaunch := `

func relaunch() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return exec.Command(exe).Run()
}
`
	head := "package tool\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\n"
	for name, tc := range map[string]struct {
		tool, test string
		reported   bool
	}{
		"dynamic case": {
			"func other() string { return \"x\" }\n\nfunc Run(args []string) error {\n\tswitch args[0] {\n\tcase \"plan\":\n\t\treturn nil\n\tcase other():\n\t\treturn relaunch()\n\t}\n\treturn nil\n}",
			"_ = Run([]string{\"plan\"})", true,
		},
		"case of many values": {
			"func Run(args []string) error {\n\tfor _, m := range []string{\"other\", \"relaunch\"} {\n\t\tswitch args[0] {\n\t\tcase m:\n\t\t\treturn relaunch()\n\t\t}\n\t}\n\treturn nil\n}",
			"_ = Run([]string{\"relaunch\"})", true,
		},
		"assigned parameter": {
			"func Run(args []string) error {\n\targs = []string{\"relaunch\"}\n\tswitch args[0] {\n\tcase \"relaunch\":\n\t\treturn relaunch()\n\t}\n\treturn nil\n}",
			"_ = Run([]string{\"plan\"})", true,
		},
		"second element": {
			"func Run(args []string) error {\n\tswitch args[1] {\n\tcase \"relaunch\":\n\t\treturn relaunch()\n\t}\n\treturn nil\n}",
			"_ = Run([]string{\"plan\", \"relaunch\"})", true,
		},
		"constant": {
			"const mode = \"plan\"\n\nfunc Start() error {\n\tswitch mode {\n\tcase \"relaunch\":\n\t\treturn relaunch()\n\t}\n\treturn nil\n}",
			"_ = Start()", false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			tool := head + tc.tool + relaunch
			test := "package tool\n\nimport \"testing\"\n\nfunc TestRun(t *testing.T) {\n\t" + tc.test + "\n}\n"
			places := selfExecPlaces(t, map[string]string{"tool/tool.go": tool, "tool/tool_test.go": test})
			if !tc.reported {
				assert.Empty(t, places)
				return
			}
			line := strings.Count(tool[:strings.Index(tool, "exec.Command(exe)")], "\n") + 1
			assert.Equal(t, []string{fmt.Sprintf("tool/tool.go:%d", line)}, places)
		})
	}
}

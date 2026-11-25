package qarules

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// selfExecBooms lists the places of the lines marked "// boom" in the files.
func selfExecBooms(files map[string]string) []string {
	places := []string{}
	for path, src := range files {
		for i, line := range strings.Split(src, "\n") {
			if strings.HasSuffix(line, "// boom") {
				places = append(places, fmt.Sprintf("%s:%d", path, i+1))
			}
		}
	}
	slices.Sort(places)
	return places
}

// selfExecExpect runs the rule on the files and expects a finding on every
// line marked "// boom" and nowhere else.
func selfExecExpect(t *testing.T, files map[string]string) {
	t.Helper()
	places := selfExecPlaces(t, files)
	if places == nil {
		places = []string{}
	}
	assert.Equal(t, selfExecBooms(files), places)
}

// selfExecCases runs each case as a subtest of a package app: app/app.go
// and app/app_test.go, and more files where a case names them.
func selfExecCases(t *testing.T, cases map[string]map[string]string) {
	t.Helper()
	for name, files := range cases {
		t.Run(name, func(t *testing.T) { selfExecExpect(t, files) })
	}
}

const selfExecDaemonPkg = `package daemon

import (
	"os"
	"os/exec"
)

type Daemon struct{}

func New() *Daemon { return &Daemon{} }

func (d *Daemon) Start() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return exec.Command(exe, "serve").Start() // boom
}
`

// A test variable named after the package it is built from: the name on the
// right of := is still the package, and the type resolution of the receiver
// must not chase the variable through its own declaration (it overflowed
// the stack and took the whole run down).
func TestSelfExecInTestRule_VariableNamedAfterPackage(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"define": {
			"daemon/daemon.go": selfExecDaemonPkg,
			"app/app.go":       "package app\n",
			"app/app_test.go": `package app

import (
	"testing"

	"example.com/rulestest/daemon"
)

func TestDaemon(t *testing.T) {
	daemon := daemon.New()
	_ = daemon.Start()
}
`,
		},
		"var": {
			"daemon/daemon.go": selfExecDaemonPkg,
			"app/app.go":       "package app\n",
			"app/app_test.go": `package app

import (
	"testing"

	"example.com/rulestest/daemon"
)

func TestDaemon(t *testing.T) {
	var daemon = daemon.New()
	_ = daemon.Start()
}
`,
		},
	})
}

// A local name shadows a function of the package only in its own scope: a
// sibling literal that declares cleanup does not hide the call of the
// package's cleanup in the other one.
func TestSelfExecInTestRule_ShadowOnlyInScope(t *testing.T) {
	src := `package app

import (
	"os"
	"os/exec"
)

func cleanup(dir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return exec.Command(exe, "cleanup", dir).Start() // boom
}
`
	selfExecCases(t, map[string]map[string]string{
		"sibling literal": {"app/app.go": src, "app/app_test.go": `package app

import "testing"

func TestCleanup(t *testing.T) {
	t.Run("runs", func(t *testing.T) {
		_ = cleanup(t.TempDir())
	})
	t.Run("deferred", func(t *testing.T) {
		cleanup := func() {}
		defer cleanup()
	})
}
`},
		"declared later": {"app/app.go": src, "app/app_test.go": `package app

import "testing"

func TestCleanup(t *testing.T) {
	_ = cleanup(t.TempDir())
	cleanup := func(string) error { return nil }
	_ = cleanup("x")
}
`},
	})
	// The shadow in scope still hides the package function.
	quiet := strings.ReplaceAll(src, " // boom", "")
	assert.Empty(t, selfExecPlaces(t, map[string]string{"app/app.go": quiet, "app/app_test.go": `package app

import "testing"

func TestCleanup(t *testing.T) {
	cleanup := func(string) error { return nil }
	_ = cleanup(t.TempDir())
}
`}))
}

const selfExecToolEnv = `package app

import (
	"os"
	"os/exec"
)

const EnvTool = "APP_TOOL"

func toolPath() string {
	if p := os.Getenv("APP_TOOL"); p != "" {
		return p
	}
	exe, _ := os.Executable()
	return exe
}

func Apply() error { return exec.Command(toolPath(), "apply").Run() }
`

// An environment variable that replaces the own path counts only where it
// is set on the path to the launch: before the call, in a block around it.
func TestSelfExecInTestRule_EnvironmentOnThePath(t *testing.T) {
	boom := strings.Replace(selfExecToolEnv, `"apply").Run() }`, `"apply").Run() } // boom`, 1)
	cases := map[string]string{
		"sibling subtest": `func TestApply(t *testing.T) {
	t.Run("stub", func(t *testing.T) {
		t.Setenv("APP_TOOL", "/bin/true")
		_ = Apply()
	})
	t.Run("default", func(t *testing.T) {
		_ = Apply()
	})
}`,
		"set after the call": `func TestApply(t *testing.T) {
	_ = Apply()
	t.Setenv("APP_TOOL", "/bin/true")
}`,
		"set in a branch": `func TestApply(t *testing.T) {
	if testing.Short() {
		t.Setenv("APP_TOOL", "/bin/true")
	}
	_ = Apply()
}`,
		"set in another test": `func TestStub(t *testing.T) {
	t.Setenv("APP_TOOL", "/bin/true")
}

func TestApply(t *testing.T) { _ = Apply() }`,
		"TestMain sets it after the tests": `func TestMain(m *testing.M) {
	code := m.Run()
	_ = os.Setenv("APP_TOOL", "/bin/true")
	os.Exit(code)
}

func TestApply(t *testing.T) { _ = Apply() }`,
	}
	quiet := map[string]string{
		"set before the subtests": `func TestApply(t *testing.T) {
	t.Setenv("APP_TOOL", "/bin/true")
	t.Run("default", func(t *testing.T) {
		_ = Apply()
	})
}`,
		"package constant": `func TestApply(t *testing.T) {
	t.Setenv(EnvTool, "/bin/true")
	_ = Apply()
}`,
		"constant of the test file": `const stubTool = "APP_TOOL"

func TestApply(t *testing.T) {
	t.Setenv(stubTool, "/bin/true")
	_ = Apply()
}`,
		"helper before the call": `func stub(t *testing.T) { t.Setenv("APP_TOOL", "/bin/true") }

func TestApply(t *testing.T) {
	stub(t)
	_ = Apply()
}`,
		"TestMain sets it": `func TestMain(m *testing.M) {
	_ = os.Setenv("APP_TOOL", "/bin/true")
	os.Exit(m.Run())
}

func TestApply(t *testing.T) { _ = Apply() }`,
	}
	all := map[string]map[string]string{}
	head := "package app\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nvar _ = os.Args\n\n"
	for name, test := range cases {
		all[name] = map[string]string{"app/app.go": boom, "app/app_test.go": head + test + "\n"}
	}
	for name, test := range quiet {
		all[name] = map[string]string{"app/app.go": selfExecToolEnv, "app/app_test.go": head + test + "\n"}
	}
	all["constant from an external test"] = map[string]string{"app/app.go": selfExecToolEnv, "app/app_test.go": `package app_test

import (
	"testing"

	"example.com/rulestest/app"
)

func TestApply(t *testing.T) {
	t.Setenv(app.EnvTool, "/bin/true")
	_ = app.Apply()
}
`}
	selfExecCases(t, all)
}

const selfExecSync = `package app

import (
	"os"
	"os/exec"
)

func Sync() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return exec.Command(exe, "sync-worker").Start() // boom
}
`

// TestMain answers a child only where the branch the child takes - with what
// the launch sets - exits before m.Run.
func TestSelfExecInTestRule_TestMainAnswersTheLaunch(t *testing.T) {
	quiet := strings.ReplaceAll(selfExecSync, " // boom", "")
	selfExecCases(t, map[string]map[string]string{
		"requires a variable": {"app/app.go": selfExecSync, "app/app_test.go": `package app

import (
	"log"
	"os"
	"testing"
)

var dsn string

func TestMain(m *testing.M) {
	if dsn = os.Getenv("APP_DSN"); dsn == "" {
		log.Fatal("APP_DSN is required")
	}
	os.Exit(m.Run())
}

func TestSync(t *testing.T) { _ = Sync() }
`},
		"another marker": {"app/app.go": selfExecSync, "app/app_test.go": `package app

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_BE_CRASHER") == "1" {
		fmt.Println("crash")
		os.Exit(3)
	}
	os.Exit(m.Run())
}

func TestCrash(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "APP_BE_CRASHER=1")
	_ = cmd.Run()
}

func TestSync(t *testing.T) { _ = Sync() }
`},
		"child runs the suite": {"app/app.go": quiet, "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_CHILD") == "1" {
		os.Exit(m.Run())
	}
	os.Exit(m.Run())
}

func TestCrash(t *testing.T) {
	cmd := exec.Command(os.Args[0]) // boom
	cmd.Env = append(os.Environ(), "APP_CHILD=1")
	_ = cmd.Run()
}
`},
		"argument the launch passes": {"app/app.go": quiet, "app/app_test.go": `package app

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "sync-worker" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSync(t *testing.T) { _ = Sync() }
`},
		"argument the launch does not pass": {"app/app.go": selfExecSync, "app/app_test.go": `package app

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "other-worker" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSync(t *testing.T) { _ = Sync() }
`},
	})
}

// -test.run makes a helper process only for the launch that passes it, and
// only where the test the child runs answers the child instead of starting
// it again.
func TestSelfExecInTestRule_HelperLaunchItself(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"literal elsewhere in the body": {"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func runCLI(t *testing.T, viaHelper bool, args ...string) error {
	if viaHelper {
		return exec.Command(os.Args[0], "-test.run=TestHelperProcess").Run()
	}
	return exec.Command(os.Args[0], args...).Run() // boom
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("APP_HELPER") != "1" {
		return
	}
	os.Exit(0)
}

func TestServe(t *testing.T) { _ = runCLI(t, false, "serve") }
`},
		"child without a guard": {"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestCrash(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestCrash") // boom
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	if err := cmd.Run(); err == nil {
		t.Fatal("want exit status 1")
	}
}
`},
		"guard on another variable": {"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestCrash(t *testing.T) {
	if os.Getenv("OTHER") == "1" {
		os.Exit(1)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCrash") // boom
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	_ = cmd.Run()
}
`},
		"guarded child": {"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestCrash(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		os.Exit(1)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCrash")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	_ = cmd.Run()
}
`},
		"pattern in a constant": {"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

const helperRun = "-test.run=^TestHelperProcess$"

func TestHelperProcess(t *testing.T) {
	if os.Getenv("APP_HELPER") != "1" {
		return
	}
	os.Exit(0)
}

func TestTool(t *testing.T) {
	cmd := exec.Command(os.Args[0], helperRun, "--", "echo")
	cmd.Env = append(os.Environ(), "APP_HELPER=1")
	_ = cmd.Run()
}
`},
		"arguments from a function": {"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func helperArgs(args ...string) []string {
	return append([]string{"-test.run=TestHelperProcess", "--"}, args...)
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("APP_HELPER") != "1" {
		return
	}
	os.Exit(0)
}

func TestTool(t *testing.T) {
	cmd := exec.Command(os.Args[0], helperArgs("echo")...)
	cmd.Env = append(os.Environ(), "APP_HELPER=1")
	_ = cmd.Run()
}
`},
	})
}

// A fallthrough carries the case of the name into the next one.
func TestSelfExecInTestRule_DispatchFallthrough(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"fallthrough": {"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func Run(args []string) error {
	switch args[0] {
	case "update":
		fallthrough
	case "restart":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		return exec.Command(exe, "serve").Start() // boom
	case "status":
		return nil
	}
	return nil
}
`, "app/app_test.go": "package app\n\nimport \"testing\"\n\nfunc TestUpdate(t *testing.T) { _ = Run([]string{\"update\"}) }\n"},
	})
}

// Forms of the own path the analysis follows to a launch.
func TestSelfExecInTestRule_PathForms(t *testing.T) {
	test := func(call string) string {
		return "package app\n\nimport \"testing\"\n\nfunc TestRun(t *testing.T) { _ = " + call + " }\n"
	}
	selfExecCases(t, map[string]map[string]string{
		"launcher in a package variable": {"app/app.go": `package app

import (
	"os"
	"os/exec"
)

var execCommand = exec.Command

func Cleanup() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return execCommand(exe, "cleanup").Start() // boom
}
`, "app/app_test.go": test("Cleanup()")},
		"closure in a variable": {"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func Run(n int) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	restart := func(mode string) error {
		return exec.Command(exe, mode).Start() // boom
	}
	if n > 3 {
		return restart("recover")
	}
	return nil
}
`, "app/app_test.go": test("Run(5)")},
		"path set on the command": {"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func Respawn() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command("worker", "serve")
	cmd.Path = exe // boom
	return cmd.Start()
}
`, "app/app_test.go": test("Respawn()")},
		"look path": {"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func Upgrade() error {
	self, err := exec.LookPath(os.Args[0])
	if err != nil {
		return err
	}
	return exec.Command(self, "post-upgrade").Start() // boom
}
`, "app/app_test.go": test("Upgrade()")},
		"proc self exe": {"app/app.go": `package app

import "os/exec"

const selfExe = "/proc/self/exe"

func Reexec(name string) error {
	return exec.Command("/proc/self/exe", name).Start() // boom
}

func Reexec2() error { return exec.Command(selfExe).Start() } // boom
`, "app/app_test.go": test("Reexec(\"init\")") + "\nfunc TestRun2(t *testing.T) { _ = Reexec2() }\n"},
		"copy of os.Args": {"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func Fork() error {
	args := os.Args
	cmd := exec.Command(args[0], append([]string{"child"}, args[1:]...)...) // boom
	return cmd.Start()
}
`, "app/app_test.go": test("Fork()")},
		"variable of the test file": {"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

var selfBin = os.Args[0]

var other = name()

func name() string { return "x" }

func TestServe(t *testing.T) {
	_ = exec.Command(selfBin, "serve").Start() // boom
}

func TestLocal(t *testing.T) {
	selfBin := "/bin/true"
	_ = exec.Command(selfBin, "serve").Start()
}
`},
		"conversions": {"app/app.go": `package app

import (
	"os"
	"os/exec"
)

type Path string

func start(p Path) error { return exec.Command(string(p), "worker").Start() }

func Grow() error {
	exe, _ := os.Executable()
	return start(Path(exe)) // boom
}

func startGeneric[T ~string](p T) error { return exec.Command(string(p), "w").Start() }

func Grow2() error {
	exe, _ := os.Executable()
	return startGeneric(exe) // boom
}
`, "app/app_test.go": test("Grow()") + "\nfunc TestRun2(t *testing.T) { _ = Grow2() }\n"},
		"generic launcher of another package": {"gen/gen.go": `package gen

import "os/exec"

func Start[T ~string](path T, args ...string) error {
	return exec.Command(string(path), args...).Start()
}
`, "app/app.go": `package app

import (
	"os"

	"example.com/rulestest/gen"
)

type Path string

func Grow() {
	exe, _ := os.Executable()
	_ = gen.Start(exe, "worker") // boom
	go func() { _ = gen.Start(Path(exe), "worker") }() // boom
}
`, "app/app_test.go": "package app\n\nimport \"testing\"\n\nfunc TestRun(t *testing.T) { Grow() }\n"},
	})
}

// What a test replaces before the call is not the own path: a package
// variable holding the path or the launcher.
func TestSelfExecInTestRule_TestReplacesVariable(t *testing.T) {
	src := `package app

import (
	"os"
	"os/exec"
)

var selfPath, _ = os.Executable()

var execCommand = exec.Command

func Spawn() error { return exec.Command(selfPath, "worker").Start() } // boom

func Kick() error { return execCommand(os.Args[0], "kick").Start() } // boom
`
	quiet := strings.ReplaceAll(src, " // boom", "")
	selfExecCases(t, map[string]map[string]string{
		"replaced": {"app/app.go": quiet, "app/app_test.go": `package app

import (
	"os/exec"
	"testing"
)

func TestSpawn(t *testing.T) {
	old := selfPath
	selfPath = "/bin/true"
	defer func() { selfPath = old }()
	_ = Spawn()
}

func TestKick(t *testing.T) {
	execCommand = func(string, ...string) *exec.Cmd { return exec.Command("true") }
	_ = Kick()
}
`},
		"not replaced": {"app/app.go": src, "app/app_test.go": `package app

import "testing"

func TestSpawn(t *testing.T) { _ = Spawn() }

func TestKick(t *testing.T) { _ = Kick() }
`},
		"replaced in another test": {"app/app.go": src, "app/app_test.go": `package app

import "testing"

func TestStub(t *testing.T) { selfPath = "/bin/true" }

func TestSpawn(t *testing.T) { _ = Spawn() }

func TestKick(t *testing.T) { _ = Kick() }
`},
		"replaced by the own path": {"app/app.go": src, "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestSpawn(t *testing.T) {
	selfPath = os.Args[0]
	_ = Spawn()
}

func TestKick(t *testing.T) {
	execCommand = exec.Command
	_ = Kick()
}
`},
	})
}

// testing.Testing() behind a helper, or the test flags being registered,
// tells a test binary as well.
func TestSelfExecInTestRule_TestingThroughHelper(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"helpers": {"app/app.go": `package app

import (
	"flag"
	"os"
	"os/exec"
	"testing"
)

func inTest() bool { return testing.Testing() }

func underGoTest() bool { return flag.Lookup("test.v") != nil }

func Restart() error {
	if inTest() {
		return nil
	}
	exe, _ := os.Executable()
	return exec.Command(exe, "serve").Start()
}

func Restart2() error {
	if underGoTest() {
		return nil
	}
	exe, _ := os.Executable()
	return exec.Command(exe, "serve").Start()
}

func Restart3(detach bool) error {
	if testing.Testing() && detach {
		return nil
	}
	exe, _ := os.Executable()
	return exec.Command(exe, "serve").Start() // boom
}
`, "app/app_test.go": `package app

import "testing"

func TestRestart(t *testing.T)  { _ = Restart() }
func TestRestart2(t *testing.T) { _ = Restart2() }
func TestRestart3(t *testing.T) { _ = Restart3(false) }
`},
	})
}

// go test runs an example with an unordered output comment as well.
func TestSelfExecInTestRule_UnorderedOutputExample(t *testing.T) {
	selfExecExpect(t, map[string]string{
		"app/app.go": selfExecSync,
		"app/example_test.go": `package app_test

import "example.com/rulestest/app"

func ExampleSync() {
	_ = app.Sync()
	// Unordered output:
}
`,
	})
}

// A body that sets os.Args itself does not take the name its callers set:
// however many callers set it, the body is followed with its own.
func TestSelfExecInTestRule_OwnArgsOverCallers(t *testing.T) {
	src := `package main

import (
	"os"
	"os/exec"
)

func main() {
	switch os.Args[1] {
	case "serve":
		return
	case "boom":
		exe, _ := os.Executable()
		_ = exec.Command(exe).Start()
	}
}

func run(name string) {
	switch name {
	case "boom":
		exe, _ := os.Executable()
		_ = exec.Command(exe).Start()
	}
	os.Args = []string{"x", "serve"}
	main()
}
`
	var test strings.Builder
	test.WriteString("package main\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n")
	for i := range selfExecMaxContexts + 2 {
		fmt.Fprintf(&test, "\nfunc TestRun%d(t *testing.T) {\n\tos.Args = []string{\"x\", \"v%d\"}\n\trun(\"quiet\")\n}\n", i, i)
	}
	assert.Empty(t, selfExecPlaces(t, map[string]string{"cmd/app/main.go": src, "cmd/app/main_test.go": test.String()}))
}

// A body that sets os.Args from os.Args names nothing it knows: the cases
// of a switch on the name all stay, and the analysis does not chase the
// name through its own assignment.
func TestSelfExecInTestRule_ArgsFromArgs(t *testing.T) {
	selfExecExpect(t, map[string]string{
		"cmd/app/main.go": `package main

import (
	"os"
	"os/exec"
)

func main() {
	switch os.Args[1] {
	case "serve":
		return
	case "boom":
		exe, _ := os.Executable()
		_ = exec.Command(exe).Start() // boom
	}
}
`,
		"cmd/app/main_test.go": `package main

import (
	"os"
	"testing"
)

func TestMainArgs(t *testing.T) {
	os.Args = []string{"x", os.Args[1]}
	main()
}
`,
	})
}

// The child of a helper start sees the environment the start gives it: a
// start that names its whole environment leaves out what the parent has;
// in the child the branch of the parent is not taken. The helper branch
// itself proves nothing for go test, which may have its variable set: the
// fallback start in it is reported whether the start of the child sets
// the variable or not.
func TestSelfExecInTestRule_ChildEnvironment(t *testing.T) {
	tool := `package app

import (
	"os"
	"os/exec"
)

func Apply() error {
	path := os.Getenv("APP_TOOL")
	if path == "" {
		path, _ = os.Executable()
	}
	return exec.Command(path, "apply").Run()
}
`
	helper := func(env string) string {
		return `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("APP_CHILD") != "1" {
		return
	}
	_ = Apply()
}

func TestApply(t *testing.T) {
	t.Setenv("APP_TOOL", "/bin/true")
	_ = Apply()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = ` + env + `
	_ = cmd.Run()
}
`
	}
	sync := `package app

import (
	"os"
	"os/exec"
)

func Sync() error {
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "sync") // boom
	cmd.Env = []string{"APP_MODE=sync"}
	return cmd.Run()
}
`
	openSync := strings.Replace(sync, `[]string{"APP_MODE=sync"}`, `append(os.Environ(), "APP_MODE=sync")`, 1)
	sync = strings.Replace(sync, " // boom", "", 1)
	homeMain := `package app

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("HOME") == "" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSync(t *testing.T) { _ = Sync() }
`
	prefix := `package app

import (
	"os"
	"os/exec"
)

func Start(name string) error {
	exe, _ := os.Executable()
	cmd := exec.Command(exe) // boom
	cmd.Env = append(os.Environ(), "APP_MODE=t"+name)
	return cmd.Run()
}
`
	prefixMain := `package app

import (
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_MODE") != "" && !strings.HasPrefix(os.Getenv("APP_MODE"), "test") {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStart(t *testing.T) { _ = Start(t.Name()) }
`
	selfExecCases(t, map[string]map[string]string{
		"set by the start":      {"app/app.go": strings.Replace(tool, `"apply").Run()`, `"apply").Run() // boom`, 1), "app/app_test.go": helper(`append(os.Environ(), "APP_CHILD=1", "APP_TOOL=/bin/true")`)},
		"not set by the start":  {"app/app.go": strings.Replace(tool, `"apply").Run()`, `"apply").Run() // boom`, 1), "app/app_test.go": helper(`append(os.Environ(), "APP_CHILD=1")`)},
		"whole environment":     {"app/app.go": sync, "app/app_test.go": homeMain},
		"inherited environment": {"app/app.go": openSync, "app/app_test.go": homeMain},
		"other branch": {"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("APP_CHILD") == "1" {
		_, _ = os.Stdout.WriteString("child")
	} else {
		cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
		cmd.Env = append(os.Environ(), "APP_CHILD=1")
		_ = cmd.Run()
	}
}
`},
		"prefix of an unknown mode": {"app/app.go": prefix, "app/app_test.go": prefixMain},
		"nested branch": {"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("APP_CHILD") != "" {
		if os.Getenv("APP_CHILD") == "1" {
			_, _ = os.Stdout.WriteString("child")
			return
		}
		_, _ = os.Stdout.WriteString("unknown child")
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "APP_CHILD=1")
	_ = cmd.Run()
}
`},
	})
}

// selfExecHelperTest wraps the body of a test file of package app that
// imports os, os/exec, path/filepath, strconv and testing.
func selfExecHelperTest(body string) map[string]string {
	return map[string]string{"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

var _ = filepath.Join
var _ = strconv.Itoa

` + body}
}

// The helper child takes its branch where the start gives the variable a
// value the branch wants: a value with a part that is never empty, the
// same parameter the branch compares with, every value of a table of
// constants. A branch that ends in t.Fatal ends the child, and the
// command of the start may sit in an element of a slice.
func TestSelfExecInTestRule_HelperChildValues(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"temporary directory": selfExecHelperTest(`func TestCrash(t *testing.T) {
	if dir := os.Getenv("APP_CRASH_DIR"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "x"), nil, 0o600)
		return
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrash$")
	cmd.Env = append(os.Environ(), "APP_CRASH_DIR="+dir)
	_ = cmd.Run()
}
`),
		"joined path under a local constant": selfExecHelperTest(`func TestWatch(t *testing.T) {
	const helperEnv = "APP_WATCH_HELPER"
	if watched := os.Getenv(helperEnv); watched != "" {
		return
	}
	path := filepath.Join(t.TempDir(), "watched.log")
	cmd := exec.Command(os.Args[0], "-test.run=^TestWatch$")
	cmd.Env = append(os.Environ(), helperEnv+"="+path)
	_ = cmd.Run()
}
`),
		"number": selfExecHelperTest(`func TestPid(t *testing.T) {
	if os.Getenv("APP_PID") != "" {
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPid$")
	cmd.Env = append(os.Environ(), "APP_PID="+strconv.Itoa(os.Getpid()))
	_ = cmd.Run()
}
`),
		"fatal ends the child": selfExecHelperTest(`func TestSignal(t *testing.T) {
	if os.Getenv("APP_SIGNAL_HELPER") == "1" {
		_, _ = os.Stdout.WriteString("blocked")
		t.Fatal("run unexpectedly returned")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSignal$")
	cmd.Env = append(os.Environ(), "APP_SIGNAL_HELPER=1")
	_ = cmd.Run()
}
`),
		"blocks forever": selfExecHelperTest(`func TestCrashWait(t *testing.T) {
	if dir := os.Getenv("APP_CRASH_DIR"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "x"), nil, 0o600)
		select {}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashWait$")
	cmd.Env = append(os.Environ(), "APP_CRASH_DIR="+t.TempDir())
	_ = cmd.Run()
}
`),
		"loops forever": selfExecHelperTest(`func TestSpin(t *testing.T) {
	if os.Getenv("APP_SPIN") == "1" {
		for {
			_, _ = os.Stdout.WriteString(".")
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSpin$")
	cmd.Env = append(os.Environ(), "APP_SPIN=1")
	_ = cmd.Run()
}
`),
		"loop that breaks": selfExecHelperTest(`func TestSpinOnce(t *testing.T) {
	if os.Getenv("APP_SPIN") == "1" {
		for {
			break
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSpinOnce$") // boom
	cmd.Env = append(os.Environ(), "APP_SPIN=1")
	_ = cmd.Run()
}
`),
		"command in a slice": selfExecHelperTest(`func TestConcurrent(t *testing.T) {
	if os.Getenv("APP_CACHE_HELPER") == "1" {
		return
	}
	commands := make([]*exec.Cmd, 2)
	for i := range commands {
		commands[i] = exec.Command(os.Args[0], "-test.run=^TestConcurrent$")
		commands[i].Env = append(os.Environ(), "APP_CACHE_HELPER=1")
		_ = commands[i].Start()
	}
}
`),
		"same parameter": selfExecHelperTest(`func checkHelp(t *testing.T, tool string) {
	if os.Getenv("APP_HELP_CHILD") == tool {
		_, _ = os.Stdout.WriteString("help")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelp$")
	cmd.Env = append(os.Environ(), "APP_HELP_CHILD="+tool)
	_ = cmd.Run()
}

func TestHelp(t *testing.T) { checkHelp(t, "app") }
`),
		"table of constants": selfExecHelperTest(`func TestExitCodes(t *testing.T) {
	if arg := os.Getenv("APP_CLI"); arg != "" {
		os.Args = []string{"app", arg}
		return
	}
	for _, tc := range []struct {
		arg  string
		code int
	}{{"bad", 2}, {"missing", 1}} {
		t.Run(tc.arg, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestExitCodes$")
			cmd.Env = append(os.Environ(), "APP_CLI="+tc.arg)
			_ = cmd.Run()
		})
	}
}
`),
		"possibly empty value": selfExecHelperTest(`func TestMaybe(t *testing.T) {
	if os.Getenv("APP_MAYBE") != "" {
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMaybe$") // boom
	cmd.Env = append(os.Environ(), "APP_MAYBE="+os.Getenv("APP_OTHER"))
	_ = cmd.Run()
}
`),
	})
}

// go test starts the test binary with the environment of the user: a
// variable a helper start sets that the environment always has, such as
// HOME, is not empty there.
func TestSelfExecInTestRule_StandardVariable(t *testing.T) {
	selfExecExpect(t, map[string]string{
		"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func Sync() error {
	if os.Getenv("HOME") == "" {
		return nil
	}
	exe, _ := os.Executable()
	return exec.Command(exe, "sync").Start() // boom
}
`,
		"app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestSync(t *testing.T) { _ = Sync() }

func TestHelper(t *testing.T) {
	if os.Getenv("APP_HELPER") == "1" {
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelper$")
	cmd.Env = append(os.Environ(), "APP_HELPER=1", "HOME="+t.TempDir())
	_ = cmd.Run()
}
`,
	})
}

// TestMain answers the child through a helper that tells the child by its
// argument or its environment and serves it, or panics, before m.Run.
func TestSelfExecInTestRule_TestMainHelper(t *testing.T) {
	main := `package app

import (
	"os"
	"testing"
)

const panicHelper = "APP_TEST_PANIC"

func TestMain(m *testing.M) {
	if code, ok := runServeHelper(); ok {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func runServeHelper() (int, bool) {
	switch {
	case len(os.Args) > 1 && os.Args[1] == WatchCommand:
		return 0, true
	case os.Getenv(panicHelper) == "1":
		panic("boom")
	}
	return 0, false
}
`
	selfExecCases(t, map[string]map[string]string{
		"argument": {"app/app.go": `package app

import (
	"os"
	"os/exec"
)

const WatchCommand = "watch"

func Notify() error {
	exe, _ := os.Executable()
	return exec.Command(exe, WatchCommand).Start()
}
`, "app/main_test.go": main, "app/app_test.go": `package app

import "testing"

func TestNotify(t *testing.T) { _ = Notify() }
`},
		"panic": {"app/app.go": "package app\n\nconst WatchCommand = \"watch\"\n", "app/main_test.go": main, "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestPanic(t *testing.T) {
	exe, _ := os.Executable()
	cli := exec.Command(exe)
	cli.Env = append(os.Environ(), panicHelper+"=1")
	_ = cli.Run()
}
`},
	})
}

// A start through a launcher that builds the arguments and the environment
// itself gives the child what the launcher builds, with the parameters the
// call gives it.
func TestSelfExecInTestRule_LauncherBuildsTheStart(t *testing.T) {
	launcher := `package run

import "os/exec"

func Start(exe, mode string, env []string) error {
	cmd := exec.Command(exe, Args(mode)...)
	cmd.Env = env
	return cmd.Start()
}

func Args(mode string) []string { return []string{mode, "--quiet"} }
`
	main := `package app

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "watch" {
		os.Exit(0)
	}
	if os.Getenv("APP_CHILD") == "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
`
	selfExecCases(t, map[string]map[string]string{
		"arguments": {"run/run.go": launcher, "app/main_test.go": main, "app/app.go": `package app

import (
	"os"

	"example.com/rulestest/run"
)

func Notify() error {
	exe, _ := os.Executable()
	return run.Start(exe, "watch", nil)
}
`, "app/app_test.go": "package app\n\nimport \"testing\"\n\nfunc TestNotify(t *testing.T) { _ = Notify() }\n"},
		"other arguments": {"run/run.go": launcher, "app/main_test.go": main, "app/app.go": `package app

import (
	"os"

	"example.com/rulestest/run"
)

func Notify() error {
	exe, _ := os.Executable()
	return run.Start(exe, "serve", nil) // boom
}
`, "app/app_test.go": "package app\n\nimport \"testing\"\n\nfunc TestNotify(t *testing.T) { _ = Notify() }\n"},
		"environment of the launcher": {"run/run.go": launcher, "app/main_test.go": main, "app/app.go": `package app

import (
	"os"

	"example.com/rulestest/run"
)

func Notify() error {
	exe, _ := os.Executable()
	return run.Start(exe, "serve", []string{"APP_CHILD=1"})
}
`, "app/app_test.go": "package app\n\nimport \"testing\"\n\nfunc TestNotify(t *testing.T) { _ = Notify() }\n"},
	})
}

// The environment a helper builds from the variadic values it is given.
func TestSelfExecInTestRule_EnvironmentFromValues(t *testing.T) {
	selfExecExpect(t, selfExecHelperTest(`func TestProcessHelper(t *testing.T) {
	switch os.Getenv("APP_HELPER") {
	case "run":
		os.Exit(0)
	case "supervise":
		_, _ = startHelper("hold")
	default:
		return
	}
	os.Exit(0)
}

func processEnv(values ...string) []string {
	env := make([]string, 0, len(os.Environ())+len(values))
	env = append(env, os.Environ()...)
	return append(env, values...)
}

func startHelper(mode string, extra ...string) (*exec.Cmd, error) {
	values := []string{"APP_HELPER=run", "APP_MODE=" + mode}
	values = append(values, extra...)
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	cmd.Env = processEnv(values...)
	return cmd, cmd.Start()
}

func TestSupervise(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	cmd.Env = processEnv("APP_HELPER=supervise")
	_ = cmd.Run()
}
`))
}

// The helper of TestMain serves several children, each told by its own
// variable, and refuses arguments before and after it.
func TestSelfExecInTestRule_TestMainHelperChain(t *testing.T) {
	selfExecExpect(t, map[string]string{
		"app/app.go": "package app\n\nfunc Serve() int { return 0 }\n",
		"app/main_test.go": `package app

import (
	"os"
	"strings"
	"testing"
)

const (
	daemonHelper = "APP_TEST_DAEMON"
	panicHelper  = "APP_TEST_PANIC"
	plainHelper  = "APP_TEST_PLAIN"
)

func TestMain(m *testing.M) {
	for _, arg := range os.Args[1:] {
		if arg == "cleanup" {
			os.Exit(2)
		}
	}
	if os.Getenv(plainHelper) == "1" {
		os.Exit(Serve())
	}
	if code, ok := runHelper(); ok {
		os.Exit(code)
	}
	for _, arg := range os.Args[1:] {
		if !strings.HasPrefix(arg, "-test.") {
			os.Exit(2)
		}
	}
	os.Exit(m.Run())
}

func runHelper() (int, bool) {
	switch {
	case len(os.Args) > 1 && os.Args[1] == "watch":
		return 0, true
	case os.Getenv(daemonHelper) == "1":
		_ = os.Unsetenv(daemonHelper)
		return Serve(), true
	case os.Getenv(panicHelper) == "1":
		panic("boom")
	}
	return 0, false
}
`,
		"app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"slices"
	"testing"
)

func testBinary(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func runBinary(t *testing.T, helper string, env []string) error {
	cmd := exec.Command(testBinary(t))
	cmd.Env = append(slices.Clone(env), helper+"=1")
	return cmd.Run()
}

func TestDaemon(t *testing.T) {
	cmd := exec.Command(testBinary(t))
	cmd.Env = append(os.Environ(), daemonHelper+"=1", plainHelper+"=0")
	_ = cmd.Run()
	_ = runBinary(t, daemonHelper, os.Environ())
}

func TestPanic(t *testing.T) {
	cli := exec.Command(testBinary(t))
	cli.Env = append(os.Environ(), panicHelper+"=1")
	_ = cli.Run()
}
`,
	})
}

// A variable a test sets for a child through a shell, or through a helper
// given its name, is no more set by go test than one it sets on a start of
// the own executable.
func TestSelfExecInTestRule_VariablesOfOtherChildren(t *testing.T) {
	selfExecExpect(t, map[string]string{
		"app/main_test.go": `package app

import (
	"os"
	"testing"
)

const (
	shellHelper = "APP_TEST_SHELL"
	proxyHelper = "APP_TEST_PROXY"
	cliHelper   = "APP_TEST_CLI"
	panicHelper = "APP_TEST_PANIC"
)

func TestMain(m *testing.M) {
	switch {
	case os.Getenv(shellHelper) == "1":
		os.Exit(0)
	case os.Getenv(proxyHelper) == "1":
		os.Exit(0)
	case os.Getenv(cliHelper) == "1":
		os.Exit(0)
	case os.Getenv(panicHelper) == "1":
		panic("boom")
	}
	os.Exit(m.Run())
}
`,
		"app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func runBinary(t *testing.T, helper string, args ...string) {
	exe, _ := os.Executable()
	cmd := exec.Command("/bin/sh", append([]string{"-c", "exec \"$0\" \"$@\"", exe}, args...)...)
	cmd.Env = append(os.Environ(), helper+"=1")
	_ = cmd.Run()
}

func TestShell(t *testing.T) {
	exe, _ := os.Executable()
	cmd := exec.Command("/bin/sh", "-c", "exec \"$0\"", exe)
	cmd.Env = append(os.Environ(), shellHelper+"=1")
	_ = cmd.Run()
	runBinary(t, proxyHelper, "a")
	runBinary(t, cliHelper, "b")
}

func TestPanic(t *testing.T) {
	exe, _ := os.Executable()
	cli := exec.Command(exe)
	cli.Env = append(os.Environ(), panicHelper+"=1")
	_ = cli.Run()
}
`,
	})
}

// A multi-call binary whose tests each call the dispatcher with a name of
// their own: a dozen names are followed apart, as each reaches one case.
func TestSelfExecInTestRule_ManyNames(t *testing.T) {
	src := `package main

import (
	"os"
	"os/exec"
)

func run(args []string) error {
	switch args[0] {
	case "boom":
		exe, _ := os.Executable()
		return exec.Command(exe).Start()
	}
	return nil
}
`
	var test strings.Builder
	test.WriteString("package main\n\nimport \"testing\"\n")
	for i := range 12 {
		fmt.Fprintf(&test, "\nfunc TestRun%d(t *testing.T) { _ = run([]string{\"fn%d\", \"-check\"}) }\n", i, i)
	}
	assert.Empty(t, selfExecPlaces(t, map[string]string{"cmd/app/main.go": src, "cmd/app/main_test.go": test.String()}))
}

// A start reached only on the branch of TestMain that a variable takes
// passes that variable on to its child when it passes the environment on:
// the child takes the same branch and does not run the tests, but starts
// the next child on it, which starts the next in turn. go test may have
// the variable set, so the branch is reached.
func TestSelfExecInTestRule_BranchVariableInherited(t *testing.T) {
	main := `package main

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_AS_MAIN") == "1" {
		main()
	}
	for key, value := range map[string]string{"HOME": os.TempDir(), "APP_STATE": "x"} {
		_ = os.Setenv(key, value)
	}
	os.Exit(m.Run())
}
`
	app := func(env, mark string) string {
		return `package main

import (
	"os"
	"os/exec"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	os.Exit(serve(os.Args[1]))
}

func serve(command string) int {
	exe, _ := os.Executable()
	cmd := exec.Command(exe, command)` + mark + `
	cmd.Env = ` + env + `
	if cmd.Run() != nil {
		return 1
	}
	return 0
}

func withoutSocket(env []string) []string {
	out := make([]string, 0, len(env))
	for _, v := range env {
		if !strings.HasPrefix(v, "APP_SOCKET=") {
			out = append(out, v)
		}
	}
	return out
}
`
	}
	test := `package main

import (
	"os/exec"
	"testing"
)

func TestServe(t *testing.T) {
	_ = exec.Command("/bin/sh", "-c", "APP_AS_MAIN=1 exec \"$0\" serve", "/bin/true").Run()
}
`
	selfExecCases(t, map[string]map[string]string{
		"passed on": {"cmd/app/main.go": app("withoutSocket(os.Environ())", " // boom"), "cmd/app/main_test.go": main, "cmd/app/serve_test.go": test},
		"dropped":   {"cmd/app/main.go": app(`[]string{"APP_SOCKET=x"}`, " // boom"), "cmd/app/main_test.go": main, "cmd/app/serve_test.go": test},
		"unset on the way": {"cmd/app/main.go": app("withoutSocket(os.Environ())", " // boom"), "cmd/app/serve_test.go": test,
			"cmd/app/main_test.go": strings.Replace(main, "\t\tmain()", "\t\t_ = os.Unsetenv(\"APP_AS_MAIN\")\n\t\tmain()", 1)},
		"main that returns": {"cmd/app/main.go": strings.Replace(app("withoutSocket(os.Environ())", " // boom"), "\t\tos.Exit(2)", "\t\treturn", 1),
			"cmd/app/main_test.go": main, "cmd/app/serve_test.go": test},
	})
}

// An init of the package answers a child by the argv[0] its start gives
// through the Args of the command, before the tests run.
func TestSelfExecInTestRule_InitAnswersArgv0(t *testing.T) {
	pkg := `package reap

import "os"

const reaperArg0 = "app-reap"

func init() {
	if len(os.Args) >= 3 && os.Args[0] == reaperArg0 {
		os.Exit(0)
	}
}
`
	test := func(args, mark string) string {
		return `package reap

import (
	"os/exec"
	"testing"
)

func TestReap(t *testing.T) {
	missing := exec.Command("/proc/self/exe")` + mark + `
	missing.Args = ` + args + `
	_ = missing.Run()
}
`
	}
	selfExecCases(t, map[string]map[string]string{
		"argv0":           {"reap/reap.go": pkg, "reap/reap_test.go": test(`[]string{reaperArg0, "/nonexistent", "command"}`, "")},
		"other argv0":     {"reap/reap.go": pkg, "reap/reap_test.go": test(`[]string{"other", "/nonexistent", "command"}`, " // boom")},
		"too few":         {"reap/reap.go": pkg, "reap/reap_test.go": test(`[]string{reaperArg0, "/nonexistent"}`, " // boom")},
		"unknown argv0":   {"reap/reap.go": pkg, "reap/reap_test.go": test(`[]string{t.Name(), "/nonexistent", "command"}`, " // boom")},
		"argv0 set again": {"reap/reap.go": pkg, "reap/reap_test.go": test("[]string{reaperArg0, \"/nonexistent\", \"command\"}\n\tmissing.Args = []string{\"other\", \"/nonexistent\", \"command\"}", " // boom")},
		"init that returns": {"reap/reap.go": `package reap

import "os"

const reaperArg0 = "app-reap"

func init() {
	if os.Args[0] != reaperArg0 {
		return
	}
	os.Exit(0)
}
`, "reap/reap_test.go": test(`[]string{"other", "/nonexistent", "command"}`, " // boom")},
	})
}

// A path a helper returns with no error is never empty where every return
// of the helper either has an error or a name that is not empty, and the
// caller leaves on the error: the child the path is given to takes the
// branch that answers it.
func TestSelfExecInTestRule_NonEmptyOnSuccess(t *testing.T) {
	main := `package app

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if spec := os.Getenv(childEnv); spec != "" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
`
	app := func(write, check string) string {
		return `package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

const childEnv = "APP_CHILD_SPEC"

func Start(dir string) error {
	specPath, err := writeSpec(dir)
` + check + `
	return spawn(specPath)
}

func writeSpec(dir string) (string, error) {
` + write + `
}

func spawn(specPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe) // boom
	cmd.Env = append(os.Environ(), childEnv+"="+specPath)
	return errors.Join(cmd.Start(), fmt.Errorf("x"))
}
`
	}
	write := `	f, err := os.CreateTemp(dir, "spec-*.json")
	if err != nil {
		return "", fmt.Errorf("spec: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", errors.Join(fmt.Errorf("spec: %w", err), os.Remove(f.Name()))
	}
	return f.Name(), nil`
	check := "\tif err != nil {\n\t\treturn err\n\t}"
	test := "package app\n\nimport \"testing\"\n\nfunc TestStart(t *testing.T) { _ = Start(t.TempDir()) }\n"
	strip := func(src string) string { return strings.Replace(src, " // boom", "", 1) }
	selfExecCases(t, map[string]map[string]string{
		"checked":      {"app/app.go": strip(app(write, check)), "app/main_test.go": main, "app/app_test.go": test},
		"not checked":  {"app/app.go": app(write, "\t_ = err"), "app/main_test.go": main, "app/app_test.go": test},
		"empty return": {"app/app.go": app("\treturn \"\", nil", check), "app/main_test.go": main, "app/app_test.go": test},
		"error that may be nil": {"app/app.go": app(strings.Replace(write, `errors.Join(fmt.Errorf("spec: %w", err), os.Remove(f.Name()))`, "errors.Join(os.Remove(f.Name()))", 1), check),
			"app/main_test.go": main, "app/app_test.go": test},
		"error set again": {"app/app.go": app(strings.Replace(write, `		return "", fmt.Errorf("spec: %w", err)`, "\t\terr = os.Remove(dir)\n\t\treturn \"\", err", 1), check),
			"app/main_test.go": main, "app/app_test.go": test},
		"check that goes on": {"app/app.go": app(write, "\tif err != nil {\n\t\t_ = os.Remove(dir)\n\t}"), "app/main_test.go": main, "app/app_test.go": test},
		"helper used as a value": {"app/app.go": app(write, check) + "\nvar launcher = spawn\n", "app/main_test.go": main,
			"app/app_test.go": "package app\n\nimport \"testing\"\n\nfunc TestStart(t *testing.T) { _ = Start(t.TempDir()); _ = launcher(\"\") }\n"},
	})
}

// The names a body is followed with are bounded in each run apart: the
// branch of TestMain a variable takes is a run of its own, and its calls
// leave the tests their own bound.
func TestSelfExecInTestRule_NamesPerRun(t *testing.T) {
	src := `package main

import (
	"os"
	"os/exec"
)

func run(args []string) error {
	switch args[0] {
	case "boom":
		exe, _ := os.Executable()
		return exec.Command(exe).Start()
	}
	return nil
}
`
	var test strings.Builder
	test.WriteString("package main\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) {\n\tif os.Getenv(\"APP_AS_MAIN\") == \"1\" {\n")
	for i := range 8 {
		fmt.Fprintf(&test, "\t\t_ = run([]string{\"main%d\"})\n", i)
	}
	test.WriteString("\t\tos.Exit(0)\n\t}\n\tos.Exit(m.Run())\n}\n")
	for i := range 14 {
		fmt.Fprintf(&test, "\nfunc TestRun%d(t *testing.T) { _ = run([]string{\"fn%d\", \"-check\"}) }\n", i, i)
	}
	assert.Empty(t, selfExecPlaces(t, map[string]string{"cmd/app/main.go": src, "cmd/app/main_test.go": test.String()}))
}

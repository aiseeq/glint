package qarules

import (
	"fmt"
	"strings"
	"testing"
)

// selfExecSyncPkg is a function that starts the own executable where a
// variable of the environment holds a value, and gives the child the same
// value: under go test with the variable set, every child starts the next.
const selfExecSyncPkg = `package app

import (
	"os"
	"os/exec"
)

const AsyncEnv = "APP_ASYNC"

func Sync() error {
	if os.Getenv(AsyncEnv) == "1" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.Command(exe, "sync-worker") // boom
		cmd.Env = append(os.Environ(), AsyncEnv+"=1")
		return cmd.Start()
	}
	return nil
}
`

// A guard silences a start only where the rule proves it holds. A variable
// go test may get from its own environment (CI sets what it likes) is
// unknown there: a name the tests give another child, a name set through a
// range over a map or through a function, a name only the own starts set.
func TestSelfExecInTestRule_EnvironmentOfGoTestIsUnknown(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"variable another child gets": {
			"app/app.go": `package app

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
`,
			"app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_DSN") == "" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestServerBinary(t *testing.T) {
	cmd := exec.Command("app-server", "--check")
	cmd.Env = append(os.Environ(), "APP_DSN="+os.Getenv("APP_DSN"))
	_ = cmd.Run()
}

func TestSync(t *testing.T) { _ = Sync() }
`,
		},
		"name from a range over a map": {
			"app/app.go": selfExecSyncPkg,
			"app/app_test.go": `package app

import "testing"

func TestSyncAsync(t *testing.T) {
	for k, v := range map[string]string{"APP_ASYNC": "1"} {
		t.Setenv(k, v)
	}
	_ = Sync()
}
`,
		},
		"name from a function": {
			"app/app.go": selfExecSyncPkg,
			"app/app_test.go": `package app

import "testing"

func asyncName() string { return AsyncEnv }

func TestSyncAsync(t *testing.T) {
	t.Setenv(asyncName(), "1")
	_ = Sync()
}
`,
		},
		"name only the own start sets": {
			"app/app.go":      selfExecSyncPkg,
			"app/app_test.go": "package app\n\nimport \"testing\"\n\nfunc TestSync(t *testing.T) { _ = Sync() }\n",
		},
		"child of the variable answered": {
			"app/app.go": strings.Replace(selfExecSyncPkg, " // boom", "", 1),
			"app/app_test.go": `package app

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv(AsyncEnv) == "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSync(t *testing.T) { _ = Sync() }
`,
		},
	})
}

// A test that sets the variable a launcher falls back from covers the
// fallback only with a value that is never empty: the path exec.LookPath
// gives is empty when the lookup fails, unless the test leaves on its error;
// os.MkdirTemp checked the same way is never empty.
func TestSelfExecInTestRule_FallbackSetToMaybeEmpty(t *testing.T) {
	tool := `package app

import (
	"os"
	"os/exec"
)

func toolPath() string {
	if p := os.Getenv("APP_TOOL"); p != "" {
		return p
	}
	exe, _ := os.Executable()
	return exe
}

func Apply() error { return exec.Command(toolPath(), "apply").Run() } // boom
`
	safe := `package app

import (
	"os"
	"os/exec"
)

func toolPath() string {
	if p := os.Getenv("APP_TOOL"); p != "" {
		return p
	}
	exe, _ := os.Executable()
	return exe
}

func Apply() error { return exec.Command(toolPath(), "apply").Run() }
`
	selfExecCases(t, map[string]map[string]string{
		"lookup not checked": {
			"app/app.go": tool,
			"app/app_test.go": `package app

import (
	"os/exec"
	"testing"
)

func TestApply(t *testing.T) {
	bin, _ := exec.LookPath("app-tool")
	t.Setenv("APP_TOOL", bin)
	_ = Apply()
}
`,
		},
		"value of an unknown variable": {
			"app/app.go": tool,
			"app/app_test.go": `package app

import (
	"os"
	"testing"
)

func TestApply(t *testing.T) {
	t.Setenv("APP_TOOL", os.Getenv("APP_TOOL_OVERRIDE"))
	_ = Apply()
}
`,
		},
		"lookup checked": {
			"app/app.go": safe,
			"app/app_test.go": `package app

import (
	"os/exec"
	"testing"
)

func TestApply(t *testing.T) {
	bin, err := exec.LookPath("app-tool")
	if err != nil {
		t.Skip(err)
	}
	t.Setenv("APP_TOOL", bin)
	_ = Apply()
}
`,
		},
		"temporary directory checked": {
			"app/app.go": safe,
			"app/app_test.go": `package app

import (
	"os"
	"testing"
)

func TestApply(t *testing.T) {
	dir, err := os.MkdirTemp("", "tool")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_TOOL", dir)
	_ = Apply()
}
`,
		},
		"temporary directory not checked": {
			"app/app.go": tool,
			"app/app_test.go": `package app

import (
	"os"
	"testing"
)

func TestApply(t *testing.T) {
	dir, _ := os.MkdirTemp("", "tool")
	t.Setenv("APP_TOOL", dir)
	_ = Apply()
}
`,
		},
		"constant": {
			"app/app.go": safe,
			"app/app_test.go": `package app

import "testing"

func TestApply(t *testing.T) {
	t.Setenv("APP_TOOL", "/bin/true")
	_ = Apply()
}
`,
		},
	})
}

// A TestMain answers the child only when every branch the child may take
// leaves before m.Run, and the branch it takes is followed: a grandchild it
// starts on the way is a start like any other.
func TestSelfExecInTestRule_AnsweredChildIsFollowed(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"main starts a grandchild that runs the tests": {
			"app/main.go": `package main

import (
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "start":
		exe, _ := os.Executable()
		cmd := exec.Command(exe, "run") // boom
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		_ = cmd.Start()
	case "run":
		println("running")
	}
	os.Exit(0)
}
`,
			"app/main_test.go": `package main

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_CLI") == "1" {
		main()
	}
	os.Exit(m.Run())
}

func TestStart(t *testing.T) {
	cmd := exec.Command(os.Args[0], "start")
	cmd.Env = append(os.Environ(), "APP_CLI=1")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}
`,
		},
		"main answers without a start": {
			"app/main.go": `package main

import "os"

func main() {
	println("running")
	os.Exit(0)
}
`,
			"app/main_test.go": `package main

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_CLI") == "1" {
		main()
	}
	os.Exit(m.Run())
}

func TestStart(t *testing.T) {
	cmd := exec.Command(os.Args[0], "start")
	cmd.Env = append(os.Environ(), "APP_CLI=1")
	_ = cmd.Run()
}
`,
		},
		"m.Run on a branch the child may take": {
			"app/app.go": "package app\n",
			"app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_MODE") == "" {
		os.Exit(m.Run())
	}
	os.Exit(0)
}

func TestStart(t *testing.T) {
	cmd := exec.Command(os.Args[0], "start") // boom
	cmd.Env = append(os.Environ(), "APP_CHILD=1")
	_ = cmd.Run()
}
`,
		},
		"switch that falls through to m.Run": {
			"app/app.go": "package app\n",
			"app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	switch {
	case os.Getenv("APP_CHILD") == "1":
		fallthrough
	case os.Getenv("APP_SUITE") == "1":
		os.Exit(m.Run())
	}
	os.Exit(0)
}

func TestStart(t *testing.T) {
	cmd := exec.Command(os.Args[0], "start") // boom
	cmd.Env = append(os.Environ(), "APP_CHILD=1")
	_ = cmd.Run()
}
`,
		},
	})
}

// -test.run selects the tests only before the first argument that is not a
// flag: the flags of go test stop there, so a subcommand put first leaves
// the child running every test. A flag that is not known to take no value
// may eat the -test.run after it. The last -test.run wins.
func TestSelfExecInTestRule_TestRunAfterSubcommand(t *testing.T) {
	helper := `
func TestHelperProcess(t *testing.T) {
	if os.Getenv("APP_HELPER") != "1" {
		return
	}
	os.Exit(0)
}
`
	selfExecCases(t, map[string]map[string]string{
		"subcommand first": selfExecHelperTest(`func TestWorker(t *testing.T) {
	cmd := exec.Command(os.Args[0], "worker", "-test.run=TestHelperProcess") // boom
	cmd.Env = append(os.Environ(), "APP_HELPER=1")
	_ = cmd.Run()
}
` + helper),
		"subcommand prepended by a launcher": {
			"launch/launch.go": `package launch

import "os/exec"

func RunWorker(path string, args ...string) error {
	args = append([]string{"worker"}, args...)
	return exec.Command(path, args...).Run()
}
`,
			"app/app.go": "package app\n",
			"app/app_test.go": `package app

import (
	"os"
	"testing"

	"example.com/rulestest/launch"
)

func TestWorker(t *testing.T) {
	_ = launch.RunWorker(os.Args[0], "-test.run=TestHelperProcess") // boom
}
` + helper,
		},
		"subcommand prepended in the call": {
			"launch/launch.go": `package launch

import "os/exec"

func RunWorker(path string, args ...string) error {
	return exec.Command(path, append([]string{"worker"}, args...)...).Run()
}
`,
			"app/app.go": "package app\n",
			"app/app_test.go": `package app

import (
	"os"
	"testing"

	"example.com/rulestest/launch"
)

func TestWorker(t *testing.T) {
	_ = launch.RunWorker(os.Args[0], "-test.run=TestHelperProcess") // boom
}
` + helper,
		},
		"flag that may take the pattern as its value": selfExecHelperTest(`func TestWorker(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-config", "-test.run=TestHelperProcess") // boom
	_ = cmd.Run()
}
` + helper),
		"a later pattern wins": selfExecHelperTest(`func TestWorker(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "-test.run=TestWorker") // boom
	_ = cmd.Run()
}
` + helper),
		"flags before the pattern": selfExecHelperTest(`func TestWorker(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.v", "-test.timeout", "30s", "-test.count=1", "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "APP_HELPER=1")
	_ = cmd.Run()
}
` + helper),
		"double dash": selfExecHelperTest(`func TestWorker(t *testing.T) {
	cmd := exec.Command(os.Args[0], "--test.run=TestHelperProcess", "worker")
	cmd.Env = append(os.Environ(), "APP_HELPER=1")
	_ = cmd.Run()
}
` + helper),
	})
}

// A child started with -test.run runs no benchmark, whatever the pattern
// matches: benchmarks run only with -test.bench.
func TestSelfExecInTestRule_HelperRunsNoBenchmark(t *testing.T) {
	selfExecExpect(t, selfExecHelperTest(`func BenchmarkSpawn(b *testing.B) {
	cmd := exec.Command(os.Args[0], "-test.run=BenchmarkSpawn")
	_ = cmd.Run()
}
`))
}

// What ends the helper branch: a select with a case goes on, a labelled
// break leaves the loop around a select, a case that falls through runs the
// next one too.
func TestSelfExecInTestRule_HelperBranchGoesOn(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"select with a case": selfExecHelperTest(`func TestWait(t *testing.T) {
	if os.Getenv("APP_WAIT") == "1" {
		done := make(chan struct{})
		close(done)
		select {
		case <-done:
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWait$") // boom
	cmd.Env = append(os.Environ(), "APP_WAIT=1")
	_ = cmd.Run()
}
`),
		"labelled break out of a select": selfExecHelperTest(`func TestPoll(t *testing.T) {
	if os.Getenv("APP_POLL") == "1" {
		done := make(chan struct{})
		close(done)
	loop:
		for {
			select {
			case <-done:
				break loop
			}
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPoll$") // boom
	cmd.Env = append(os.Environ(), "APP_POLL=1")
	_ = cmd.Run()
}
`),
		"case that falls through": selfExecHelperTest(`func TestFall(t *testing.T) {
	switch {
	case os.Getenv("APP_FALL") == "1":
		fallthrough
	default:
		cmd := exec.Command(os.Args[0], "-test.run=^TestFall$") // boom
		cmd.Env = append(os.Environ(), "APP_FALL=1")
		_ = cmd.Run()
	}
}
`),
	})
}

// A launcher that gives its command an Env passes the child more than the
// arguments: the TestMain that answers the variable answers the child.
func TestSelfExecInTestRule_LauncherWithEnvironment(t *testing.T) {
	selfExecExpect(t, map[string]string{
		"launch/launch.go": `package launch

import (
	"os"
	"os/exec"
)

func Start(path string, args ...string) error {
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), "APP_CHILD=1")
	return cmd.Run()
}
`,
		"app/app.go": "package app\n",
		"app/app_test.go": `package app

import (
	"os"
	"testing"

	"example.com/rulestest/launch"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_CHILD") == "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStart(t *testing.T) { _ = launch.Start(os.Args[0]) }
`,
	})
}

// A pattern selects the tests of the child only where it is proven: an
// argument without a dash ends the flags, a pattern with an end the start
// does not tell may match any test, an argument the start does not tell
// before it may be a flag that takes it as its value, and arguments the
// start does not tell after it may set it again.
func TestSelfExecInTestRule_PatternIsProven(t *testing.T) {
	helper := `
func TestHelperProcess(t *testing.T) {
	if os.Getenv("APP_HELPER") != "1" {
		return
	}
	os.Exit(0)
}
`
	start := func(args string) map[string]string {
		return map[string]string{"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

var _ = strings.Fields

func TestWorker(t *testing.T) {
	cmd := exec.Command(os.Args[0], ` + args + `
	cmd.Env = append(os.Environ(), "APP_HELPER=1")
	_ = cmd.Run()
}
` + helper}
	}
	selfExecCases(t, map[string]map[string]string{
		"pattern":                      start(`"-test.run=TestHelperProcess")`),
		"pattern without a dash":       start(`"test.run=TestHelperProcess") // boom`),
		"pattern with an end not told": start(`"-test.run=TestHelperProcess"+os.Getenv("APP_SUFFIX")) // boom`),
		"argument not told before it":  start(`os.Getenv("APP_FLAG"), "-test.run=TestHelperProcess") // boom`),
		"arguments not told after it":  start(`append([]string{"-test.run=TestHelperProcess"}, strings.Fields(os.Getenv("APP_ARGS"))...)...) // boom`),
	})
}

// A launcher is read for the start only where what it starts is proven: it
// has one launch of the path, its own, and the rest it forwards is the one
// the call gives, not one it appends to.
func TestSelfExecInTestRule_LauncherIsProven(t *testing.T) {
	helper := `
func TestHelperProcess(t *testing.T) {
	if os.Getenv("APP_HELPER") != "1" {
		return
	}
	os.Exit(0)
}
`
	test := func(call string) string {
		return `package app

import (
	"os"
	"testing"

	"example.com/rulestest/launch"
)

func TestWorker(t *testing.T) {
	_ = ` + call + `
}
` + helper
	}
	selfExecCases(t, map[string]map[string]string{
		"two launches of the path": {
			"launch/launch.go": `package launch

import (
	"os"
	"os/exec"
)

func Run(path string, helper bool) error {
	if helper {
		cmd := exec.Command(path, "-test.run=TestHelperProcess")
		cmd.Env = append(os.Environ(), "APP_HELPER=1")
		return cmd.Run()
	}
	return exec.Command(path, "worker").Run()
}
`,
			"app/app.go":      "package app\n",
			"app/app_test.go": test(`launch.Run(os.Args[0], false) // boom`),
		},
		"a launch through another launcher that sets the arguments": {
			"launch/launch.go": `package launch

import (
	"os"
	"os/exec"
)

func inner(path string) error {
	cmd := exec.Command(path, "-test.run=TestHelperProcess")
	cmd.Args = []string{path, "worker"}
	cmd.Env = append(os.Environ(), "APP_HELPER=1")
	return cmd.Run()
}

func Run(path string) error { return inner(path) }
`,
			"app/app.go":      "package app\n",
			"app/app_test.go": test(`launch.Run(os.Args[0]) // boom`),
		},
		"a rest the launcher appends to": {
			"launch/launch.go": `package launch

import (
	"os"
	"os/exec"
)

func Run(path string, args ...string) error {
	args = append(args, "-test.run=Test")
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), "APP_HELPER=1")
	return cmd.Run()
}
`,
			"app/app.go":      "package app\n",
			"app/app_test.go": test(`launch.Run(os.Args[0], "-test.run=TestHelperProcess") // boom`),
		},
	})
}

// A variable of the child covers the fallback only where its value is
// never empty: a value the start takes from its own environment may be.
func TestSelfExecInTestRule_ChildVariableMaybeEmpty(t *testing.T) {
	selfExecExpect(t, map[string]string{
		"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func Start() error {
	bin := os.Getenv("APP_BIN")
	if bin == "" {
		bin, _ = os.Executable()
	}
	cmd := exec.Command(bin, "serve") // boom
	cmd.Env = append(os.Environ(), "APP_CHILD=1", "APP_BIN="+os.Getenv("APP_REAL_BIN"))
	return cmd.Run()
}
`,
		"app/app_test.go": `package app

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_CHILD") == "1" {
		_ = Start()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStart(t *testing.T) { _ = Start() }
`,
	})
}

// What TestMain sets before m.Run covers the tests, not TestMain itself: a
// branch of it that starts a child before it sets the variable falls back
// to the own executable.
func TestSelfExecInTestRule_BeforeTheTests(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"TestMain starts before it sets": {
			"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func Start() error {
	bin := os.Getenv("APP_BIN")
	if bin == "" {
		bin, _ = os.Executable()
	}
	cmd := exec.Command(bin, "serve") // boom
	cmd.Env = []string{"APP_CHILD=1"}
	return cmd.Run()
}
`,
			"app/app_test.go": `package app

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("APP_CHILD") == "1" {
		_ = Start()
		os.Exit(0)
	}
	os.Setenv("APP_BIN", "/bin/true")
	os.Exit(m.Run())
}

func TestStart(t *testing.T) { _ = Start() }
`,
		},
		"the tests start after it sets": {
			"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func Start() error {
	bin := os.Getenv("APP_BIN")
	if bin == "" {
		bin, _ = os.Executable()
	}
	return exec.Command(bin, "serve").Run()
}
`,
			"app/app_test.go": `package app

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("APP_BIN", "/bin/true")
	os.Exit(m.Run())
}

func TestStart(t *testing.T) { _ = Start() }
`,
		},
	})
}

// Past the bound of the runs a body is followed in, the child of a helper
// is followed in its own run, not in one the walk knows nothing of: the
// variable the start gives the child still holds, so the branch that would
// start the helper again stays out of the child.
func TestSelfExecInTestRule_ManyGuardsInTheChild(t *testing.T) {
	var src strings.Builder
	src.WriteString(`package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("APP_HELPER") != "1" {
		return
	}
	k1()
	os.Exit(0)
}

func startWorker() {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "APP_HELPER=1")
	_ = cmd.Run()
}

func TestWorker(t *testing.T) { startWorker() }
`)
	const n = 12
	for i := 1; i < n; i++ {
		fmt.Fprintf(&src, "\nfunc k%d() {\n\tif os.Getenv(\"APP_K%d\") == \"1\" {\n\t\tk%d()\n\t}\n\tk%d()\n}\n", i, i, i+1, i+1)
	}
	fmt.Fprintf(&src, "\nfunc k%d() {\n\tif os.Getenv(\"APP_HELPER\") == \"1\" {\n\t\treturn\n\t}\n\tstartWorker()\n}\n", n)
	selfExecExpect(t, map[string]string{"app/app.go": "package app\n", "app/app_test.go": src.String()})
}

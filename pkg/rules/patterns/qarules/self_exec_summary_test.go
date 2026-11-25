package qarules

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A launcher that calls itself to retry, and two launchers that call each
// other: the summary of a launcher met again while it is being found has no
// launch, so the walk ends instead of overflowing the stack, and the start
// is still reported.
func TestSelfExecInTestRule_LauncherCycle(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"retry calls itself": {
			"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func start(path string, tries int) error {
	err := exec.Command(path, "worker").Start()
	if err != nil && tries > 0 {
		return start(path, tries-1)
	}
	return err
}

func Spawn() error {
	exe, _ := os.Executable()
	return start(exe, 3) // boom
}
`,
			"app/app_test.go": `package app

import "testing"

func TestSpawn(t *testing.T) { _ = Spawn() }
`,
		},
		"two launchers call each other": {
			"app/app.go": `package app

import (
	"os"
	"os/exec"
)

func ping(path string, n int) error {
	if n == 0 {
		return exec.Command(path, "ping").Start()
	}
	return pong(path, n-1)
}

func pong(path string, n int) error { return ping(path, n) }

func Loop() error {
	exe, _ := os.Executable()
	return ping(exe, 3) // boom
}
`,
			"app/app_test.go": `package app

import "testing"

func TestLoop(t *testing.T) { _ = Loop() }
`,
		},
	})
}

// selfExecChainFiles builds a chain of n functions, each calling the next
// twice with the own path, and a test that enters the chain at each.
func selfExecChainFiles(n int) map[string]string {
	var src, tests strings.Builder
	src.WriteString("package app\n\nimport \"os/exec\"\n\n")
	for i := 1; i < n; i++ {
		fmt.Fprintf(&src, "func f%d(p string, k int) error {\n\tif k > %d {\n\t\treturn f%d(p, k)\n\t}\n\treturn f%d(p, k+1)\n}\n\n", i, i, i+1, i+1)
	}
	fmt.Fprintf(&src, "func f%d(p string, k int) error { return exec.Command(p, \"end\").Start() }\n", n)
	tests.WriteString("package app\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&tests, "func TestF%d(t *testing.T) { _ = f%d(os.Args[0], %d) } // boom\n", i, i, i)
	}
	return map[string]string{"app/app.go": src.String(), "app/app_test.go": tests.String()}
}

// A chain of launchers, each calling the next twice: each launcher is
// summarized once, so the time grows with the number of functions and not
// with the number of paths through them (2^n).
func TestSelfExecInTestRule_ChainIsLinear(t *testing.T) {
	files := selfExecChainFiles(60)
	done := make(chan []string, 1)
	go func() { done <- selfExecPlaces(t, files) }()
	select {
	case places := <-done:
		if places == nil {
			places = []string{}
		}
		if got, want := strings.Join(places, " "), strings.Join(selfExecBooms(files), " "); got != want {
			t.Fatalf("places %q, want %q", got, want)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("a chain of 60 launchers took more than a minute: the walk follows every path")
	}
}

// selfExecFanOutFiles builds a chain of levels functions, each passing its
// string parameter to the next at fanOut calls; the last starts the own
// executable with it, and a test passes -test.run of no test.
func selfExecFanOutFiles(levels, fanOut int) map[string]string {
	var src strings.Builder
	src.WriteString("package app\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\n")
	for i := 1; i < levels; i++ {
		fmt.Fprintf(&src, "func g%d(s string) {\n", i)
		for range fanOut {
			fmt.Fprintf(&src, "\tg%d(s)\n", i+1)
		}
		src.WriteString("}\n\n")
	}
	fmt.Fprintf(&src, "func g%d(s string) {\n\texe, _ := os.Executable()\n\t_ = exec.Command(exe, s).Run()\n}\n", levels)
	test := "package app\n\nimport \"testing\"\n\nfunc TestG(t *testing.T) { g1(\"-test.run=TestNothing\") }\n"
	return map[string]string{"app/app.go": src.String(), "app/app_test.go": test}
}

// The value of a string parameter is the summary of the parameter, found
// once: each call site of each function is read once, not once per path to
// it, so the value is followed to its constant however far it goes.
func TestSelfExecInTestRule_ParameterValueIsLinear(t *testing.T) {
	files := selfExecFanOutFiles(30, 32)
	done := make(chan []string, 1)
	go func() { done <- selfExecPlaces(t, files) }()
	select {
	case places := <-done:
		if len(places) != 0 {
			t.Fatalf("places %q, want none: the child runs no test", places)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("a parameter passed through 30 functions at 32 calls each took more than a minute")
	}
}

// selfExecWithin runs the rule on the files and fails when it takes more
// than a minute.
func selfExecWithin(t *testing.T, files map[string]string, what string) []string {
	t.Helper()
	done := make(chan []string, 1)
	go func() { done <- selfExecPlaces(t, files) }()
	select {
	case places := <-done:
		return places
	case <-time.After(60 * time.Second):
		t.Fatalf("%s took more than a minute", what)
	}
	return nil
}

// A chain of functions, each calling the next under a guard on its own
// variable and once without: a body is followed in a bounded number of
// runs, past which it is followed in the run the walk starts in, so the
// runs do not double at each step.
func TestSelfExecInTestRule_GuardChainIsLinear(t *testing.T) {
	var src strings.Builder
	src.WriteString("package app\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\n")
	const n = 40
	for i := 1; i < n; i++ {
		fmt.Fprintf(&src, "func k%d() {\n\tif os.Getenv(\"APP_K%d\") == \"1\" {\n\t\tk%d()\n\t}\n\tk%d()\n}\n\n", i, i, i+1, i+1)
	}
	fmt.Fprintf(&src, "func k%d() {\n\texe, _ := os.Executable()\n\t_ = exec.Command(exe, \"worker\").Run() // boom\n}\n", n)
	files := map[string]string{"app/app.go": src.String(), "app/app_test.go": "package app\n\nimport \"testing\"\n\nfunc TestK(t *testing.T) { k1() }\n"}
	places := selfExecWithin(t, files, "a chain of 40 guarded calls")
	if got, want := strings.Join(places, " "), strings.Join(selfExecBooms(files), " "); got != want {
		t.Fatalf("places %q, want %q", got, want)
	}
}

// TestMain answers through a chain of predicates, each asking the next on
// many branches: the value of each is found once per evaluation, and is
// known where every return the run may reach gives the same.
func TestSelfExecInTestRule_PredicateChainIsLinear(t *testing.T) {
	var src strings.Builder
	src.WriteString("package app\n\nimport \"os\"\n\n")
	const n, fanOut = 30, 32
	for i := 1; i < n; i++ {
		fmt.Fprintf(&src, "func c%d() bool {\n", i)
		for j := range fanOut {
			fmt.Fprintf(&src, "\tif os.Getenv(\"APP_C%d_%d\") == \"1\" {\n\t\treturn c%d()\n\t}\n", i, j, i+1)
		}
		fmt.Fprintf(&src, "\treturn c%d()\n}\n\n", i+1)
	}
	fmt.Fprintf(&src, "func c%d() bool { return os.Getenv(\"APP_CHILD\") == \"1\" }\n", n)
	test := `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	if c1() {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStart(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "APP_CHILD=1")
	_ = cmd.Run()
}
`
	places := selfExecWithin(t, map[string]string{"app/app.go": src.String(), "app/app_test.go": test}, "a chain of 30 predicates")
	if len(places) != 0 {
		t.Fatalf("places %q, want none: every predicate is true in the child", places)
	}
}

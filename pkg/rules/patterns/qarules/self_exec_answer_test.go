package qarules

import "testing"

// selfExecAnsweredBy builds a package whose TestMain is given, with a test
// that starts the own binary with APP_CHILD=1 added to the environment.
func selfExecAnsweredBy(testMain, more, mark string) map[string]string {
	return map[string]string{"app/app.go": "package app\n" + more, "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

` + testMain + `

func TestStart(t *testing.T) {
	cmd := exec.Command(os.Args[0])` + mark + `
	cmd.Env = append(os.Environ(), "APP_CHILD=1")
	_ = cmd.Run()
}
`}
}

// selfExecInitAnswers builds a package with the given init and a TestMain
// that runs the tests: the init answers the child only where every path
// of it exits.
func selfExecInitAnswers(init, mark string) map[string]string {
	return selfExecAnsweredBy(`func init() {
`+init+`
	if os.Getenv("APP_CHILD") == "1" {
		os.Exit(0)
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }`, "", mark)
}

// An init answers the child only where no path of it returns before the
// answer: a return in a loop, in a range, under a guard the run does not
// tell, in a case another falls through to or in a case of a value the run
// does not tell lets the tests run.
func TestSelfExecInTestRule_InitReturnsOnSomePath(t *testing.T) {
	selfExecCases(t, map[string]map[string]string{
		"answer": selfExecInitAnswers("", ""),
		"return in a loop": selfExecInitAnswers(`	for i := 0; i < 1; i++ {
		if os.Getenv("APP_SKIP") != "" {
			return
		}
	}`, " // boom"),
		"return in a range": selfExecInitAnswers(`	for _, name := range []string{"APP_SKIP"} {
		if os.Getenv(name) != "" {
			return
		}
	}`, " // boom"),
		"return under a guard the run does not tell": selfExecInitAnswers(`	if os.Getenv("APP_SKIP") == "1" {
		return
	}`, " // boom"),
		"case that falls through to a return": selfExecInitAnswers(`	switch os.Getenv("APP_CHILD") {
	case "1":
		fallthrough
	case "2":
		return
	}`, " // boom"),
		"case of a value the run does not tell": selfExecInitAnswers(`	switch os.Getenv("APP_MODE") {
	case "plain":
		return
	}`, " // boom"),
	})
}

// A switch in TestMain answers the child where the case the child takes
// exits; a case of another value, or one the run may not reach, does not.
func TestSelfExecInTestRule_TestMainSwitch(t *testing.T) {
	main := func(tag, value string) string {
		return `func TestMain(m *testing.M) {
	switch os.Getenv("` + tag + `") {
	case "` + value + `":
		os.Exit(0)
	}
	os.Exit(m.Run())
}`
	}
	selfExecCases(t, map[string]map[string]string{
		"case of the child":         selfExecAnsweredBy(main("APP_CHILD", "1"), "", ""),
		"case of another value":     selfExecAnsweredBy(main("APP_CHILD", "2"), "", " // boom"),
		"case the run may not take": selfExecAnsweredBy(main("APP_MODE", "child"), "", " // boom"),
	})
}

// A function TestMain asks answers the child where every return the run
// may reach gives the same value; a path that exits gives none; a loop or
// a switch that falls through with a return in it leaves the value unknown.
func TestSelfExecInTestRule_PredicateOfTheChild(t *testing.T) {
	asks := func(cond string) string {
		return `func TestMain(m *testing.M) {
	if ` + cond + ` {
		os.Exit(0)
	}
	os.Exit(m.Run())
}`
	}
	selfExecCases(t, map[string]map[string]string{
		"same value on every path": selfExecAnsweredBy(asks("isChild()"), `
import "os"

func isChild() bool {
	if os.Getenv("APP_MODE") == "1" {
		return os.Getenv("APP_CHILD") == "1"
	}
	return os.Getenv("APP_CHILD") == "1"
}
`, ""),
		"values that differ": selfExecAnsweredBy(asks("isChild()"), `
import "os"

func isChild() bool {
	if os.Getenv("APP_MODE") == "1" {
		return true
	}
	return false
}
`, " // boom"),
		"a string with an end the run does not tell": {
			"app/app.go": `package app

import "os"

func role() string {
	if os.Getenv("APP_MODE") == "1" {
		return "child"
	}
	return os.Getenv("APP_ROLE")
}
`,
			"app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	if role() == "child" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStart(t *testing.T) {
	cmd := exec.Command(os.Args[0]) // boom
	cmd.Env = append(os.Environ(), "APP_ROLE=child"+os.Getenv("APP_SUFFIX"))
	_ = cmd.Run()
}
`,
		},
		"a count of arguments the run does not tell": {
			"app/app.go": `package app

import "os"

func count() int {
	if os.Getenv("APP_MODE") == "1" {
		return 2
	}
	return len(os.Args)
}
`,
			"app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if count() == 2 {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStart(t *testing.T) {
	cmd := exec.Command(os.Args[0], append([]string{"child"}, strings.Fields(os.Getenv("APP_ARGS"))...)...) // boom
	_ = cmd.Run()
}
`,
		},
		"a predicate that exits in the child": selfExecAnsweredBy(asks("isChild()"), `
import "os"

func exitInChild() bool {
	if os.Getenv("APP_CHILD") == "1" {
		os.Exit(0)
	}
	return false
}

func isChild() bool {
	if exitInChild() {
		return true
	}
	return false
}
`, ""),
		"a switch that falls through to a return": selfExecAnsweredBy(asks("isChild()"), `
import "os"

func isChild() bool {
	switch os.Getenv("APP_MODE") {
	case "a":
		fallthrough
	case "b":
		return false
	}
	return os.Getenv("APP_CHILD") == "1"
}
`, " // boom"),
		"a loop with a return": selfExecAnsweredBy(asks("isChild()"), `
import "os"

func isChild() bool {
	for i := 0; i < 1; i++ {
		if os.Getenv("APP_MODE") == "a" {
			return false
		}
	}
	return os.Getenv("APP_CHILD") == "1"
}
`, " // boom"),
	})
}

// The child TestMain answers runs the inits before it: a start an init
// makes in the child is followed like any other, and one that starts the
// child again is reported.
func TestSelfExecInTestRule_InitOfTheAnsweredChild(t *testing.T) {
	selfExecExpect(t, map[string]string{"app/app.go": "package app\n", "app/app_test.go": `package app

import (
	"os"
	"os/exec"
	"testing"
)

func init() {
	if os.Getenv("APP_CHILD") == "1" {
		spawn()
	}
}

func spawn() {
	cmd := exec.Command(os.Args[0]) // boom
	cmd.Env = append(os.Environ(), "APP_CHILD=1")
	_ = cmd.Run()
}

func TestMain(m *testing.M) {
	if os.Getenv("APP_CHILD") == "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStart(t *testing.T) { spawn() }
`})
}

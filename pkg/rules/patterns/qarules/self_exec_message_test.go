package qarules

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selfExecMessage runs the rule on a package whose test file is given and
// returns the one finding's message and suggestion.
func selfExecMessage(t *testing.T, test string) (message, suggestion string) {
	t.Helper()
	violations := rulestest.RunRuleOnFiles(t, NewSelfExecInTestRule(), map[string]string{
		"relay/relay.go":      "package relay\n",
		"relay/relay_test.go": test,
	})
	require.Len(t, violations, 1)
	return violations[0].Message, violations[0].Suggestion
}

// A test answers the child by the variable its launch sets, but the branch
// does not end the test: the child goes on, reaches the launch again and
// starts the next copy. -test.run pins the child to the one test, so the
// message names the branch, not a run of every test.
func TestSelfExecInTestRule_MessageEnvBranchWithoutExit(t *testing.T) {
	message, suggestion := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRelayChild(t *testing.T) {
	if os.Getenv("RELAY_HELPER") == "1" {
		time.Sleep(time.Millisecond)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`)
	assert.Equal(t, "TestRelayChild starts its own test binary: TestRelayChild passes the process's own executable to exec.Command, reached through TestRelayChild"+
		" — the branch on RELAY_HELPER at line 11 answers the child but does not end the test: the child goes on and reaches this launch again, and each copy starts the next", message)
	assert.Equal(t, "End the branch on RELAY_HELPER at line 11 with os.Exit or a return, so the child never reaches the launch", suggestion)
}

// TestMain answers the child by its argument but does not exit: the child
// goes on to m.Run, runs the tests and reaches the launch again.
func TestSelfExecInTestRule_MessageTestMainArgBranchWithoutExit(t *testing.T) {
	message, suggestion := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func serveRelay() {}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "relay-child" {
		serveRelay()
	}
	os.Exit(m.Run())
}

func TestRelay(t *testing.T) {
	_ = exec.Command(os.Args[0], "relay-child").Run()
}
`)
	assert.Equal(t, "TestRelay starts its own test binary: TestRelay passes the process's own executable to exec.Command, reached through TestRelay"+
		" — the branch on os.Args[1] at line 12 of TestMain answers the child but does not exit before m.Run: the child goes on to the tests and reaches this launch again, and each copy starts the next", message)
	assert.Equal(t, "End the branch on os.Args[1] at line 12 with os.Exit before m.Run, so the child never reaches the launch", suggestion)
}

// -test.run pins the child to the test that starts it, and nothing answers
// the child there: the one test runs again and starts the next copy.
func TestSelfExecInTestRule_MessagePinnedRunWithoutAnswer(t *testing.T) {
	message, suggestion := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func TestRelayLoop(t *testing.T) {
	_ = exec.Command(os.Args[0], "-test.run=^TestRelayLoop$").Run()
}
`)
	assert.Equal(t, "TestRelayLoop starts its own test binary: TestRelayLoop passes the process's own executable to exec.Command, reached through TestRelayLoop"+
		" — -test.run=^TestRelayLoop$ runs TestRelayLoop in the child, and it reaches this launch again, and each copy starts the next", message)
	assert.Equal(t, "Answer the child and end the test before the launch: a branch on what the launch passes that returns or calls os.Exit, or a TestHelperProcess that does not launch", suggestion)
}

// A launch with no -test.run and no answer keeps the message of a run of
// every test.
func TestSelfExecInTestRule_MessageEveryTest(t *testing.T) {
	message, suggestion := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func TestRelayAll(t *testing.T) {
	_ = exec.Command(os.Args[0], "relay-child").Run()
}
`)
	assert.Equal(t, "TestRelayAll starts its own test binary: TestRelayAll passes the process's own executable to exec.Command, reached through TestRelayAll"+
		" — under go test that binary runs every test again, and each copy starts the next", message)
	assert.Contains(t, suggestion, "Refuse the launch when testing.Testing() is true")
}

// An init answers the child by the variable the launch sets but does not
// exit: the child goes on to the test that starts it.
func TestSelfExecInTestRule_MessageInitBranchWithoutExit(t *testing.T) {
	message, suggestion := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

var relayMode string

func init() {
	if os.Getenv("RELAY_MODE") == "child" {
		relayMode = "child"
	}
}

func TestRelayInit(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayInit$")
	cmd.Env = append(os.Environ(), "RELAY_MODE=child")
	_ = cmd.Run()
}
`)
	assert.Contains(t, message, " — the branch on RELAY_MODE at line 12 of init answers the child but does not exit: the child goes on to the tests and reaches this launch again, and each copy starts the next")
	assert.Equal(t, "End the branch on RELAY_MODE at line 12 with os.Exit, so the child never reaches the launch", suggestion)
}

// The branch is in the test, the launch in a helper of another file: the
// message places the branch by its file and names the test.
func TestSelfExecInTestRule_MessageBranchInCallerOfLauncher(t *testing.T) {
	violations := rulestest.RunRuleOnFiles(t, NewSelfExecInTestRule(), map[string]string{
		"relay/relay.go": "package relay\n",
		"relay/relay_test.go": `package relay

import (
	"os"
	"testing"
)

func TestRelayVia(t *testing.T) {
	if os.Getenv("RELAY_VIA") == "1" {
		println("child")
	}
	launchRelay()
}
`,
		"relay/launch_test.go": `package relay

import (
	"os"
	"os/exec"
)

func launchRelay() {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayVia$")
	cmd.Env = append(os.Environ(), "RELAY_VIA=1")
	_ = cmd.Run()
}
`,
	})
	require.Equal(t, []string{"relay/launch_test.go:9"}, rulestest.ViolationPlaces(violations))
	assert.Contains(t, violations[0].Message, " — the branch on RELAY_VIA at relay/relay_test.go:9 of TestRelayVia answers the child but does not end the test")
	assert.Equal(t, "End the branch on RELAY_VIA at relay/relay_test.go:9 with os.Exit or a return, so the child never reaches the launch", violations[0].Suggestion)
}

// A switch on the variable in the launcher, which is no test: only os.Exit
// ends the child there.
func TestSelfExecInTestRule_MessageSwitchInLauncher(t *testing.T) {
	message, suggestion := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func launchRelay() {
	switch os.Getenv("RELAY_SWITCH") {
	case "child":
		println("child")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelaySwitch$")
	cmd.Env = append(os.Environ(), "RELAY_SWITCH=child")
	_ = cmd.Run()
}

func TestRelaySwitch(t *testing.T) { launchRelay() }
`)
	assert.Contains(t, message, " — the branch on RELAY_SWITCH at line 10 answers the child but does not end the test")
	assert.Equal(t, "End the branch on RELAY_SWITCH at line 10 with os.Exit, so the child never reaches the launch", suggestion)
}

// A branch the child takes that ends it is no answer without an end, nor is
// a branch after it; the launch passes no -test.run, so the child runs every
// test again.
func TestSelfExecInTestRule_MessageEndingBranch(t *testing.T) {
	message, _ := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func launchRelay() {
	if os.Getenv("RELAY_ONCE") == "1" {
		println("child")
	}
	cmd := exec.Command(os.Args[0], "relay-child")
	cmd.Env = append(os.Environ(), "RELAY_ONCE=1")
	_ = cmd.Run()
}

func TestRelayOnce(t *testing.T) {
	if os.Getenv("RELAY_ONCE") == "1" {
		os.Exit(0)
	}
	launchRelay()
}
`)
	assert.Contains(t, message, " — under go test that binary runs every test again, and each copy starts the next")
}

// A pattern that names more than one test: the message names the test that
// starts the child.
func TestSelfExecInTestRule_MessagePinnedRunOfTwoTests(t *testing.T) {
	message, suggestion := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(m.Run()) }

func TestRelayPair(t *testing.T) {
	_ = exec.Command(os.Args[0], "-test.run=^TestRelayPair").Run()
}

func TestRelayPairSlow(t *testing.T) {}
`)
	assert.Contains(t, message, " — -test.run=^TestRelayPair runs TestRelayPair in the child, and it reaches this launch again")
	assert.Contains(t, suggestion, "Answer the child and end the test before the launch")
}

// TestMain starts the child before the branch that answers it: the child
// runs no test, it reaches the launch on its way to the answer.
func TestSelfExecInTestRule_MessageLaunchBeforeAnswer(t *testing.T) {
	message, suggestion := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayNone$")
	cmd.Env = append(os.Environ(), "RELAY_MAIN=1")
	_ = cmd.Run()
	if os.Getenv("RELAY_MAIN") == "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestRelayNone(t *testing.T) {}
`)
	assert.Contains(t, message, " — the child reaches this launch again on its way to the branch of TestMain or an init that answers it, and each copy starts the next")
	assert.Contains(t, suggestion, "move the branch that answers it above the start")
}

// A branch after the call that leads to the launch, or after m.Run, is no
// answer the child surely passes: the message is the neutral one.
func TestSelfExecInTestRule_MessageBranchAfterTheWay(t *testing.T) {
	message, _ := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	if os.Getenv("RELAY_AFTER") == "1" {
		println("child done")
	}
	os.Exit(code)
}

func launchRelay() {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayAfter$")
	cmd.Env = append(os.Environ(), "RELAY_AFTER=1")
	_ = cmd.Run()
}

func TestRelayAfter(t *testing.T) {
	if testing.Testing() {
		println("under go test")
	}
	launchRelay()
	if os.Getenv("RELAY_AFTER") == "1" {
		println("child")
	}
}
`)
	assert.Contains(t, message, " — -test.run=^TestRelayAfter$ runs TestRelayAfter in the child, and it reaches this launch again, and each copy starts the next")
}

// A -test.run pattern the analysis does not know pins nothing it can name.
func TestSelfExecInTestRule_MessageUnknownPattern(t *testing.T) {
	message, _ := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func TestRelayAny(t *testing.T) {
	_ = exec.Command(os.Args[0], "-test.run=^TestRelayAny"+os.Getenv("RELAY_PATTERN")).Run()
}
`)
	assert.Contains(t, message, " — under go test that binary runs every test again, and each copy starts the next")
}

// A TestMain that starts the child is walked up to the launch, past m.Run.
func TestSelfExecInTestRule_MessageLaunchInTestMainAfterRun(t *testing.T) {
	message, _ := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	if os.Getenv("RELAY_TAIL") == "1" {
		println("child")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayTail$")
	cmd.Env = append(os.Environ(), "RELAY_TAIL=1")
	_ = cmd.Run()
	os.Exit(code)
}

func TestRelayTail(t *testing.T) {}
`)
	assert.Contains(t, message, " — the branch on RELAY_TAIL at line 11 answers the child but does not exit: the child goes on and reaches this launch again")
}

// A TestMain that starts the child after m.Run, answering it before: the
// child goes on through the tests to the launch.
func TestSelfExecInTestRule_MessageLaunchInTestMainAnswerBeforeRun(t *testing.T) {
	message, _ := selfExecMessage(t, `package relay

import (
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("RELAY_HEAD") == "1" {
		println("child")
	}
	code := m.Run()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayHead$")
	cmd.Env = append(os.Environ(), "RELAY_HEAD=1")
	_ = cmd.Run()
	os.Exit(code)
}

func TestRelayHead(t *testing.T) {}
`)
	assert.Contains(t, message, " — the branch on RELAY_HEAD at line 10 answers the child but does not exit: the child goes on and reaches this launch again")
}

// selfExecRelayTest wraps a body of declarations into a test file of the
// relay package that imports os, os/exec and testing.
func selfExecRelayTest(decls string) string {
	return `package relay

import (
	"log"
	"os"
	"os/exec"
	"testing"
)

var _ = log.Print

` + decls
}

// The message names no cause it does not prove: an answer off the way to
// the launch, one in a function literal, one after the launch, a branch the
// child may leave, or more than one place that reads what the launch passes
// leave the neutral message of the test -test.run runs; a child that
// reaches the launch on its way to its answer is told so first.
func TestSelfExecInTestRule_MessageClaimsOnlyWhatItProves(t *testing.T) {
	const neutral = "Answer the child and end the test before the launch: a branch on what the launch passes that returns or calls os.Exit, or a TestHelperProcess that does not launch"
	cases := map[string]struct {
		files              map[string]string
		reason, suggestion string
	}{
		"answer in a helper called before the launch": {
			files: map[string]string{"relay/relay_test.go": selfExecRelayTest(`func maybeServe() {
	if os.Getenv("RELAY_HELPER") == "1" {
		println("serve")
	}
}

func TestChild(t *testing.T) {
	maybeServe()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`)},
			reason:     "-test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"answer in a helper of another file whose return ends only the helper": {
			files: map[string]string{
				"relay/helper_test.go": `package relay

import "os"

func maybeServe() {
	if os.Getenv("RELAY_HELPER") == "1" {
		println("serve")
		return
	}
}
`,
				"relay/relay_test.go": selfExecRelayTest(`func TestChild(t *testing.T) {
	maybeServe()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`)},
			reason:     "-test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"answer in a function literal of t.Run": {
			files: map[string]string{"relay/relay_test.go": selfExecRelayTest(`func TestOuter(t *testing.T) {
	t.Run("inner", func(t *testing.T) {
		if os.Getenv("RELAY_HELPER") == "1" {
			println("serve")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestOuter$/^inner$")
		cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
		_ = cmd.Run()
	})
}
`)},
			reason:     "-test.run=^TestOuter$/^inner$ runs TestOuter in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"answer after the launch": {
			files: map[string]string{"relay/relay_test.go": selfExecRelayTest(`func TestChild(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
	if os.Getenv("RELAY_HELPER") == "1" {
		os.Exit(0)
	}
}
`)},
			reason:     "-test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"a pattern that also runs the test that answers": {
			files: map[string]string{"relay/relay_test.go": selfExecRelayTest(`func TestRelayLaunch(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelay")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}

func TestRelayServe(t *testing.T) {
	if os.Getenv("RELAY_HELPER") != "1" {
		return
	}
	os.Exit(0)
}
`)},
			reason:     "-test.run=^TestRelay runs TestRelayLaunch in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"a branch of an init beside a helper -test.run does not pick": {
			files: map[string]string{"relay/relay_test.go": selfExecRelayTest(`func init() {
	if os.Getenv("RELAY_HELPER") != "" {
		log.SetFlags(0)
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("RELAY_HELPER") != "1" {
		return
	}
	os.Exit(0)
}

func TestUse(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestUse$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`)},
			reason:     "-test.run=^TestUse$ runs TestUse in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"a branch beside a helper that exits": {
			files: map[string]string{"relay/relay_test.go": selfExecRelayTest(`func exitIfChild() {
	if os.Getenv("RELAY_HELPER") == "1" {
		os.Exit(0)
	}
}

func TestChild(t *testing.T) {
	if os.Getenv("RELAY_HELPER") == "1" {
		println("child")
	}
	exitIfChild()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`)},
			reason:     "-test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"a branch that calls a function of the module that exits": {
			files: map[string]string{"relay/relay_test.go": selfExecRelayTest(`func stopRelay() { os.Exit(0) }

func TestChild(t *testing.T) {
	if os.Getenv("RELAY_HELPER") == "1" {
		stopRelay()
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`)},
			reason:     "-test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"a branch that calls a function value": {
			files: map[string]string{"relay/relay_test.go": selfExecRelayTest(`func TestChild(t *testing.T) {
	stop := os.Exit
	if os.Getenv("RELAY_HELPER") == "1" {
		stop(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`)},
			reason:     "-test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"an answer by what os.Environ holds, which the rule does not read": {
			files: map[string]string{"relay/relay_test.go": selfExecRelayTest(`func TestChild(t *testing.T) {
	for _, kv := range os.Environ() {
		if kv == "RELAY_HELPER=1" {
			println("serve")
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`)},
			reason:     "-test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"an answer in an init of a package the tests import": {
			files: map[string]string{
				"cfg/cfg.go":     "package cfg\n\nimport \"os\"\n\nvar Child bool\n\nfunc init() {\n\tif os.Getenv(\"RELAY_HELPER\") == \"1\" {\n\t\tChild = true\n\t}\n}\n\nfunc Name() string { return \"cfg\" }\n",
				"relay/relay.go": "package relay\n\nimport \"example.com/rulestest/cfg\"\n\nfunc Serve() string { return cfg.Name() }\n",
				"relay/relay_test.go": selfExecRelayTest(`func TestChild(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`)},
			reason:     "-test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again, and each copy starts the next",
			suggestion: neutral,
		},
		"an init branch that only sets up, and a TestMain that starts the child before its answer": {
			files: map[string]string{"relay/relay_test.go": selfExecRelayTest(`func init() {
	if os.Getenv("RELAY_CHILD") != "" {
		log.SetFlags(0)
	}
}

func TestMain(m *testing.M) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "RELAY_CHILD=1")
	_ = cmd.Start()
	if os.Getenv("RELAY_CHILD") != "" {
		os.Exit(0)
	}
	code := m.Run()
	_ = cmd.Wait()
	os.Exit(code)
}

func TestNothing(t *testing.T) {}
`)},
			reason:     "the child reaches this launch again on its way to the branch of TestMain or an init that answers it, and each copy starts the next",
			suggestion: "Answer the child before the launch: move the branch that answers it above the start, or start the child from a test",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"relay/relay.go": "package relay\n"}
			maps.Copy(files, c.files)
			violations := rulestest.RunRuleOnFiles(t, NewSelfExecInTestRule(), files)
			require.Len(t, violations, 1)
			_, reason, _ := strings.Cut(violations[0].Message, " — ")
			assert.Equal(t, c.reason, reason)
			assert.Equal(t, c.suggestion, violations[0].Suggestion)
		})
	}
}

// A branch every run takes is no answer: the one that answers the child is
// named past it.
func TestSelfExecInTestRule_MessageBranchEveryRunTakes(t *testing.T) {
	message, _ := selfExecMessage(t, selfExecRelayTest(`func TestRelayChild(t *testing.T) {
	if testing.Testing() {
		println("under go test")
	}
	if os.Getenv("RELAY_HELPER") == "1" {
		println("child")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`))
	assert.Contains(t, message, " — the branch on RELAY_HELPER at line 16 answers the child but does not end the test")
}

// selfExecRelayChild is a test that answers its child by RELAY_HELPER at
// line 13 without an end, with more declarations after it.
func selfExecRelayChild(branch, more string) string {
	return selfExecRelayTest(`func TestChild(t *testing.T) {
	if os.Getenv("RELAY_HELPER") == "1" {
` + branch + `
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
` + more)
}

// A branch is named only where nothing in it may end the child and nothing
// else in the test binary reads what the launch passes: a read anywhere -
// in the package, in a test file, in a package the tests call, through
// LookupEnv, a name it cannot tell, os.Args or the flag package - leaves the
// neutral message. A read of a variable the launch does not pass does not.
func TestSelfExecInTestRule_MessageNamesTheOneReadThatCannotEnd(t *testing.T) {
	const (
		neutral    = "-test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again, and each copy starts the next"
		named      = "the branch on RELAY_HELPER at line 13 answers the child but does not end the test: the child goes on and reaches this launch again, and each copy starts the next"
		namedLater = "End the branch on RELAY_HELPER at line 13 with os.Exit or a return, so the child never reaches the launch"
	)
	cases := map[string]struct {
		files  map[string]string
		reason string
	}{
		"a branch that may return": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tif testing.Short() {\n\t\t\treturn\n\t\t}", "")}, reason: neutral},
		"a branch that may skip the test": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tif testing.Short() {\n\t\t\tt.Skip()\n\t\t}", "")}, reason: neutral},
		"a branch that may exit": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tif testing.Short() {\n\t\t\tos.Exit(0)\n\t\t}", "")}, reason: neutral},
		"a read in a package the tests call": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tprintln(\"child\")", ""),
			"relay/use_test.go":   "package relay\n\nimport \"example.com/rulestest/mode\"\n\nfunc useMode() bool { return mode.Child() }\n",
			"mode/mode.go":        "package mode\n\nimport \"os\"\n\nfunc Child() bool { return os.Getenv(\"RELAY_HELPER\") == \"1\" }\n",
		}, reason: neutral},
		"a read in the package under test": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tprintln(\"child\")", ""),
			"relay/relay.go":      "package relay\n\nimport \"os\"\n\nfunc Child() bool { return os.Getenv(\"RELAY_HELPER\") == \"1\" }\n",
		}, reason: neutral},
		"a package variable of a test file": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tprintln(\"child\")", "\nvar child = os.Getenv(\"RELAY_HELPER\")\n"),
		}, reason: neutral},
		"a read through LookupEnv": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tprintln(\"child\")", "\nfunc child() bool {\n\t_, set := os.LookupEnv(\"RELAY_HELPER\")\n\treturn set\n}\n"),
		}, reason: neutral},
		"a read of a name it cannot tell": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tprintln(\"child\")", "\nfunc envOf(name string) string { return os.Getenv(name) }\n"),
		}, reason: neutral},
		"a read of a name built at run time": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tprintln(\"child\")", "\nfunc envOf(name string) string { return os.Getenv(\"RELAY_\" + name) }\n"),
		}, reason: neutral},
		"a read of the arguments": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tprintln(\"child\")", "\nfunc argc() int { return len(os.Args) }\n"),
		}, reason: neutral},
		"a read of the flags": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tprintln(\"child\")", ""),
			"relay/main_test.go":  "package relay\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) {\n\tflag.Parse()\n\tos.Exit(m.Run())\n}\n",
		}, reason: neutral},
		"a read of a variable the launch does not pass": {files: map[string]string{
			"relay/relay_test.go": selfExecRelayChild("\t\tprintln(\"child\")", "\nfunc home() string { return os.Getenv(\"RELAY_HOME\") }\n"),
		}, reason: named},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"relay/relay.go": "package relay\n"}
			maps.Copy(files, c.files)
			violations := rulestest.RunRuleOnFiles(t, NewSelfExecInTestRule(), files)
			require.Len(t, violations, 1)
			_, reason, _ := strings.Cut(violations[0].Message, " — ")
			assert.Equal(t, c.reason, reason)
			if c.reason == named {
				assert.Equal(t, namedLater, violations[0].Suggestion)
			}
		})
	}
}

// A function value the package code calls in the branch may end the child.
func TestSelfExecInTestRule_MessageFuncValueInPackageCode(t *testing.T) {
	violations := rulestest.RunRuleOnFiles(t, NewSelfExecInTestRule(), map[string]string{
		"relay/relay.go": `package relay

import (
	"os"
	"os/exec"
)

func Launch(stop func()) {
	if os.Getenv("RELAY_HELPER") == "1" {
		stop()
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`,
		"relay/relay_test.go": "package relay\n\nimport \"testing\"\n\nfunc TestChild(t *testing.T) { Launch(func() {}) }\n",
	})
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, " — -test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again")
}

// A call in a branch may end the child unless it is proven to return: a
// function of the module whose body returns, a builtin, a conversion, or a
// function or method of the standard library that does not end the process.
// A function of another module, a method on a value whose type the rule does
// not tell, a method of an interface, a function value may: the branch is
// not named, in a test file and in the package code.
func TestSelfExecInTestRule_MessageBranchCallsOnlyWhatReturns(t *testing.T) {
	ext := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(ext, "go.mod"), []byte("module example.com/ext\n\ngo 1.24\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(ext, "ext.go"), []byte(`package ext

import "os"

func MaybeExit() {
	if os.Getenv("RELAY_STAY") == "" {
		os.Exit(0)
	}
}

type Server struct{}

func New() *Server { return &Server{} }

func (*Server) Run() { os.Exit(0) }
`), 0o644))
	goMod := "module example.com/rulestest\n\ngo 1.24\n\nrequire example.com/ext v0.0.0\n\nreplace example.com/ext => " + ext + "\n"
	const neutral = "-test.run=^TestChild$ runs TestChild in the child, and it reaches this launch again, and each copy starts the next"
	inTest := func(pre, call string) map[string]string {
		return map[string]string{"relay/relay.go": "package relay\n", "relay/relay_test.go": `package relay

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"example.com/ext"
	"example.com/rulestest/mode"
)

var _, _, _, _, _, _, _ = ext.MaybeExit, mode.Serve, fmt.Sprint, log.Print, runtime.GC, syscall.Getpid, time.Now

var srv = ext.New()

type relayLocal struct{}

func (relayLocal) Run() {}

var stopRelay = func() { os.Exit(0) }

func countdown(n int) {
	if n > 0 {
		countdown(n - 1)
	}
}

func TestChild(t *testing.T) {
	` + pre + `
	if os.Getenv("RELAY_HELPER") == "1" {
		` + call + `
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`}
	}
	inPackage := func(pre, call string) map[string]string {
		return map[string]string{"relay/relay_test.go": "package relay\n\nimport \"testing\"\n\nfunc TestChild(t *testing.T) { Launch() }\n", "relay/relay.go": `package relay

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"example.com/ext"
	"example.com/rulestest/mode"
)

var _, _, _, _, _, _ = ext.MaybeExit, fmt.Sprint, io.EOF, strings.ToLower, mode.Serve, syscall.Getpid

func Launch() {
	` + pre + `
	if os.Getenv("RELAY_HELPER") == "1" {
		` + call + `
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestChild$")
	cmd.Env = append(os.Environ(), "RELAY_HELPER=1")
	_ = cmd.Run()
}
`}
	}
	cases := map[string]struct {
		files map[string]string
		named bool
	}{
		"test file: a function of another module":                        {files: inTest("", "ext.MaybeExit()")},
		"test file: a method of a package variable of another module":    {files: inTest("", "srv.Run()")},
		"test file: a method of a local named like a standard import":    {files: inTest("fmt := ext.New()", "fmt.Run()")},
		"test file: a local function named like a builtin":               {files: inTest("len := func() { os.Exit(0) }", "len()")},
		"test file: a package variable of a function type":               {files: inTest("", "stopRelay()")},
		"test file: a function of a package of the module":               {files: inTest("", "mode.Serve()"), named: true},
		"test file: a method of a type of the module":                    {files: inTest("", "mode.M{}.Run()"), named: true},
		"test file: a method of a type of the test file":                 {files: inTest("", "relayLocal{}.Run()"), named: true},
		"test file: a recursive function of the module":                  {files: inTest("", "countdown(3)"), named: true},
		"test file: a function literal":                                  {files: inTest("", "func() { println(\"child\") }()"), named: true},
		"test file: the standard library, builtins and conversions":      {files: inTest("", "fmt.Println(len(os.Args), []byte(\"x\"), string(rune(65)))"), named: true},
		"test file: a method of a testing value":                         {files: inTest("", "t.Log(\"child\")")},
		"test file: syscall.Exit":                                        {files: inTest("", "syscall.Exit(0)")},
		"test file: a signal to the own process":                         {files: inTest("", "_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)")},
		"test file: a method of a log.Logger":                            {files: inTest("", "log.Default().Fatal(\"child\")")},
		"test file: a function of runtime":                               {files: inTest("", "runtime.GC()")},
		"test file: a function of log":                                   {files: inTest("", "log.Println(\"child\")")},
		"test file: a function of testing":                               {files: inTest("", "_ = testing.Verbose()")},
		"test file: a panic under a condition":                           {files: inTest("", "if len(os.Args) > 5 {\n\t\t\tpanic(\"child\")\n\t\t}")},
		"test file: a function of os that is not known to return":        {files: inTest("", "_ = os.Chdir(\"/\")")},
		"test file: the answer of a helper process":                      {files: inTest("", "_ = syscall.Setpgid(0, 0)\n\t\t_ = os.WriteFile(os.Getenv(\"RELAY_OUT\"), []byte(\"ready\"), 0o600)\n\t\ttime.Sleep(time.Millisecond)"), named: true},
		"package code: a function of another module":                     {files: inPackage("", "ext.MaybeExit()")},
		"package code: a method of a value of another module":            {files: inPackage("srv := ext.New()", "srv.Run()")},
		"package code: a method of an interface of the standard library": {files: inPackage("var w io.Writer = os.Stdout", "_, _ = w.Write(nil)")},
		"package code: a function value":                                 {files: inPackage("f := fmt.Println", "f()")},
		"package code: a method of a type of the module":                 {files: inPackage("", "mode.M{}.Run()"), named: true},
		"package code: a method of a type of the standard library":       {files: inPackage("var sb strings.Builder", "sb.WriteString(\"child\")"), named: true},
		"package code: a method of a type of os":                         {files: inPackage("p, _ := os.FindProcess(os.Getpid())", "_ = p.Kill()")},
		"package code: a function of syscall":                            {files: inPackage("", "syscall.Exit(0)")},
		"package code: a panic under a condition":                        {files: inPackage("", "if len(os.Args) > 5 {\n\t\t\tpanic(\"child\")\n\t\t}")},
		"package code: a function of os known to return":                 {files: inPackage("", "_ = os.Getpid()"), named: true},
		"package code: a builtin":                                        {files: inPackage("", "_ = len(os.Args)"), named: true},
		"package code: the standard library, builtins and conversions":   {files: inPackage("", "fmt.Println(len(os.Args), []byte(\"x\"), string(rune(65)))"), named: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"go.mod": goMod, "mode/mode.go": "package mode\n\nfunc Serve() {}\n\ntype M struct{}\n\nfunc (M) Run() {}\n"}
			maps.Copy(files, c.files)
			violations := rulestest.RunRuleOnFiles(t, NewSelfExecInTestRule(), files)
			require.Len(t, violations, 1)
			_, reason, _ := strings.Cut(violations[0].Message, " — ")
			if c.named {
				assert.True(t, strings.HasPrefix(reason, "the branch on RELAY_HELPER at line "), reason)
			} else {
				assert.Equal(t, neutral, reason)
			}
		})
	}
}

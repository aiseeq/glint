package qarules

import (
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
		" — -test.run=^TestRelayLoop$ runs only TestRelayLoop in the child, nothing there answers the child, so it reaches this launch again, and each copy starts the next", message)
	assert.Equal(t, "Answer the child in TestRelayLoop before the launch: set a variable in the command's Env and end the test with os.Exit or a return when it is set, or start a TestHelperProcess that does not launch", suggestion)
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
// message places the branch by its file and names the test; the condition
// reads the variable through a local.
func TestSelfExecInTestRule_MessageBranchInCallerOfLauncher(t *testing.T) {
	violations := rulestest.RunRuleOnFiles(t, NewSelfExecInTestRule(), map[string]string{
		"relay/relay.go": "package relay\n",
		"relay/relay_test.go": `package relay

import (
	"os"
	"testing"
)

func TestRelayVia(t *testing.T) {
	mode := os.Getenv("RELAY_VIA")
	if mode == "1" {
		t.Log("child")
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
	assert.Contains(t, violations[0].Message, " — the branch on RELAY_VIA at relay/relay_test.go:10 of TestRelayVia answers the child but does not end the test")
	assert.Equal(t, "End the branch on RELAY_VIA at relay/relay_test.go:10 with os.Exit or a return, so the child never reaches the launch", violations[0].Suggestion)
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

// A pattern that names more than one test lists them.
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
	assert.Contains(t, message, " — -test.run=^TestRelayPair runs only TestRelayPair, TestRelayPairSlow in the child, nothing there answers the child")
	assert.Contains(t, suggestion, "Answer the child in TestRelayPair, TestRelayPairSlow before the launch")
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
// answer: the child reaches the launch before it; nor is a branch every run
// takes.
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
		t.Log("under go test")
	}
	launchRelay()
	if os.Getenv("RELAY_AFTER") == "1" {
		t.Log("child")
	}
}
`)
	assert.Contains(t, message, " — -test.run=^TestRelayAfter$ runs only TestRelayAfter in the child, nothing there answers the child")
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
	_ = exec.Command(os.Args[0], "-test.run="+os.Getenv("RELAY_PATTERN")).Run()
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

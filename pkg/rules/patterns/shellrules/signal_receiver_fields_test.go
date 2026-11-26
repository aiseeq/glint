package shellrules

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// receiverFieldsWant lists the lines of source marked // WANT.
func receiverFieldsWant(source string) []int {
	var want []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// WANT") {
			want = append(want, i+1)
		}
	}
	return want
}

// A method with a value receiver works on its own copy: a field it sets is
// seen in its body and in the methods it calls on that copy, but not by its
// caller or by a sibling the caller calls on its own copy. A pointer receiver
// shares the value, so what one method sets the next one runs.
func TestSignalImplicitTargetValueReceiverWriteStaysInItsCopy(t *testing.T) {
	source := `package sample
import (
	"os/exec"
	"testing"
)
type stage struct{ script string }
type job struct {
	cmd, script string
	in          stage
}
func (k job) copyPrep(t *testing.T) { k.script = k.cmd; t.Log(k.script) }
func (k job) copyRun(t *testing.T) { _ = exec.Command("sh", "-c", k.script).Run() }
func (k job) copyBoth(t *testing.T) { k.copyPrep(t); k.copyRun(t) }
func (k job) ownWrite(t *testing.T) { k.script = k.cmd; _ = exec.Command("sh", "-c", k.script).Run() }
func (k job) writeThenCall(t *testing.T) { k.script = k.cmd; k.copyRun(t) }
func (k job) viaWriter(t *testing.T) { k.writeThenCall(t) }
func (k *job) ptrPrep(t *testing.T) { k.script = k.cmd }
func (k *job) ptrRun(t *testing.T) { _ = exec.Command("sh", "-c", k.script).Run() }
func (k *job) ptrBoth(t *testing.T) { k.ptrPrep(t); k.ptrRun(t) }
func (k job) nestedPrep(t *testing.T) { k.in.script = k.cmd }
func (k job) nestedRun(t *testing.T) { _ = exec.Command("sh", "-c", k.in.script).Run() }
func (k job) nestedBoth(t *testing.T) { k.nestedPrep(t); k.nestedRun(t) }
func (k job) nestedOwn(t *testing.T) { k.in.script = k.cmd; _ = exec.Command("sh", "-c", k.in.script).Run() }
func (k job) inSubtest(t *testing.T) { t.Run("in", func(t *testing.T) { _ = exec.Command("sh", "-c", k.cmd).Run() }) }
func (k job) sendInSubtest(t *testing.T) {
	ch := make(chan string, 1)
	t.Run("in", func(t *testing.T) { ch <- k.cmd })
	t.Log(<-ch)
}
func (k job) relay(t *testing.T) {
	var out string
	for i := 0; i < 2; i++ {
		out = k.script
		k.script = k.cmd
	}
	_ = exec.Command("sh", "-c", out).Run()
}
func TestTable(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} { t.Run("a", job{cmd: s}.copyBoth) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("b", job{cmd: s}.copyBoth) }
	for _, s := range []string{"kill -9 $PPID"} { t.Run("g", job{cmd: s}.nestedBoth) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("h", job{cmd: s}.nestedBoth) }
	for _, s := range []string{"kill -9 $PPID"} { t.Run("i", job{cmd: s}.nestedOwn) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("j", job{cmd: s}.inSubtest) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("k", job{cmd: s}.relay) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("l", job{cmd: s}.sendInSubtest) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("c", job{cmd: s}.ownWrite) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("d", job{cmd: s}.writeThenCall) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { t.Run("e", job{cmd: s}.viaWriter) } // WANT
	for _, s := range []string{"kill -9 $PPID"} { e := job{cmd: s}; t.Run("f", e.ptrBoth) } // WANT
}
`
	file, pkg := signalSourceTyped(t, "copy_test.go", source)
	assert.Equal(t, receiverFieldsWant(source), rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

// A method whose receiver has no name cannot read a field of it, so calling
// it — or running it as the subtest — passes the table string nowhere.
func TestSignalImplicitTargetUnnamedReceiverReadsNoField(t *testing.T) {
	source := `package sample
import (
	"os/exec"
	"testing"
)
type job struct{ cmd string }
func (job) setup(t *testing.T) { t.Helper() }
func (k job) logged(t *testing.T) { k.setup(t); t.Log(k.cmd) }
func (k job) setupThenRun(t *testing.T) { k.setup(t); _ = exec.Command("sh", "-c", k.cmd).Run() }
func (job) bare(t *testing.T) { t.Helper() }
func TestTable(t *testing.T) {
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("a", job{cmd: s}.logged) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("b", job{cmd: s}.bare) }
	for _, s := range []string{"kill -9 $PPID"} { t.Run("c", job{cmd: s}.setupThenRun) } // WANT
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("d", job{cmd: s}.setupThenRun) } // WANT
}
`
	file, pkg := signalSourceTyped(t, "unnamed_test.go", source)
	assert.Equal(t, receiverFieldsWant(source), rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

// The table string sits in a field of the receiver; another value of the same
// type does not hold it, however its fields are named.
func TestSignalImplicitTargetOtherValueOfReceiverTypeHoldsNoString(t *testing.T) {
	source := `package sample
import (
	"os/exec"
	"testing"
)
type job struct{ cmd, script string }
func (k job) shell(t *testing.T) { _ = exec.Command("sh", "-c", k.cmd).Run() }
func (k job) sibling(t *testing.T) { t.Log(k.cmd); x := job{cmd: "echo hi"}; _ = exec.Command("sh", "-c", x.cmd).Run() }
func (k job) siblingCall(t *testing.T) { t.Log(k.cmd); job{cmd: "echo hi"}.shell(t) }
func (k job) siblingWrite(t *testing.T) { var x job; x.script = k.cmd; t.Log(x.script); _ = exec.Command("sh", "-c", k.script).Run() }
func (k job) stash(t *testing.T) { var x job; x.script = k.cmd; t.Log(x.script) }
func (k job) selfAmongOthers(t *testing.T) { x := job{cmd: "echo hi"}; t.Log(x.cmd); _ = exec.Command("sh", "-c", k.cmd).Run() }
func TestTable(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} { t.Run("a", job{cmd: s}.sibling) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("b", job{cmd: s}.sibling) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("c", job{cmd: s}.siblingCall) }
	for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("d", job{cmd: s}.siblingWrite) }
	for _, s := range []string{"kill -9 $PPID"} { t.Run("e", job{cmd: s}.selfAmongOthers) } // WANT
}
func TestStash(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} { var o job; t.Run("g", job{cmd: s}.stash); _ = exec.Command("sh", "-c", o.script).Run() }
}
func TestSetAfter(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} { e := job{script: s}; e.cmd = s; t.Run("f", e.shell) } // WANT
}
func TestCopied(t *testing.T) {
	for _, s := range []string{"kill -9 $PPID"} { var all [1]job; all[0].cmd = s; x := all[0]; _ = exec.Command("sh", "-c", x.cmd).Run() } // WANT
}
`
	file, pkg := signalSourceTyped(t, "sibling_test.go", source)
	assert.Equal(t, receiverFieldsWant(source), rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
}

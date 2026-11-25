package shellrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A function variable declared without a value is nil until a write: a call
// through it calls one of the values written, so the zero value is no write.
func TestSignalFunctionVariableDeclaredWithoutValue(t *testing.T) {
	source := `package sample
import (
	"flag"
	"syscall"
)
var stopAll, unset func(int, syscall.Signal) error
func init() { stopAll = syscall.Kill } // raw: value taken
func stop(pid int, other func(int, syscall.Signal) error) {
	var f func(int, syscall.Signal) error
	f = syscall.Kill // raw: value taken
	_ = f(-1, syscall.SIGTERM) // signal
	_ = f(pid, syscall.SIGTERM) // raw
	_ = stopAll(0, syscall.SIGTERM) // signal
	var g func(int, syscall.Signal) error
	g = syscall.Kill // raw: value taken
	g = other
	_ = g(-1, syscall.SIGTERM)
	var h func(int, syscall.Signal) error
	_ = h(-1, syscall.SIGTERM)
	var k func(int, syscall.Signal) error
	k = syscall.Kill // raw: value taken
	keep(&k)
	_ = k(-1, syscall.SIGTERM)
	_ = unset(-1, syscall.SIGTERM)
	flag.Usage()
}
func keep(*func(int, syscall.Signal) error) {}
`
	file, pkg := rawProcessTypedFile(t, "values.go", "example.com/sample", source)
	assert.Equal(t, []int{11, 13}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
	assert.Equal(t, []int{7, 10, 12, 15, 21}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
}

// A raw kill or tgkill system call is the same signal as syscall.Kill or
// Tgkill with the arguments after the trap; the kernel reads the target, a
// uintptr, as a signed pid, so ^uintptr(0) is -1. tgkill answers EINVAL to a
// group or thread id of 0 or below: only the parent is its implicit target.
func TestSignalRawSystemCall(t *testing.T) {
	source := `package sample
import (
	"errors"
	"os"
	"syscall"
	"golang.org/x/sys/unix"
)
func stop(pid, tid uintptr, trap uintptr) {
	_, _, _ = syscall.Syscall(syscall.SYS_KILL, pid, uintptr(syscall.SIGTERM), 0) // raw
	_, _, _ = syscall.Syscall(syscall.SYS_KILL, ^uintptr(0), uintptr(syscall.SIGTERM), 0) // signal
	_, _, _ = syscall.RawSyscall(syscall.SYS_KILL, 0, 9, 0) // signal
	_, _, _ = syscall.Syscall6(syscall.SYS_KILL, uintptr(os.Getppid()), 15, 0, 0, 0, 0) // signal
	_, _, _ = syscall.RawSyscall6(syscall.SYS_TGKILL, pid, tid, 15, 0, 0, 0) // raw
	_, _, _ = syscall.Syscall(syscall.SYS_TGKILL, 0xFFFFFFFF, tid, 15) // raw
	_, _, _ = unix.Syscall(unix.SYS_KILL, pid, 15, 0) // raw
	_, _, _ = syscall.Syscall(syscall.SYS_KILL, uintptr(os.Getpid()), 15, 0)
	_, _, _ = syscall.Syscall(syscall.SYS_KILL, pid, 0, 0)
	_, _, _ = syscall.Syscall(syscall.SYS_KILL, pid, uintptr(syscall.SIGCHLD), 0)
	_, _, _ = syscall.Syscall(syscall.SYS_KILL, pid, 1, 0)
	_, _, _ = syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)
	_, _, _ = syscall.Syscall(trap, pid, 15, 0)
	_, _, _ = syscall.Syscall(62, pid, 15, 0)
	self := os.Getpid()
	_, _, _ = syscall.Syscall(syscall.SYS_KILL, uintptr(self), 15, 0)
	_ = Syscall(syscall.SYS_KILL, pid, 15, 0)
	_ = errors.New("stop").Error()
	_, _ = syscall.Getpgid(syscall.SYS_KILL)
	_, _, _ = syscall.Syscall(SYS_KILL, pid, 15, 0)
	_, _, _ = syscall.Syscall(syscall.SYS_TGKILL, pid, tid, 0)
	_, _, _ = syscall.Syscall(syscall.SYS_TGKILL, pid, 0, 15) // raw
	_, _, _ = syscall.Syscall(syscall.SYS_TGKILL, uintptr(os.Getppid()), tid, 15) // signal
}
const SYS_KILL = 39
func Syscall(trap, a, b, c uintptr) error { return nil }
`
	file, pkg := rawProcessTypedFile(t, "syscall.go", "example.com/sample", source)
	assert.Equal(t, []int{10, 11, 12, 31}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
	assert.Equal(t, []int{9, 13, 14, 15, 30}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
}

// The target of kill is implicit by its value, not by how it is written: a
// constant of -1 or 0 however it is spelled, a negative group number but
// math.MinInt32 as pid_t (ESRCH), and the caller's own process group negated.
// Tgkill answers EINVAL to such ids: only the parent is its target.
func TestSignalImplicitTargetByValue(t *testing.T) {
	source := `package sample
import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)
const everyone = -1
const group = 0
const someone = 4242
const groupLeader = 4242
func stop(cmd *exec.Cmd, pid, pgid int) {
	_ = syscall.Kill(int(-1), syscall.SIGTERM) // signal
	_ = syscall.Kill(everyone, syscall.SIGTERM) // signal
	_ = syscall.Kill(group, syscall.SIGTERM) // signal
	_ = syscall.Kill(-groupLeader, syscall.SIGTERM) // signal
	_ = syscall.Kill(-syscall.Getpgrp(), syscall.SIGTERM) // signal
	own := syscall.Getpgrp()
	_ = syscall.Kill(-own, syscall.SIGTERM) // signal
	mine, _ := syscall.Getpgid(0)
	_ = syscall.Kill(-mine, syscall.SIGKILL) // signal
	_ = syscall.Kill(-int(must(syscall.Getpgid(os.Getpid()))), syscall.SIGTERM)
	leader, _ := syscall.Getpgid(os.Getpid())
	_ = syscall.Kill(-leader, syscall.SIGTERM) // signal
	_ = syscall.Tgkill(everyone, pid, syscall.SIGTERM) // raw
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) // raw
	_ = syscall.Kill(-pgid, syscall.SIGTERM) // raw
	other, _ := syscall.Getpgid(pid)
	_ = syscall.Kill(-other, syscall.SIGTERM) // raw
	_ = syscall.Kill(own, syscall.SIGTERM) // raw
	_ = syscall.Kill(someone, syscall.SIGTERM) // raw
	_ = syscall.Kill(pid, 0)
	_ = syscall.Kill(os.Getpid(), 0)
	_ = syscall.Kill(everyone, 0)
	text := errors.New("stop").Error()
	_ = text
	again := own
	_ = syscall.Kill(-again, syscall.SIGTERM) // signal
	_ = syscall.Kill(^own, syscall.SIGTERM) // raw
	_ = syscall.Kill(int(-own), syscall.SIGTERM) // signal
	_ = syscall.Kill(-Getpgrp(), syscall.SIGTERM) // raw
	far, _ := syscall.Getpgid(5)
	_ = syscall.Kill(-far, syscall.SIGTERM) // raw
	count := func() int { return 1 }
	n := count()
	_ = n
	_ = syscall.Kill(-2147483648, syscall.SIGTERM) // raw
	_ = syscall.Kill(1<<31, syscall.SIGTERM) // raw
	_ = syscall.Tgkill(os.Getppid(), pid, syscall.SIGTERM) // signal
	_ = syscall.Tgkill(pid, os.Getppid(), syscall.SIGTERM) // signal
	_ = syscall.Tgkill(-own, pid, syscall.SIGTERM) // raw
	_ = syscall.Kill(-2147483647, syscall.SIGTERM) // signal
}
func must(v int, _ error) int { return v }
func Getpgrp() int { return 7 }
`
	file, pkg := rawProcessTypedFile(t, "value.go", "example.com/sample", source)
	assert.Equal(t, []int{13, 14, 15, 16, 17, 19, 21, 24, 38, 40, 49, 50, 52}, rulestest.ViolationLines(newSignalImplicitTargetRule().goTypedFile(file, pkg)))
	assert.Equal(t, []int{22, 25, 26, 27, 29, 30, 31, 39, 41, 43, 47, 48, 51}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
	// Both rules read the package's aliases at once: a function's own
	// aliases stay out of them.
	assert.Empty(t, pkg.parent.Groups)
}

// Every module of a go.work run is loaded on its own and sees another module
// only through export data: an alias declared there is not followed, so a run
// over a file, a directory or the whole workspace finds the same. Within a
// module an alias of another package is followed.
func TestSignalAliasFromAnotherModuleOfTheRun(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.work":          "go 1.24\n\nuse (\n\t./app\n\t./lib\n)\n",
		"lib/go.mod":       "module example.com/lib\n\ngo 1.24\n",
		"lib/stop.go":      "package lib\n\nimport \"syscall\"\n\nvar Stopper = syscall.Kill\n\nvar Replaced = syscall.Kill\n\nfunc Replace(f func(int, syscall.Signal) error) { Replaced = f }\n\ntype Box struct{ Stopper func(int, syscall.Signal) error }\n\nvar TestOnly func(int, syscall.Signal) error\n",
		"app/go.mod":       "module example.com/app\n\ngo 1.24\n\nrequire example.com/lib v0.0.0\n",
		"app/main.go":      "package main\n\nimport (\n\t\"syscall\"\n\n\t\"example.com/lib\"\n)\n\nfunc main() {\n\t_ = lib.Stopper(-1, syscall.SIGTERM)\n\t_ = lib.Replaced(-1, syscall.SIGTERM)\n\tvar box lib.Box\n\t_ = box.Stopper(-1, syscall.SIGTERM)\n\t_ = lib.TestOnly(-1, syscall.SIGTERM)\n}\n",
		"app/local.go":     "package main\n\nimport \"syscall\"\n\nvar Stopper = syscall.Kill\n",
		"app/reuse.go":     "package main\n\nimport \"syscall\"\n\nfunc reuse() { _ = Stopper(0, syscall.SIGTERM) }\n\nfunc shadow(f func(int, syscall.Signal) error) {\n\tStopper := f\n\t_ = Stopper(-1, syscall.SIGTERM)\n}\n",
		"lib/plain.go":     "package lib\n\nfunc Plain() {}\n",
		"lib/stop_test.go": "package lib\n\nimport (\n\t\"syscall\"\n\t\"testing\"\n)\n\nfunc fake(int, syscall.Signal) error { return nil }\n\nfunc TestStop(t *testing.T) {\n\tTestOnly = syscall.Kill\n\tStopper = fake\n\t_ = Stopper(-1, syscall.SIGTERM)\n}\n",
		"app/plain2.go":    "package main\n\nfunc plain() {}\n",
	}
	var contexts []*core.FileContext
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		if filepath.Ext(name) == ".go" {
			ctx, err := core.NewFileContextChecked(path, root, []byte(content), core.DefaultConfig())
			require.NoError(t, err)
			contexts = append(contexts, ctx)
		}
	}
	t.Setenv("GOWORK", filepath.Join(root, "go.work"))
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"app/reuse.go:5"}, rulestest.ViolationPlaces(rulestest.RunRuleOnProject(t, newSignalImplicitTargetRule(), project)))
}

// A Go file under testdata is built by no package: it is typed like a test
// file whatever the root of the run, so a run over the project and a run
// over the file find the same.
func TestSignalTestdataFileSameInProjectAndFileRun(t *testing.T) {
	files := map[string]string{
		"lib/lib.go":         "package lib\n\nfunc Noop() {}\n",
		"lib/testdata/td.go": "package td\n\nimport \"syscall\"\n\nfunc stop() {\n\t_ = syscall.Kill(-1, syscall.SIGTERM)\n}\n",
	}
	root, contexts := rulestest.Module(t, files)
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	assert.Equal(t, []string{"lib/testdata/td.go:6"}, rulestest.ViolationPlaces(rulestest.RunRuleOnProject(t, newSignalImplicitTargetRule(), project)))

	path := filepath.Join(root, "lib", "testdata", "td.go")
	dir := filepath.Dir(path)
	file, err := core.NewFileContextChecked(path, dir, []byte(files["lib/testdata/td.go"]), core.DefaultConfig())
	require.NoError(t, err)
	single, err := core.LoadGoProject(dir, []*core.FileContext{file}, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	assert.Equal(t, []string{"td.go:6"}, rulestest.ViolationPlaces(rulestest.RunRuleOnProject(t, newSignalImplicitTargetRule(), single)))
	assert.Empty(t, rulestest.RunRuleOnProject(t, newRawProcessKillRule(), single))
}

// A Go file of no module, which the core loads no project of, has no
// testdata directory of its own: a directory named testdata above it makes it
// no test file.
func TestSignalFileOfNoModuleUnderTestdata(t *testing.T) {
	top := t.TempDir()
	path := filepath.Join(top, "testdata", "loose.go")
	content := "package loose\n\nimport \"syscall\"\n\nfunc stop() { _ = syscall.Kill(-1, syscall.SIGTERM) }\n"
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	_, found, err := core.NearestGoModule(filepath.Dir(path))
	require.NoError(t, err)
	require.False(t, found)
	testdata, err := inModuleTestdata(path)
	require.NoError(t, err)
	assert.False(t, testdata)
}

// A test file that only makes a raw kill system call is typed with its
// package; a call the type check cannot make sense of is no own group.
func TestSignalRawSystemCallInTestFiles(t *testing.T) {
	files := map[string]string{
		"lib.go":     "package lib\n\nfunc Noop() {}\n",
		"raw/raw.go": "package raw\n\nfunc Noop() {}\n",
		"raw/raw_test.go": `package raw

import (
	"syscall"
	"testing"
)

func TestRaw(t *testing.T) {
	_, _, _ = syscall.Syscall(syscall.SYS_KILL, ^uintptr(0), 15, 0)
}
`,
		"sub/sub.go":     "package sub\n\nfunc Noop() {}\n",
		"sub/tg_test.go": "package sub\n\nimport (\n\t\"syscall\"\n\t\"testing\"\n)\n\nfunc TestTg(t *testing.T) {\n\t_, _, _ = syscall.Syscall(syscall.SYS_TGKILL, uintptr(syscall.Getppid()), 1, 15)\n}\n",
		"broken_test.go": `package lib

import (
	"syscall"
	"testing"
)

func TestBroken(t *testing.T) {
	_ = syscall.Kill(-syscall.Getpgid(), syscall.SIGTERM)
	_ = syscall.Kill("all", syscall.SIGTERM)
	_ = syscall.Kill(int(), syscall.SIGTERM)
	_ = syscall.Kill(1<<70, syscall.SIGTERM)
	_, _, _ = syscall.Syscall(true, 0, 15, 0)
	_, _, _ = syscall.Syscall()
}
`,
	}
	assert.Equal(t, []string{"raw/raw_test.go:9", "sub/tg_test.go:9"}, rulestest.ViolationPlaces(rulestest.RunRuleOnFiles(t, newSignalImplicitTargetRule(), files)))
	assert.Equal(t, []string{"broken_test.go:10", "broken_test.go:11", "broken_test.go:12", "broken_test.go:9"}, rulestest.ViolationPlaces(rulestest.RunRuleOnFiles(t, newRawProcessKillRule(), files)))
}

// The testdata a file is under is a directory of its own module: a project
// that itself lies in a testdata directory keeps the types of its packages,
// and a file its build leaves out stays out, in a run over the project and
// over the file alike.
func TestSignalModuleUnderTestdataDirectory(t *testing.T) {
	top := t.TempDir()
	root := filepath.Join(top, "testdata", "fixture")
	files := map[string]string{
		"stop.go":          "package fixture\n\nimport \"syscall\"\n\nfunc stop() { _ = syscall.Kill(-1, syscall.SIGTERM) }\n",
		"ignored.go":       "//go:build ignore\n\npackage main\n\nimport \"syscall\"\n\nfunc main() { _ = syscall.Kill(-1, syscall.SIGTERM) }\n",
		"sub/sub.go":       "package sub\n\nfunc Noop() {}\n",
		"sub/sub_other.go": "//go:build windows\n\npackage sub\n\nimport \"syscall\"\n\nfunc stop() { _ = syscall.Kill(-1, syscall.SIGTERM) }\n",
	}
	contexts := rulestest.ModuleIn(t, root, files)
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	typed, err := typeSignalFiles(project)
	require.NoError(t, err)
	for _, file := range project.Files {
		if filepath.Base(file.Path) == "stop.go" {
			assert.Same(t, file.GoTypesInfo, typed[file].info)
		}
	}
	assert.Equal(t, []string{"stop.go:5"}, rulestest.ViolationPlaces(rulestest.RunRuleOnProject(t, newSignalImplicitTargetRule(), project)))
	var above []*core.FileContext
	for _, file := range contexts {
		content, err := os.ReadFile(file.Path)
		require.NoError(t, err)
		ctx, err := core.NewFileContextChecked(file.Path, top, content, core.DefaultConfig())
		require.NoError(t, err)
		above = append(above, ctx)
	}
	outer, err := core.LoadGoProject(top, above, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	assert.Equal(t, []string{"testdata/fixture/stop.go:5"}, rulestest.ViolationPlaces(rulestest.RunRuleOnProject(t, newSignalImplicitTargetRule(), outer)))
	for _, name := range []string{"ignored.go", "sub/sub_other.go"} {
		path := filepath.Join(root, name)
		file, err := core.NewFileContextChecked(path, filepath.Dir(path), []byte(files[name]), core.DefaultConfig())
		require.NoError(t, err)
		single, err := core.LoadGoProject(filepath.Dir(path), []*core.FileContext{file}, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
		require.NoError(t, err)
		assert.Empty(t, rulestest.RunRuleOnProject(t, newSignalImplicitTargetRule(), single), name)
	}
}

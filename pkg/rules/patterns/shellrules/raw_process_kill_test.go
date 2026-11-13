package shellrules

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRawProcessKillReportsDirectSignalCalls(t *testing.T) {
	source := `package sample
import (
	"os"
	"syscall"
	"golang.org/x/sys/unix"
)
func stop(p *os.Process, pid, tid int, sig syscall.Signal) {
	_ = p.Kill() // want
	_ = p.Signal(sig) // want
	_ = syscall.Kill(pid, sig) // want
	_ = syscall.Tgkill(pid, tid, sig) // want
	_ = unix.Kill(pid, sig) // want
	_ = unix.Tgkill(pid, tid, sig) // want
}
`
	file, pkg := rawProcessTypedFile(t, "sample_test.go", "example.com/sample", source)
	assert.Equal(t, []int{8, 9, 10, 11, 12, 13}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
}

func TestRawProcessKillReportsUnknownSignalAndTestFiles(t *testing.T) {
	source := `package sample
import "syscall"
func TestStop(sig syscall.Signal, pid int) {
	_ = syscall.Kill(pid, sig) // want
}
`
	file, pkg := rawProcessTypedFile(t, "sample_test.go", "example.com/sample", source)
	assert.Equal(t, []int{4}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
}

func TestRawProcessKillTypesTestFilesWithoutProjectTypes(t *testing.T) {
	source := `package sample
import "os/exec"
func TestStop() {
	cmd := exec.Command("worker")
	_ = cmd.Process.Kill() // want
}
`
	assert.Equal(t, []int{5}, rulestest.GoProjectRuleLines(t, newRawProcessKillRule(), "stop_test.go", source))
}

func TestRawProcessKillSharesProjectTargetsAndTestTypes(t *testing.T) {
	files := map[string]string{
		"stop.go":      `package sample; import "os"; import "syscall"; var self = os.Getpid(); func stop() { _ = syscall.Kill(self, syscall.SIGTERM); var local = os.Getpid(); _ = syscall.Kill(local, syscall.SIGTERM); parent, _ := os.FindProcess(os.Getppid()); stopper := parent.Kill; _ = stopper() }`,
		"stop_test.go": `package sample; import "testing"; import "golang.org/x/sys/unix"; func TestStop(t *testing.T) { _ = unix.Kill(-1, unix.SIGTERM) }`,
	}
	raw := rulestest.RunRuleOnFiles(t, newRawProcessKillRule(), files)
	signal := rulestest.RunRuleOnFiles(t, newSignalImplicitTargetRule(), files)
	assert.Empty(t, raw)
	assert.Equal(t, []int{1, 1}, rulestest.ViolationLines(signal))
}

// A test file is typed with its package by the project: aliases through :=
// resolve there as in a file of the build.
func TestRawProcessKillAliasesInTestFiles(t *testing.T) {
	files := map[string]string{
		"lib.go": "package lib\nfunc Noop() {}\n",
		"alias_test.go": `package lib
import (
	"os"
	"syscall"
	"testing"
)
func TestAliases(t *testing.T) {
	f := syscall.Kill // raw: value taken
	_ = f(-1, syscall.SIGTERM) // signal
	self := os.Getpid()
	_ = syscall.Kill(self, syscall.SIGTERM)
	me, _ := os.FindProcess(os.Getpid())
	_ = me.Signal(syscall.SIGTERM)
	par, _ := os.FindProcess(os.Getppid())
	_ = par.Kill() // signal
}
`,
	}
	assert.Equal(t, []int{8}, rulestest.ViolationLines(rulestest.RunRuleOnFiles(t, newRawProcessKillRule(), files)))
	assert.Equal(t, []int{9, 15}, rulestest.ViolationLines(rulestest.RunRuleOnFiles(t, newSignalImplicitTargetRule(), files)))
}

// A package variable is its own PID only when every write to it in every
// file of the package is.
func TestRawProcessKillPackageVariableWrittenElsewhere(t *testing.T) {
	files := map[string]string{
		"target.go": `package sample
import (
	"os"
	"syscall"
)
var selfTarget = os.Getpid()
var ownTarget = os.Getpid()
func stop() {
	_ = syscall.Kill(selfTarget, syscall.SIGTERM) // want
	_ = syscall.Kill(ownTarget, syscall.SIGTERM)
}
func stopAgain() {
	selfTarget = os.Getpid()
	_ = syscall.Kill(selfTarget, syscall.SIGTERM) // want
}
`,
		"retarget.go": "package sample\nimport \"os\"\nfunc retarget(child int) { selfTarget = child; ownTarget = os.Getpid() }\n",
	}
	assert.Equal(t, []string{"target.go:14", "target.go:9"}, rulestest.ViolationPlaces(rulestest.RunRuleOnFiles(t, newRawProcessKillRule(), files)))
}

// The helper package and its tests, internal and external, are exempt; the
// same files in another module are not.
func TestRawProcessKillSkipsHelperPackageInProject(t *testing.T) {
	files := map[string]string{
		"proc/stop.go":          "package proc\nimport \"syscall\"\nfunc stop(pid int) { _ = syscall.Kill(pid, syscall.SIGKILL) }\n",
		"proc/stop_test.go":     "package proc\nimport (\"os/exec\"; \"testing\")\nfunc TestStop(t *testing.T) { _ = exec.Command(\"w\").Process.Kill() }\n",
		"proc/stop_ext_test.go": "package proc_test\nimport (\"os/exec\"; \"testing\")\nfunc TestStop(t *testing.T) { _ = exec.Command(\"w\").Process.Kill() }\n",
	}
	files["go.mod"] = "module github.com/aiseeq/akit\n\ngo 1.24\n"
	assert.Empty(t, rulestest.RunRuleOnFiles(t, newRawProcessKillRule(), files))
	files["go.mod"] = "module example.com/ctl\n\ngo 1.24\n"
	assert.Equal(t, []string{"proc/stop.go:3", "proc/stop_ext_test.go:3", "proc/stop_test.go:3"}, rulestest.ViolationPlaces(rulestest.RunRuleOnFiles(t, newRawProcessKillRule(), files)))
}

// An external test sees export_test.go of the package under test and the
// other packages of the module the core loaded.
func TestRawProcessKillExternalTestTypes(t *testing.T) {
	files := map[string]string{
		"lib/lib.go":         "package lib\nimport \"os/exec\"\nfunc Start() *exec.Cmd { return exec.Command(\"worker\") }\n",
		"lib/export_test.go": "package lib\nimport \"os\"\nfunc Spawn() *os.Process { return Start().Process }\n",
		"other/other.go":     "package other\nimport \"os\"\nfunc Find() *os.Process { return nil }\n",
		"lib/ext_test.go": `package lib_test
import (
	"testing"
	"example.com/rulestest/lib"
	"example.com/rulestest/other"
)
func TestStop(t *testing.T) {
	_ = lib.Spawn().Kill() // want
	_ = other.Find().Kill() // want
}
`,
	}
	assert.Equal(t, []string{"lib/ext_test.go:8", "lib/ext_test.go:9"}, rulestest.ViolationPlaces(rulestest.RunRuleOnFiles(t, newRawProcessKillRule(), files)))
}

// Packages that did not load are known by their import spec: a selector of
// the package name, every dot import of the file.
func TestRawProcessKillUnloadedPackages(t *testing.T) {
	files := map[string]string{
		"lib.go": "package lib\nfunc Noop() {}\n",
		"dot_test.go": `package lib
import (
	. "bytes"
	. "golang.org/x/sys/unix"
	"testing"
)
func TestDot(t *testing.T) {
	_ = NewBufferString("x")
	_ = Kill(-1, SIGTERM) // signal
	_ = Kill(4242, SIGTERM) // raw
	_ = Tgkill(4242, 1, SIGTERM) // raw
	Kill := func(int, int) error { return nil }
	_ = Kill(4242, 15)
}
`,
		"stop_test.go": `package lib
import (
	"os/exec"
	"testing"
	"github.com/aiseeq/akit/proc"
)
func TestStop(t *testing.T) {
	cmd := exec.Command("worker")
	_, _ = proc.StopChild(cmd.Process.Pid, 0, func() error { return cmd.Process.Kill() })
	_ = cmd.Process.Kill() // raw
}
`,
		"stopdot_test.go": `package lib
import (
	"os/exec"
	"testing"
	. "github.com/aiseeq/akit/proc"
)
func TestStopDot(t *testing.T) {
	cmd := exec.Command("worker")
	_, _ = StopChild(cmd.Process.Pid, 0, func() error { return cmd.Process.Kill() })
}
`,
	}
	assert.Equal(t, []string{"dot_test.go:10", "dot_test.go:11", "stop_test.go:10"}, rulestest.ViolationPlaces(rulestest.RunRuleOnFiles(t, newRawProcessKillRule(), files)))
	assert.Equal(t, []string{"dot_test.go:9"}, rulestest.ViolationPlaces(rulestest.RunRuleOnFiles(t, newSignalImplicitTargetRule(), files)))
}

// A package-level alias of Kill is called from another file of the package,
// its test and its external test, none of which names a signal function.
func TestSignalImplicitTargetAliasesFromOtherFiles(t *testing.T) {
	files := map[string]string{
		"lib/alias.go":    "package lib\nimport \"syscall\"\nvar stopper = syscall.Kill\nvar Stopper = syscall.Kill\n",
		"lib/use.go":      "package lib\nimport \"syscall\"\nfunc stopAll() error {\n\treturn stopper(-1, syscall.SIGTERM) // want\n}\n",
		"lib/use_test.go": "package lib\nimport (\n\t\"syscall\"\n\t\"testing\"\n)\nfunc TestUse(t *testing.T) {\n\t_ = stopper(0, syscall.SIGTERM) // want\n}\n",
		"lib/ext_test.go": `package lib_test
import (
	"syscall"
	"testing"
	"example.com/rulestest/lib"
)
func TestExt(t *testing.T) {
	_ = lib.Stopper(-1, syscall.SIGTERM) // want
}
`,
	}
	assert.Equal(t, []string{"lib/ext_test.go:8", "lib/use.go:4", "lib/use_test.go:7"}, rulestest.ViolationPlaces(rulestest.RunRuleOnFiles(t, newSignalImplicitTargetRule(), files)))
}

// Only a directory whose test file names a signal function is typed again,
// and a run over some files reads only those.
func TestRawProcessKillTypesNeededTestsAndReadsScope(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"plain/plain.go":      "package plain\nfunc Add(a, b int) int { return a + b }\n",
		"plain/plain_test.go": "package plain\nimport \"testing\"\nfunc TestAdd(t *testing.T) { _ = Add(1, 2) }\n",
		"stop/stop.go":        "package stop\nimport \"os\"\nfunc Find() *os.Process { return nil }\n",
		"stop/stop_test.go":   "package stop\nimport \"testing\"\nfunc TestStop(t *testing.T) { _ = Find().Kill() }\n",
	})
	typed := typeSignalFiles(project)
	byName := make(map[string]*core.FileContext)
	for _, file := range project.Files {
		byName[filepath.Base(file.Path)] = file
	}
	assert.Nil(t, typed[byName["plain_test.go"]].info)
	assert.NotNil(t, typed[byName["stop_test.go"]].info)

	project.SetReportFiles([]*core.FileContext{byName["stop_test.go"]})
	var seen []string
	_, err := analyzeSignalProject(project, func(file *core.FileContext, _ *signalPackage) []*core.Violation {
		seen = append(seen, filepath.Base(file.Path))
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"stop_test.go"}, seen)
}

func TestRawProcessKillPackageInitializerHasOneFinding(t *testing.T) {
	source := `package sample
import "syscall"
var killAllErr = syscall.Kill(-1, syscall.SIGTERM) // signal
var killGroupErr = syscall.Kill(-42, syscall.SIGTERM) // signal
var stopErr = syscall.Kill(42, syscall.SIGTERM) // raw
`
	file, pkg := rawProcessTypedFile(t, "init.go", "example.com/sample", source)
	assert.Equal(t, []int{5}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
	assert.Equal(t, []int{3, 4}, rulestest.ViolationLines(newSignalImplicitTargetRule().goFile(file, pkg)))
}

func TestRawProcessKillReportsPackageLevelFunctionLiteral(t *testing.T) {
	source := `package sample
import "os"
var stop = func(p *os.Process) {
	_ = p.Kill() // want
}
`
	file, pkg := rawProcessTypedFile(t, "package_level.go", "example.com/sample", source)
	assert.Equal(t, []int{4}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
}

// A method value is a finding where it is taken, a Kill function value where
// it is called.
func TestRawProcessKillRecognizesFunctionAndMethodValues(t *testing.T) {
	source := `package sample
import (
	"os"
	. "syscall"
	"golang.org/x/sys/unix"
)
func stop(p *os.Process, pid int) {
	k := p.Kill // want
	_ = k()
	f := Kill
	_ = f(pid, SIGTERM) // want
	_ = (*os.Process).Kill(p) // want
	g := f
	_ = g(pid, SIGTERM) // want
	u := unix.Kill // want
	_ = u(pid, unix.SIGTERM) // want
}
`
	file, pkg := rawProcessTypedFile(t, "values.go", "example.com/sample", source)
	assert.Equal(t, []int{8, 11, 12, 14, 15, 16}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
}

func TestRawProcessKillTgkillSelfIsAllowed(t *testing.T) {
	source := `package sample
import (
	"os"
	"syscall"
)
func stop(tid int) {
	_ = syscall.Tgkill(os.Getpid(), tid, syscall.SIGTERM)
	_ = syscall.Tgkill(os.Getpid(), os.Getpid(), syscall.SIGTERM)
}
`
	file, pkg := rawProcessTypedFile(t, "self.go", "example.com/sample", source)
	assert.Empty(t, newRawProcessKillRule().analyzeGo(file, pkg))
}

// Own PID needs every write of the variable to be own: no last write wins.
func TestRawProcessKillReportsReassignedSelfAlias(t *testing.T) {
	source := `package sample
import (
	"os"
	"syscall"
)
func stop(pid int) {
	self := os.Getpid()
	self = pid
	self = os.Getpid()
	_ = syscall.Kill(self, syscall.SIGTERM) // want
	me, _ := os.FindProcess(os.Getpid())
	me, _ = os.FindProcess(pid)
	me, _ = os.FindProcess(os.Getpid())
	_ = me.Kill() // want
	mine := os.Getpid()
	own := mine
	_ = syscall.Kill(own, syscall.SIGTERM)
	bumped := os.Getpid()
	bumped++
	_ = syscall.Kill(bumped, syscall.SIGTERM) // want
	ranged := os.Getpid()
	for ranged = range []int{pid} {
	}
	_ = syscall.Kill(ranged, syscall.SIGTERM) // want
	var zeroed int
	zeroed = os.Getpid()
	_ = syscall.Kill(zeroed, syscall.SIGTERM) // want
	addressed := os.Getpid()
	overwrite(&addressed)
	_ = syscall.Kill(addressed, syscall.SIGTERM) // want
}
func overwrite(*int) {}
`
	file, pkg := rawProcessTypedFile(t, "reassigned.go", "example.com/sample", source)
	assert.Equal(t, []int{10, 14, 20, 24, 27, 30}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
}

// The load knows a dependency of a dependency only by reference, as an
// incomplete package; go/types drops such an import, so it is imported anew.
func TestRawProcessKillImporterSkipsIncompletePackages(t *testing.T) {
	packages := map[string]*types.Package{"golang.org/x/sys/unix": types.NewPackage("golang.org/x/sys/unix", "unix")}
	pkg, err := signalImporter{packages: packages, std: importer.Default()}.Import("golang.org/x/sys/unix")
	require.NoError(t, err)
	assert.True(t, pkg.Complete())
}

func TestRawProcessKillSkipsNonterminatingSignals(t *testing.T) {
	source := `package sample
import (
	"os"
	"syscall"
)
func stop(p *os.Process, pid int) {
	_ = p.Signal(syscall.SIGHUP)
	_ = (*os.Process).Signal(p, syscall.SIGHUP)
	_ = syscall.Kill(pid, syscall.SIGUSR1)
	_ = syscall.Kill(pid, syscall.SIGUSR2)
	_ = syscall.Kill(pid, syscall.SIGSTOP)
	_ = syscall.Kill(pid, syscall.SIGTSTP)
	_ = syscall.Kill(pid, syscall.SIGTTIN)
	_ = syscall.Kill(pid, syscall.SIGTTOU)
	_ = syscall.Kill(pid, syscall.SIGCONT)
	_ = syscall.Kill(pid, syscall.SIGCHLD)
	_ = syscall.Kill(pid, syscall.SIGURG)
	_ = syscall.Kill(pid, syscall.SIGWINCH)
	_ = syscall.Kill(pid, 0)
}
`
	file, pkg := rawProcessTypedFile(t, "signals.go", "example.com/sample", source)
	assert.Empty(t, newRawProcessKillRule().analyzeGo(file, pkg))
}

func TestRawProcessKillSkipsSelfAndParentTargets(t *testing.T) {
	source := `package sample
import (
	"os"
	"syscall"
	"golang.org/x/sys/unix"
)
func stop(pid int) {
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	self := os.Getpid()
	_ = syscall.Kill(self, syscall.SIGTERM)
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Kill()
	_ = p.Signal(syscall.SIGTERM)
	_ = syscall.Kill(os.Getppid(), syscall.SIGTERM)
	_ = syscall.Kill(pid, syscall.SIGTERM) // want
	parent, _ := os.FindProcess(os.Getppid())
	_ = parent.Kill()
	_ = syscall.Kill(0, syscall.SIGTERM)
	_ = syscall.Kill(-1, syscall.SIGTERM)
	mine := os.Getpid()
	h, _ := os.FindProcess(mine)
	_ = h.Signal(syscall.SIGTERM)
	_ = (*os.Process).Kill(p)
	_ = syscall.Kill(int(os.Getpid()), syscall.SIGTERM)
	k := p.Kill
	_ = k()
	q := p
	_ = q.Kill()
	var s os.Signal = syscall.SIGTERM
	s.Signal()
	_ = unix.Kill(unix.Getpid(), unix.SIGTERM)
}
`
	file, pkg := rawProcessTypedFile(t, "targets.go", "example.com/sample", source)
	assert.Equal(t, []int{16}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
}

func TestRawProcessKillSkipsStopChildRequestAndHelperPackage(t *testing.T) {
	source := `package sample
import (
	"os"
	"syscall"
	"github.com/aiseeq/akit/proc"
)
func stop(p *os.Process, pid int) {
	proc.StopChild(pid, 0, func() { _ = p.Signal(syscall.SIGTERM) })
	proc.StopChild(pid, 0, (func() { _ = p.Kill() }))
	_ = p.Kill() // want
}
`
	file, pkg := rawProcessTypedFile(t, "helper.go", "example.com/sample", source)
	assert.Equal(t, []int{10}, rulestest.ViolationLines(newRawProcessKillRule().analyzeGo(file, pkg)))
	helperFile, helperPkg := rawProcessTypedFile(t, "stop.go", "github.com/aiseeq/akit/proc", `package proc
import "syscall"
func init() { _ = syscall.Kill(1, syscall.SIGKILL) }
`)
	assert.Empty(t, newRawProcessKillRule().analyzeGo(helperFile, helperPkg))
}

func TestRawProcessKillFindingMessageNamesApprovedHelper(t *testing.T) {
	source := `package sample
import (
	"os"
	"syscall"
)
func stop(p *os.Process) { _ = p.Signal(syscall.SIGTERM) }
`
	file, pkg := rawProcessTypedFile(t, "stop.go", "example.com/sample", source)
	findings := newRawProcessKillRule().analyzeGo(file, pkg)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "proc.StopChild")
	assert.Contains(t, findings[0].Message, "Call to p.Signal sends")
	assert.Contains(t, findings[0].Suggestion, "request function literal")
}

func TestRawProcessKillHonorsInlineSuppressionAndRecordsIt(t *testing.T) {
	source := `package sample
import (
	"os"
	"syscall"
)
func stop(p *os.Process) {
	_ = p.Signal(syscall.SIGTERM) //nolint:raw-process-kill
}
`
	file, pkg := rawProcessTypedFile(t, "stop.go", "example.com/sample", source)
	assert.Empty(t, newRawProcessKillRule().analyzeGo(file, pkg))
	assert.Equal(t, []int{7}, file.TakeSuppressionHits("raw-process-kill"))
}

func rawProcessTypedFile(t *testing.T, name, pkgPath, source string) (*core.FileContext, *signalPackage) {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, name, source, parser.AllErrors)
	require.NoError(t, err)
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	_, err = (&types.Config{Importer: signalTestImporter{base: importer.Default()}}).Check(pkgPath, fset, []*ast.File{parsed}, info)
	require.NoError(t, err)
	file := core.NewFileContext(filepath.Clean(name), ".", []byte(source), nil)
	file.GoAST, file.GoFileSet, file.GoTypesInfo = parsed, fset, info
	return file, newSignalPackage(pkgPath, info, parsed)
}

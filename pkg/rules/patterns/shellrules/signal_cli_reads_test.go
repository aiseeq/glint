package shellrules

import (
	"go/ast"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func TestSignalProjectTableReads(t *testing.T) {
	root, files := rulestest.Module(t, map[string]string{
		"iso1/a_test.go": `package iso1
import "testing"
func inspect(string) {}
func TestRead(t *testing.T) {
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", func(t *testing.T) { inspect(s) }) }
}`,
		"iso2/a_test.go": `package iso2
import "testing"
func inspect(string) {}
func TestRead(t *testing.T) {
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} {
  inspect(s)
 }
}

func TestLog(t *testing.T) {
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} {
  t.Log(s)
 }
}
func TestLogSub(t *testing.T) {
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} {
  t.Run("case", func(t *testing.T) { t.Log(s) })
 }
}`,
		"iso3/helpers.go": `package iso3
func inspect(s string) int { return len(s) }`,
		"iso3/a_test.go": `package iso3
import "testing"
func TestRead(t *testing.T) {
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { inspect(s) }
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", func(t *testing.T) { inspect(s) }) }
}`,
		"iso4/a_test.go": `package iso4
import "testing"
func TestRead(t *testing.T) {
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = len(s) }
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", func(t *testing.T) { _ = len(s) }) }
}`,
		"pos/a_test.go": `package pos
import ("testing"; "os/exec")
func run(s string) { _ = exec.Command("sh", "-c", s).Run() }
func TestRun(t *testing.T) {
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", func(t *testing.T) { _ = exec.Command("sh", "-c", s).Run() }) }
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { run(s) }
}`,
		"shadow/a_test.go": `package shadow
import ("testing"; "os/exec")
func len(s string) int { _ = exec.Command("sh", "-c", s).Run(); return 0 }
func TestRun(t *testing.T) {
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { _ = len(s) }
}`,
		"custom/a_test.go": `package custom
import "os/exec"
type logger struct{}
func (logger) Log(s string) { _ = exec.Command("sh", "-c", s).Run() }
func run(t logger) {
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Log(s) }
}`,
	})
	project, err := core.LoadGoProject(root, files, core.GoProjectOptions{RequireSSA: true})
	require.NoError(t, err)
	violations, err := newSignalImplicitTargetRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Equal(t, []string{"custom/a_test.go:6", "pos/a_test.go:5", "pos/a_test.go:6", "shadow/a_test.go:5"}, rulestest.ViolationPlaces(violations))
}

func TestSignalTableTestLogWithIncompleteTypes(t *testing.T) {
	source := `package sample
import "testing"
func TestRead(t *testing.T) {
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Log(s) }
 for _, s := range []string{"bash -c 'kill -9 $PPID'"} { t.Run("case", func(t *testing.T) { t.Log(s) }) }
}`
	file, pkg := signalSourceTyped(t, "sample_test.go", source)
	ast.Inspect(file.GoAST, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == "Log" {
			delete(pkg.info.Types, selector.X)
			delete(pkg.info.Uses, selector.Sel)
			if id, ok := selector.X.(*ast.Ident); ok {
				delete(pkg.info.Uses, id)
			}
		}
		return true
	})
	require.Empty(t, newSignalImplicitTargetRule().goTypedFile(file, pkg))
}

package patternkit

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamedObjectOfFunctionExpressions(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "named.go", `package sample
import "time"
type clock struct{ now func() time.Time }
func local() {}
func use(c clock, fs []func()) {
	local()
	(time.Now)()
	c.now()
	_ = time.Time{}.Add
	fs[0]()
	f := local
	f()
}
`, 0)
	require.NoError(t, err)
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	_, err = (&types.Config{Importer: importer.Default()}).Check("sample", fset, []*ast.File{file}, info)
	require.NoError(t, err)
	var names []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			names = append(names, objectName(NamedObject(info, n.Fun)))
		case *ast.AssignStmt:
			names = append(names, objectName(NamedObject(info, n.Rhs[0])))
		}
		return true
	})
	assert.Equal(t, []string{"sample.local", "time.Now", "field now", "method (time.Time).Add", "<nil>", "sample.local", "var f func()"}, names)
	assert.Nil(t, NamedObject(info, nil))
}

func objectName(obj types.Object) string {
	switch obj := obj.(type) {
	case nil:
		return "<nil>"
	case *types.Func:
		if obj.Signature().Recv() != nil {
			return "method " + obj.FullName()
		}
		return obj.FullName()
	case *types.Var:
		if obj.IsField() {
			return "field " + obj.Name()
		}
	}
	return obj.String()
}

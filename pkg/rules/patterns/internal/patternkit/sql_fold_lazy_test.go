package patternkit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestSQLFolderCollectsLocalsOnDemand(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "p.go", `package p
func f(other string) {
	const suffix = "one"
	stable := "two"
	mutable := "three"
	mutable = other
	_ = "select " + suffix
	_ = "select " + stable
	_ = "select " + mutable
}`, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ids = map[string]*ast.Ident{}
	ast.Inspect(file, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && id.Obj != nil {
			ids[id.Name] = id
		}
		return true
	})
	fold := newSQLFolder(file)
	if fold.value(ids["suffix"]) == nil || fold.locals != nil {
		t.Fatal("constant resolution should not collect local variables")
	}
	if fold.value(ids["stable"]) == nil || fold.locals == nil {
		t.Fatal("stable local should trigger collection and resolve")
	}
	if fold.value(ids["mutable"]) != nil {
		t.Fatal("reassigned local must not resolve")
	}
}

func TestSqlLiteralsNilBody(t *testing.T) {
	var body *ast.BlockStmt
	if got := SqlLiterals(body); len(got) != 0 {
		t.Fatalf("nil body returned %v", got)
	}
}

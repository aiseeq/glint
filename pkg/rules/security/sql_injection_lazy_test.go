package security

import (
	"go/ast"
	"go/types"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// sqlInjectionPatternsEager are the patterns of a file's database calls with
// the taint index built before the first call, as analyze did before it
// built the index on the first database call.
func sqlInjectionPatternsEager(file *core.FileContext, info *types.Info, decls map[*types.Func]*ast.FuncDecl) []string {
	check := newSQLTaintCheck(file.GoAST, info, decls)
	var patterns []string
	ast.Inspect(file.GoAST, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if query := sqlQueryArgument(call, info); query != nil {
				if pattern := check.injectedPattern(query, call.Pos()); pattern != "" {
					patterns = append(patterns, pattern)
				}
			}
		}
		return true
	})
	return patterns
}

func TestSQLInjectionLazyIndexMatchesEager(t *testing.T) {
	files := map[string]string{
		"db/calls.go": `package db
import ("database/sql"; "fmt")
func safeThenUnsafe(db *sql.DB, id, table string) {
	db.Query("SELECT * FROM users WHERE id = $1", id)
	db.Query("SELECT * FROM " + table)
	db.Query(fmt.Sprintf("SELECT * FROM %s", table))
}
`,
		"db/none.go": `package db
func helper(name string) string { return "x" + name }
`,
		"db/safe.go": `package db
import "database/sql"
func allowed(db *sql.DB, column string) {
	if column != "name" && column != "id" { return }
	db.Query("SELECT " + column + " FROM users")
}
`,
	}
	maps.Copy(files, fakeSQLXModule)
	project := rulestest.Project(t, files)
	decls := make(map[*types.Func]*ast.FuncDecl)
	for _, pkg := range project.Packages {
		for _, file := range pkg.Package.Syntax {
			helpers.IndexFuncDecls(decls, file, pkg.Package.TypesInfo)
		}
	}
	rule := NewSQLInjectionRule()
	seen := 0
	for _, pkg := range project.Packages {
		for _, file := range pkg.Files {
			var lazy []string
			for _, v := range rule.analyze(file, pkg.Package.TypesInfo, decls) {
				lazy = append(lazy, v.Context["pattern"].(string))
			}
			assert.Equal(t, sqlInjectionPatternsEager(file, pkg.Package.TypesInfo, decls), lazy, file.RelPath)
			if file.RelPath == "db/calls.go" {
				seen++
				assert.Equal(t, []string{"concatenation", "sprintf"}, lazy, "the index built at the safe call serves the unsafe ones after it")
			}
		}
	}
	require.Equal(t, 1, seen)
}
